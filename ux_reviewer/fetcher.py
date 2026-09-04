"""
Слой загрузки страницы (граница «интернет → наш код»).

Задача одна: по адресу вернуть ЧИСТЫЙ текст и заголовок страницы. Всё, что
касается модели, лежит слоем выше и про HTTP ничего не знает — благодаря этому
разбор промптов отлаживается на сохранённом тексте, без обращений в сеть.

⚠️ Опасность первая — ТИХИЙ УСПЕХ: сервер ответил 200, парсер отработал, а текста
нет (страница собирается скриптами в браузере). Дальше такой пустой текст ушёл бы
в модель, та бы честно нафантазировала UX-отчёт ни о чём, и подделка выглядела бы
как рабочий результат. Поэтому объём текста проверяется явно.

⚠️ Опасность вторая — SSRF: адрес приходит от постороннего человека, а ходит по
нему НАШ сервер, изнутри периметра. Проверка вынесена в safety.py, здесь она
применяется к каждому шагу цепочки переходов.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ux_reviewer.logging_setup import get_logger
from ux_reviewer.safety import MAX_REDIRECTS, UnsafeURLError, assert_url_is_safe

log = get_logger("fetch")

# Представляемся честно: маскировка под браузер часто нарушает правила сайта,
# а нам нужен обычный публичный HTML.
USER_AGENT: Final[str] = "UX-Reviewer/1.0 (educational project; +https://github.com/)"

REQUEST_TIMEOUT: Final[float] = 30.0

# Порог «страница пустая». 200 знаков — это меньше одного абзаца: на таком объёме
# UX-разбор невозможен в принципе, и честнее отказаться, чем выдумывать.
MIN_TEXT_LENGTH: Final[int] = 200

# Больше 40 тыс. знаков в модель не отдаём: смысла нет, а токены платные.
MAX_TEXT_LENGTH: Final[int] = 40_000

# ⚠️ Потолок СКАЧИВАНИЯ. Без него чужой адрес может отдавать поток бесконечно
# долго (так устроены ловушки для краулеров) — память сервера кончится раньше,
# чем терпение. 5 МБ с запасом покрывают любую честную страницу.
MAX_DOWNLOAD_BYTES: Final[int] = 5 * 1024 * 1024

# Теги, которые к содержанию отношения не имеют и только зашумляют разбор.
NOISE_TAGS: Final[tuple[str, ...]] = (
    "script",
    "style",
    "noscript",
    "svg",
    "iframe",
    "template",
)


class FetchError(RuntimeError):
    """Страницу не удалось получить или из неё нечего разбирать."""


@dataclass(frozen=True)
class PageContent:
    """Результат работы слоя: то, что уходит выше по стопке."""

    url: str
    title: str
    text: str
    # Сколько знаков было ДО обрезки — нужно, чтобы в отчёте честно сказать,
    # что разбиралась только часть длинной страницы.
    original_length: int

    @property
    def truncated(self) -> bool:
        return self.original_length > len(self.text)


@retry(
    retry=retry_if_exception_type(requests.RequestException),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=15),
    reraise=True,
)
def _download_once(url: str) -> requests.Response:
    """
    Одно скачивание с повторами при сетевых сбоях.

    ⚠️ allow_redirects=False стоит НЕ для удобства, а ради безопасности:
    библиотека пошла бы по переходу сама, в том числе на 127.0.0.1, и проверка
    адреса осталась бы позади. Переходы обрабатываются вызывающей функцией —
    с повторной проверкой каждого шага.
    """
    log.info("Загружаю страницу: %s", url)
    return requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "ru,en;q=0.8"},
        allow_redirects=False,
        stream=True,
    )


def _read_limited(response: requests.Response) -> bytes:
    """
    Прочитать тело ответа, оборвав чтение на потолке.

    Считаем ФАКТИЧЕСКИЕ байты, а не верим заголовку Content-Length: его можно
    написать любой, а можно и вовсе не прислать.
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        total += len(chunk)
        if total > MAX_DOWNLOAD_BYTES:
            log.warning("Превышен потолок скачивания %d байт — чтение оборвано", MAX_DOWNLOAD_BYTES)
            raise FetchError(
                f"Страница больше {MAX_DOWNLOAD_BYTES // 1024 // 1024} МБ — такие не разбираем"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _decode(response: requests.Response, body: bytes) -> str:
    """
    Превратить байты в текст, определив кодировку.

    Порядок важен: заголовок сервера → объявление внутри HTML → utf-8 как
    последняя попытка. Русские сайты регулярно врут в заголовке (классика —
    объявленный windows-1251 при фактическом utf-8), поэтому errors="replace":
    отдельный битый символ не должен ронять весь разбор.
    """
    encoding = response.encoding
    if not encoding or encoding.lower() == "iso-8859-1":
        match = re.search(rb'charset=["\']?([\w-]+)', body[:4096], re.IGNORECASE)
        encoding = match.group(1).decode("ascii", "ignore") if match else "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        # Сервер назвал кодировку, которой не существует, — не редкость.
        log.warning("Неизвестная кодировка %r, читаю как utf-8", encoding)
        return body.decode("utf-8", errors="replace")


def _download(url: str) -> tuple[requests.Response, bytes]:
    """
    Скачать страницу, проверяя безопасность КАЖДОГО шага цепочки переходов.

    Граница «интернет → наш сервер»: перед каждым запросом адрес резолвится и
    сверяется со списком запретов (см. safety.py).
    """
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        try:
            assert_url_is_safe(current)
        except UnsafeURLError as exc:
            raise FetchError(str(exc)) from exc

        response = _download_once(current)

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location", "")
            response.close()
            if not location:
                raise FetchError("Сервер ответил переходом, но не сказал куда")
            current = urljoin(current, location)
            log.info("Переход %d из %d: %s", hop + 1, MAX_REDIRECTS, current)
            continue

        response.raise_for_status()
        return response, _read_limited(response)

    raise FetchError(f"Слишком много переходов (больше {MAX_REDIRECTS}) — похоже на петлю")


def fetch_page(url: str) -> PageContent:
    """
    Скачать страницу и достать из неё заголовок и текст.

    :raises FetchError: адрес запрещён, не открылся, отдал не HTML или текста мало.
    """
    if not url.startswith(("http://", "https://")):
        raise FetchError(f"Адрес должен начинаться с http:// или https://, получено: {url!r}")

    try:
        response, body = _download(url)
    except requests.RequestException as exc:
        log.error("Страница не загрузилась: %s (%s)", url, exc)
        raise FetchError(f"Не удалось загрузить страницу: {exc}") from exc

    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        # Проверка на границе: код 200 ещё не значит, что пришло то, что нужно.
        raise FetchError(
            f"По адресу лежит не HTML, а {content_type or 'неизвестный тип'} — разбирать нечего"
        )

    soup = BeautifulSoup(_decode(response, body), "html.parser")

    for tag in soup(list(NOISE_TAGS)):
        tag.decompose()

    title = soup.title.get_text(strip=True) if soup.title else ""
    # separator="\n": без него слова из соседних блоков слипаются в одно длинное,
    # и модель читает «Каталогдоставкаоплата».
    raw_text = soup.get_text(separator="\n", strip=True)

    # Схлопываем пустые строки — они съедают токены, не добавляя смысла.
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    text = "\n".join(lines)
    original_length = len(text)

    if original_length < MIN_TEXT_LENGTH:
        # Тихий успех запрещён: говорим ПОЧЕМУ нечего разбирать.
        log.warning(
            "Текста слишком мало: %d знаков (порог %d). Вероятно, страница "
            "собирается скриптами в браузере.",
            original_length,
            MIN_TEXT_LENGTH,
        )
        raise FetchError(
            f"Со страницы удалось извлечь всего {original_length} знаков текста "
            f"(нужно от {MIN_TEXT_LENGTH}). Скорее всего, содержимое рисуется "
            f"скриптами и в исходном HTML его нет."
        )

    if original_length > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH]
        log.warning(
            "Страница обрезана: %d → %d знаков (экономим токены)",
            original_length,
            MAX_TEXT_LENGTH,
        )

    log.info(
        "Страница разобрана: заголовок=%r, текст %d знаков",
        title[:80],
        len(text),
    )
    return PageContent(url=url, title=title, text=text, original_length=original_length)
