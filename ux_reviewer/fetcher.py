"""
Слой загрузки страницы (граница «интернет → наш код»).

Задача одна: по адресу вернуть ЧИСТЫЙ текст и заголовок страницы. Всё, что
касается модели, лежит слоем выше и про HTTP ничего не знает — благодаря этому
разбор промптов отлаживается на сохранённом тексте, без обращений в сеть.

⚠️ Главная опасность этого слоя — ТИХИЙ УСПЕХ: сервер ответил 200, парсер
отработал, а текста нет (страница собирается скриптами в браузере). Дальше такой
пустой текст ушёл бы в модель, та бы честно нафантазировала UX-отчёт ни о чём,
и подделка выглядела бы как рабочий результат. Поэтому объём текста проверяется
явно и мало текста = ошибка, а не «пустой, но успешный» ответ.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import requests
from bs4 import BeautifulSoup
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ux_reviewer.logging_setup import get_logger

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
def _download(url: str) -> requests.Response:
    """Скачивание с повторами: сеть моргает чаще, чем кажется."""
    log.info("Загружаю страницу: %s", url)
    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "ru,en;q=0.8"},
    )
    response.raise_for_status()
    return response


def fetch_page(url: str) -> PageContent:
    """
    Скачать страницу и достать из неё заголовок и текст.

    :raises FetchError: адрес не открылся, отдал не HTML или текста слишком мало.
    """
    if not url.startswith(("http://", "https://")):
        raise FetchError(f"Адрес должен начинаться с http:// или https://, получено: {url!r}")

    try:
        response = _download(url)
    except requests.RequestException as exc:
        log.error("Страница не загрузилась: %s (%s)", url, exc)
        raise FetchError(f"Не удалось загрузить страницу: {exc}") from exc

    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        # Проверка на границе: код 200 ещё не значит, что пришло то, что нужно.
        raise FetchError(
            f"По адресу лежит не HTML, а {content_type or 'неизвестный тип'} — разбирать нечего"
        )

    # requests угадывает кодировку по заголовкам и иногда ошибается на русских
    # сайтах; apparent_encoding смотрит в само содержимое и надёжнее.
    if not response.encoding or response.encoding.lower() == "iso-8859-1":
        response.encoding = response.apparent_encoding

    soup = BeautifulSoup(response.text, "html.parser")

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
    return PageContent(
        url=url, title=title, text=text, original_length=original_length
    )
