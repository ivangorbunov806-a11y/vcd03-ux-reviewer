"""
Охрана сервиса: кто пускается, как часто и сколько это стоит владельцу.

⚠️ ГЛАВНОЕ ПРО ДЕНЬГИ. Каждый разбор — платные запросы к модели: быстрый режим
один (~0,5 ₽), глубокий два (~1 ₽). Сервис открыт всем, поэтому платит владелец
за каждого зашедшего. Значит нужен потолок, и он обязан быть ОБЩИМ.

⭐ Почему одного лимита на адрес мало. Ограничение «20 в час с адреса» защищает
от одного любопытного и совершенно не защищает от сотни адресов: суммарный
расход ничем не ограничен. Поэтому лимитов два:
  • на адрес (RATE_LIMIT_PER_HOUR) — против одного шумного посетителя;
  • ⭐ на весь сервис в сутки (DAILY_LIMIT) — против всех сразу. Это и есть
    настоящий потолок расходов: 100 разборов ≈ 100 ₽ в худший день.

Токен `X-API-Token` остался, но сменил смысл: теперь это не пропуск, а ключ
ВЛАДЕЛЬЦА. Он обходит общий суточный лимит — иначе в день, когда демо разобрали
до нуля, хозяин сервиса не смог бы им воспользоваться и показать его людям.

⭐ Суточный счётчик хранится в ФАЙЛЕ, а не в памяти процесса. Причина простая:
у сервиса стоит Restart=always, и счётчик в памяти обнулялся бы при каждом
перезапуске — то есть потолок обходился бы падением, о котором никто не знает.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any, Final

from fastapi import Header, HTTPException, Request

from ux_reviewer.logging_setup import get_logger

log = get_logger("security")

# Сколько разборов разрешено с одного адреса в час.
DEFAULT_RATE_LIMIT: Final[int] = 20

# Сколько разборов в сутки разрешено ВСЕМ посетителям вместе. Это потолок
# расходов владельца: примерно столько же рублей в худшем случае.
DEFAULT_DAILY_LIMIT: Final[int] = 100

RATE_WINDOW: Final[int] = 3600

# Файл суточного счётчика. Лежит рядом с журналом — единственное место, куда
# юнит systemd разрешает сервису писать.
STATE_FILE: Final[Path] = Path(__file__).resolve().parent.parent / "logs" / "usage.json"

# Журнал обращений по адресам: адрес → отметки времени. Живёт в памяти:
# почасовой лимит переживать перезапуск не обязан, в отличие от суточного.
_hits: dict[str, list[float]] = defaultdict(list)


def _configured_token() -> str:
    """Токен владельца из окружения (пустая строка = владельца нет)."""
    return os.getenv("APP_TOKEN", "").strip()


def allowed_origins() -> list[str]:
    """
    Список источников для CORS из переменной ALLOWED_ORIGINS через запятую.

    По умолчанию пусто: страница сервиса лежит на том же домене, и CORS ей не
    нужен, а чужим сайтам дёргать платную ручку из браузера посетителя незачем.
    """
    raw = os.getenv("ALLOWED_ORIGINS", "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def client_ip(request: Request) -> str:
    """
    Адрес обратившегося.

    ⚠️ X-Forwarded-For читается ТОЛЬКО когда мы сами поставили перед сервисом
    обратный прокси (TRUST_PROXY=true). Иначе этот заголовок — подарок
    злоупотребляющему: он подставит любой адрес и обнулит себе счётчик.
    """
    if os.getenv("TRUST_PROXY", "").lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --- Суточный потолок на весь сервис ----------------------------------------


def _read_state() -> dict[str, Any]:
    """
    Прочитать счётчик суток из файла.

    Битый или отсутствующий файл — не авария: начинаем сутки заново, но пишем
    в журнал. Молча проглатывать такое нельзя, иначе потерянный счётчик
    останется незамеченным.
    """
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "day" in data and "used" in data:
            return data
        log.warning("Файл счётчика имеет неожиданный вид — начинаю сутки заново")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Счётчик суток не прочитался (%s) — начинаю сутки заново", exc)
    return {"day": date.today().isoformat(), "used": 0}


def _write_state(state: dict[str, Any]) -> None:
    """Сохранить счётчик. Ошибка записи не должна ронять разбор."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        # ⚠️ Осознанное решение: сервис продолжает работать, но факт записывается.
        # Иначе сбой прав на папку тихо отключил бы весь суточный учёт.
        log.error("Счётчик суток не сохранился: %s. Потолок может сброситься!", exc)


def daily_usage() -> tuple[int, int]:
    """Вернуть (сколько разборов сделано сегодня, каков предел)."""
    limit = int(os.getenv("DAILY_LIMIT", str(DEFAULT_DAILY_LIMIT)))
    state = _read_state()
    today = date.today().isoformat()
    used = int(state["used"]) if state.get("day") == today else 0
    return used, limit


def _spend_daily() -> None:
    """Отметить один израсходованный разбор в суточном счётчике."""
    state = _read_state()
    today = date.today().isoformat()
    used = int(state["used"]) if state.get("day") == today else 0
    _write_state({"day": today, "used": used + 1})


def check_daily_budget() -> None:
    """
    Проверить общий потолок на сутки.

    :raises HTTPException: 429, когда бюджет дня исчерпан.
    """
    used, limit = daily_usage()
    if used >= limit:
        log.warning("Суточный потолок исчерпан: %d из %d", used, limit)
        raise HTTPException(
            status_code=429,
            detail=(
                f"На сегодня демонстрационный лимит исчерпан ({limit} разборов). "
                "Каждый разбор оплачивает владелец сервиса, поэтому счёт ограничен. "
                "Попробуйте завтра."
            ),
        )


# --- Ограничение по адресу ---------------------------------------------------


def check_rate_limit(request: Request) -> None:
    """
    Пропустить запрос или отказать, если с адреса их слишком много.

    :raises HTTPException: 429, когда лимит адреса исчерпан.
    """
    limit = int(os.getenv("RATE_LIMIT_PER_HOUR", str(DEFAULT_RATE_LIMIT)))
    ip = client_ip(request)
    now = time.time()

    # Чистим отметки старше окна — заодно не даём словарю расти бесконечно.
    fresh = [ts for ts in _hits[ip] if now - ts < RATE_WINDOW]
    _hits[ip] = fresh

    if len(fresh) >= limit:
        oldest = min(fresh)
        wait_min = int((RATE_WINDOW - (now - oldest)) // 60) + 1
        log.warning("Лимит адреса исчерпан для %s: %d за час", ip, len(fresh))
        raise HTTPException(
            status_code=429,
            detail=f"Слишком много запросов с вашего адреса. Попробуйте через {wait_min} мин.",
            headers={"Retry-After": str(wait_min * 60)},
        )

    _hits[ip].append(now)


# --- Точка входа охраны ------------------------------------------------------


def access_control(
    request: Request,
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> None:
    """
    Решить, пускать ли этот запрос. Подключается зависимостью к ручке разбора.

    Два пути:
      • ВЛАДЕЛЕЦ — прислал верный токен: проходит мимо суточного потолка
        (иначе в исчерпанный день не смог бы показать собственный сервис);
      • ГОСТЬ — токена нет или он неверен: проверяется лимит адреса И общий
        суточный потолок, и только потом расходуется единица бюджета.

    :raises HTTPException: 429 при исчерпании любого из лимитов.
    """
    expected = _configured_token()

    if expected and x_api_token:
        # compare_digest вместо == : обычное сравнение строк завершается на
        # первом различии, и по времени ответа токен подбирается посимвольно.
        # ⚠️ .encode() обязателен: со строками compare_digest работает только
        # пока обе состоят из ASCII, иначе бросает TypeError. Токен приходит
        # снаружи — прислать кириллицу может кто угодно.
        if secrets.compare_digest(x_api_token.encode("utf-8"), expected.encode("utf-8")):
            log.info("Запрос владельца (токен верный) — вне суточного лимита")
            check_rate_limit(request)
            return
        log.warning("Прислан неверный токен, адрес %s — работаю как с гостем", client_ip(request))

    # Гостевой путь: сначала оба лимита, и только потом трата бюджета.
    check_rate_limit(request)
    check_daily_budget()
    _spend_daily()

    used, limit = daily_usage()
    log.info("Гостевой разбор: израсходовано %d из %d за сутки", used, limit)
