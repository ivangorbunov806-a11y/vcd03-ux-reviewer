"""
Защита веб-слоя: кто пускается к сервису и как часто.

⚠️ ЗАЧЕМ ЭТО ВООБЩЕ НУЖНО. Ручка /review стоит денег: каждый вызов — два запроса
к платной модели. Сервис, открытый в интернет без охраны, — это открытый кран
к чужому кошельку. Адреса новых серверов боты находят за часы, а не за месяцы:
они перебирают диапазоны хостеров и читают журналы выданных TLS-сертификатов,
которые публичны по устройству. «Адрес никто не знает» защитой не является.

Три меры, каждая закрывает свою дыру:
  1. ТОКЕН — отсекает посторонних вообще;
  2. ОГРАНИЧЕНИЕ ЧАСТОТЫ — не даёт своему же токену (например, утёкшему)
     сжечь бюджет за час;
  3. СПИСОК ИСТОЧНИКОВ CORS — не позволяет чужому сайту дёргать сервис из
     браузера посетителя.

⭐ FAIL-CLOSED. Если токен в настройках не задан, сервис НЕ работает открыто, а
отвечает отказом. Это прямое следствие правила «настройка — просьба, а не запрет»:
забытая переменная не должна молча превращаться в публичный доступ. Локальная
разработка на это не страдает — командная строка веб-слой не трогает.
"""

from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict
from typing import Final

from fastapi import Header, HTTPException, Request

from ux_reviewer.logging_setup import get_logger

log = get_logger("security")

# Сколько разборов с одного адреса разрешено в час. 20 × ~2 ₽ = потолок расхода
# около 40 ₽/час на источник даже при полном злоупотреблении.
DEFAULT_RATE_LIMIT: Final[int] = 20

# Окно ограничения в секундах.
RATE_WINDOW: Final[int] = 3600

# Журнал обращений: адрес → отметки времени. Живёт в памяти процесса.
# ⚠️ Осознанное упрощение: при перезапуске счётчики обнуляются, а при нескольких
# процессах у каждого свой счёт. Для одного сервиса на одном сервере этого
# достаточно; для нескольких машин понадобится общее хранилище (Redis).
_hits: dict[str, list[float]] = defaultdict(list)


def _configured_token() -> str:
    """Токен доступа из окружения (пустая строка = не настроен)."""
    return os.getenv("APP_TOKEN", "").strip()


def allowed_origins() -> list[str]:
    """
    Список источников для CORS из переменной ALLOWED_ORIGINS через запятую.

    По умолчанию — пусто: ни один сайт не может обращаться к сервису из браузера.
    Раньше здесь стояла звёздочка «потому что учебный проект» — но именно так
    учебные сервисы и превращаются в чужой бесплатный API.
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


def check_rate_limit(request: Request) -> None:
    """
    Пропустить запрос или отказать, если с адреса их слишком много.

    :raises HTTPException: 429, когда лимит исчерпан.
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
        log.warning("Лимит исчерпан для %s: %d запросов за час", ip, len(fresh))
        raise HTTPException(
            status_code=429,
            detail=f"Слишком много запросов. Попробуйте через {wait_min} мин.",
            headers={"Retry-After": str(wait_min * 60)},
        )

    _hits[ip].append(now)


def require_token(
    request: Request,
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> None:
    """
    Проверка токена доступа. Подключается как зависимость к защищённым ручкам.

    :raises HTTPException: 503 — токен не настроен на сервере; 401 — не совпал.
    """
    expected = _configured_token()

    if not expected:
        # Fail-closed: лучше отказать всем, чем молча пускать всех.
        log.error("APP_TOKEN не задан — ручка разбора закрыта до настройки")
        raise HTTPException(
            status_code=503,
            detail=(
                "Сервис не сконфигурирован: не задан APP_TOKEN. "
                "Разбор недоступен, пока администратор не настроит доступ."
            ),
        )

    # compare_digest вместо == : обычное сравнение строк завершается на первом
    # различии, и по времени ответа токен подбирается посимвольно.
    # ⚠️ .encode() обязателен: со строками compare_digest работает ТОЛЬКО пока
    # обе состоят из ASCII, иначе бросает TypeError. Токен приходит снаружи —
    # прислать кириллицу может кто угодно, и это уронило бы ручку в 500-ю
    # ошибку вместо честного отказа. Поймано тестом, а не в проде.
    if not x_api_token or not secrets.compare_digest(
        x_api_token.encode("utf-8"), expected.encode("utf-8")
    ):
        log.warning("Отказ по токену, адрес %s", client_ip(request))
        raise HTTPException(
            status_code=401,
            detail="Нужен верный заголовок X-API-Token",
        )

    check_rate_limit(request)
