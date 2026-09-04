"""
Настройка логирования проекта.

Зачем отдельный модуль: логи заводятся ОДИН раз и одинаково для всех точек входа
(CLI `agent.py` и веб-сервис `app/main.py`), иначе каждая заводит своё и они
расходятся — в одном месте пишется в файл, в другом только в консоль.

Два приёмника осознанно:
  • stdout — для человека, который прямо сейчас смотрит в терминал;
  • ФАЙЛ с ротацией — для расследования постфактум. Под Docker и cron stdout
    теряется, и без файла разбирать аварию будет нечем.

Ротация обязательна: лог без ограничения размера рано или поздно съедает диск.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Корень проекта = папка на уровень выше пакета. Путь считается от файла, а не от
# текущей директории: запуск из другой папки не должен уводить лог в случайное место.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "ux-reviewer.log"

# 1 МБ × 3 файла — с запасом на несколько сотен прогонов, но диск не переполнит.
MAX_BYTES = 1_000_000
BACKUP_COUNT = 3

_CONFIGURED = False


def setup_logging(level: int | None = None) -> logging.Logger:
    """
    Включает логирование и возвращает логгер приложения.

    Вызывать можно сколько угодно раз — повторный вызов не плодит обработчики
    (иначе каждая строка дублировалась бы столько раз, сколько было вызовов).

    :param level: уровень; по умолчанию INFO, либо значение LOG_LEVEL из окружения.
    """
    global _CONFIGURED

    logger = logging.getLogger("ux_reviewer")
    if _CONFIGURED:
        return logger

    if level is None:
        level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)

    logger.setLevel(level)
    # propagate=False: иначе сообщения уходят ещё и в корневой логгер, который
    # настраивает uvicorn, — получаются задвоенные строки в консоли сервера.
    logger.propagate = False

    fmt = logging.Formatter(
        # Метка времени + уровень + шаг: по этим трём полям лог читается без исходников.
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ⚠️ Консоль Windows по умолчанию не в UTF-8, и русские строки в логе
    # превращаются в мусор вида «????». Файл при этом пишется правильно, поэтому
    # дефект выглядит загадочно. Переключаем поток явно.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    _CONFIGURED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Логгер конкретного модуля — дочерний, чтобы в строке было видно слой."""
    setup_logging()
    return logging.getLogger(f"ux_reviewer.{name}")
