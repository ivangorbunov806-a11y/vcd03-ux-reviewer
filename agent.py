"""
Точка входа агента: UX-рецензент сайта.

Запуск:
    python agent.py https://example.com
    python agent.py https://example.com --json            # машинный вывод
    python agent.py https://example.com --out report.json # сохранить в файл
    python agent.py https://example.com --no-plan         # один запрос вместо двух

Функция run(url) — тот самый «запуск одной функцией с аргументом url» из ТЗ:
её же вызывает веб-сервис, поэтому CLI и HTTP дают одинаковый результат
и расходиться не могут.

Коды возврата (важно для запуска из cron и других скриптов):
    0 — отчёт получен
    1 — ошибка загрузки страницы
    2 — ошибка модели
    3 — прервано пользователем
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

from ux_reviewer.analyzer import UXReport, analyze
from ux_reviewer.fetcher import FetchError, fetch_page
from ux_reviewer.llm_client import LLMClient, LLMError
from ux_reviewer.logging_setup import get_logger

log = get_logger("agent")


def run(url: str, with_plan: bool = True) -> UXReport:
    """
    Разобрать страницу по адресу и вернуть UX-отчёт.

    Оркестрация трёх слоёв и больше ничего: загрузили → разобрали → отдали.
    Вся логика живёт в слоях, поэтому эта функция читается за десять секунд.

    :param url: адрес страницы (http:// или https://).
    :param with_plan: агент сам выбирает критерии разбора (два запроса к модели).
    :raises FetchError: страница не загрузилась или пуста.
    :raises LLMError: модель не ответила или ответила не тем.
    """
    log.info("=== Старт разбора: %s (план=%s) ===", url, with_plan)

    page = fetch_page(url)
    client = LLMClient()
    report = analyze(page, client, with_plan=with_plan)

    log.info("=== Разбор завершён: %s ===", url)
    return report


def main() -> int:
    """Разбор аргументов и печать результата. Возвращает код выхода процесса."""
    parser = argparse.ArgumentParser(
        description="UX-рецензент: разбирает веб-страницу и выдаёт отчёт с рекомендациями",
    )
    parser.add_argument("url", help="адрес страницы для разбора")
    parser.add_argument(
        "--json",
        action="store_true",
        help="вывести отчёт как JSON вместо человекочитаемого текста",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="сохранить отчёт в JSON-файл по указанному пути",
    )
    parser.add_argument(
        "--no-plan",
        action="store_true",
        help="пропустить шаг выбора критериев (дешевле на один запрос, разбор поверхностнее)",
    )
    args = parser.parse_args()

    # .env читается здесь, в точке входа: слои ниже получают настройки готовыми
    # и не лезут в файловую систему сами.
    load_dotenv()

    try:
        report = run(args.url, with_plan=not args.no_plan)
    except FetchError as exc:
        print(f"Ошибка загрузки страницы: {exc}", file=sys.stderr)
        return 1
    except LLMError as exc:
        print(f"Ошибка обращения к модели: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Прервано пользователем", file=sys.stderr)
        return 3

    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
        print(f"Отчёт сохранён: {args.out}")

    print(payload if args.json else report.to_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
