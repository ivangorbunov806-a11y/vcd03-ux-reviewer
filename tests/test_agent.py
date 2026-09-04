"""
Смоук-тесты: проверяют границы между слоями.

Правило этих тестов — НИ ОДНОГО обращения в сеть и к модели: они должны
проходить на машине без ключа и без интернета. Всё, что связано с моделью,
подменяется заглушкой.

Запуск:  python -m unittest discover -s tests
"""

from __future__ import annotations

import unittest
from typing import Any

from ux_reviewer.analyzer import (
    REQUIRED_RECOMMENDATIONS,
    Recommendation,
    UXReport,
    _normalize_recommendations,
    analyze,
)
from ux_reviewer.fetcher import MIN_TEXT_LENGTH, FetchError, PageContent, fetch_page


class FakeClient:
    """
    Заглушка клиента модели.

    Отдаёт заранее заданные ответы по очереди — так проверяется поведение
    анализатора, а не качество модели.
    """

    def __init__(self, answers: list[dict[str, Any]]) -> None:
        self.answers = answers
        self.calls = 0

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer


def make_page(text: str = "текст " * 100) -> PageContent:
    return PageContent(
        url="https://example.com", title="Пример", text=text, original_length=len(text)
    )


class TestFetcherGuards(unittest.TestCase):
    """Границы слоя загрузки: что он обязан отвергнуть, не ходя в сеть."""

    def test_rejects_non_http_scheme(self) -> None:
        with self.assertRaises(FetchError):
            fetch_page("ftp://example.com")

    def test_rejects_plain_path(self) -> None:
        with self.assertRaises(FetchError):
            fetch_page("example.com")

    def test_truncated_flag_reflects_cut(self) -> None:
        page = PageContent(url="u", title="t", text="a" * 100, original_length=500)
        self.assertTrue(page.truncated)

    def test_not_truncated_when_full(self) -> None:
        page = PageContent(url="u", title="t", text="a" * 500, original_length=500)
        self.assertFalse(page.truncated)

    def test_min_length_threshold_is_meaningful(self) -> None:
        # Порог должен быть больше нуля, иначе проверка «пустой страницы» фиктивна.
        self.assertGreater(MIN_TEXT_LENGTH, 0)


class TestRecommendationNormalization(unittest.TestCase):
    """Модель отвечает по-разному — приведение к контракту не должно падать."""

    def test_objects_are_parsed(self) -> None:
        raw = [{"problem": "нет цены", "action": "добавить цену", "priority": "высокий"}]
        result = _normalize_recommendations(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].action, "добавить цену")
        self.assertEqual(result[0].priority, "высокий")

    def test_plain_strings_are_accepted(self) -> None:
        result = _normalize_recommendations(["вынести телефон в шапку"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].action, "вынести телефон в шапку")

    def test_empty_input_gives_empty_list(self) -> None:
        self.assertEqual(_normalize_recommendations(None), [])

    def test_priority_defaults_when_missing(self) -> None:
        result = _normalize_recommendations([{"problem": "п", "action": "д"}])
        self.assertEqual(result[0].priority, "средний")


class TestAnalyzeBoundary(unittest.TestCase):
    """Главная проверка на границе: отчёт обязан соответствовать ТЗ."""

    def _answers(self, count: int) -> list[dict[str, Any]]:
        plan = {
            "page_type": "лендинг",
            "audience": "покупатели",
            "target_action": "оставить заявку",
            "criteria": ["ясность", "доверие"],
        }
        review = {
            "summary": "Короткий вывод.",
            "pros": ["плюс"],
            "cons": ["минус"],
            "recommendations": [
                {"problem": f"проблема {i}", "action": f"действие {i}", "priority": "средний"}
                for i in range(count)
            ],
        }
        return [plan, review]

    def test_exact_count_passes_through(self) -> None:
        client = FakeClient(self._answers(REQUIRED_RECOMMENDATIONS))
        report = analyze(make_page(), client)  # type: ignore[arg-type]
        self.assertEqual(len(report.recommendations), REQUIRED_RECOMMENDATIONS)

    def test_excess_recommendations_are_trimmed(self) -> None:
        # Модель дала больше, чем требует ТЗ, — лишнее обязано быть срезано.
        client = FakeClient(self._answers(REQUIRED_RECOMMENDATIONS + 3))
        report = analyze(make_page(), client)  # type: ignore[arg-type]
        self.assertEqual(len(report.recommendations), REQUIRED_RECOMMENDATIONS)

    def test_plan_fields_land_in_report(self) -> None:
        client = FakeClient(self._answers(REQUIRED_RECOMMENDATIONS))
        report = analyze(make_page(), client)  # type: ignore[arg-type]
        self.assertEqual(report.page_type, "лендинг")
        self.assertEqual(report.target_action, "оставить заявку")

    def test_no_plan_mode_makes_single_call(self) -> None:
        # with_plan=False должен экономить именно ЗАПРОС, а не только строку в логе.
        client = FakeClient([self._answers(REQUIRED_RECOMMENDATIONS)[1]])
        analyze(make_page(), client, with_plan=False)  # type: ignore[arg-type]
        self.assertEqual(client.calls, 1)

    def test_truncation_flag_reaches_report(self) -> None:
        page = PageContent(url="u", title="t", text="a" * 100, original_length=9000)
        client = FakeClient(self._answers(REQUIRED_RECOMMENDATIONS))
        report = analyze(page, client)  # type: ignore[arg-type]
        self.assertTrue(report.truncated)


class TestReportRendering(unittest.TestCase):
    """Отчёт должен читаться человеком и сериализоваться машиной."""

    def _report(self) -> UXReport:
        return UXReport(
            url="https://example.com",
            title="Пример",
            page_type="лендинг",
            audience="покупатели",
            target_action="заявка",
            summary="Вывод.",
            pros=["ясный заголовок"],
            cons=["нет цены"],
            recommendations=[Recommendation("нет цены", "добавить цену", "высокий")],
        )

    def test_to_dict_is_serializable(self) -> None:
        data = self._report().to_dict()
        self.assertEqual(data["page_type"], "лендинг")
        self.assertEqual(data["recommendations"][0]["action"], "добавить цену")

    def test_to_text_contains_key_blocks(self) -> None:
        text = self._report().to_text()
        self.assertIn("СИЛЬНЫЕ СТОРОНЫ", text)
        self.assertIn("СЛАБЫЕ МЕСТА", text)
        self.assertIn("РЕКОМЕНДАЦИИ", text)
        self.assertIn("добавить цену", text)

    def test_truncated_note_shown_only_when_needed(self) -> None:
        report = self._report()
        self.assertNotIn("разбиралась только", report.to_text())
        report.truncated = True
        self.assertIn("разбиралась только", report.to_text())


if __name__ == "__main__":
    unittest.main()
