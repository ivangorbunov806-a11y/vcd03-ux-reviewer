"""
Слой анализа: превращает текст страницы в UX-отчёт.

Здесь живёт то, ради чего проект существует, — промпты и проверка ответа модели.
Слой НИЧЕГО не знает ни про HTTP, ни про устройство клиента LLM: на вход ему
дают готовый текст, на выходе он отдаёт разобранный отчёт. Поэтому промпты можно
править и переигрывать на сохранённом тексте, не тратя запросы на скачивание.

⭐ Почему два шага, а не один.
Тема урока — АВТОНОМНЫЙ агент, то есть программа, которая сама решает, что делать,
а не гоняет один зашитый промпт. Поэтому:
  шаг 1 — агент сам определяет, что перед ним за страница, кто её аудитория,
          какое действие она должна вызвать и по каким критериям её судить;
  шаг 2 — агент разбирает страницу ПО СОБСТВЕННЫМ критериям из шага 1.
Разбор лендинга и разбор статьи в блоге получаются разными не потому, что мы
написали два промпта, а потому, что агент сам выбрал разные критерии.

⚠️ Цена: два запроса вместо одного. На дешёвой модели это единицы рублей, но
если бюджет важнее глубины — шаг 1 отключается флагом (см. analyze()).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

from ux_reviewer.fetcher import PageContent
from ux_reviewer.llm_client import LLMClient, LLMError
from ux_reviewer.logging_setup import get_logger

log = get_logger("analyze")

# Сколько рекомендаций требует ТЗ. Вынесено константой, потому что число
# проверяется в трёх местах: в промпте, в проверке ответа и в тестах.
REQUIRED_RECOMMENDATIONS: Final[int] = 5

# --- Шаг 1: агент определяет, что перед ним и как это судить -----------------

PLANNER_SYSTEM: Final[str] = """Ты ведущий UX-исследователь. Тебе дают текст веб-страницы.
Твоя задача — НЕ разбирать её, а понять, что это за страница и по каким критериям
её честно судить.

Верни строго JSON:
{
  "page_type": "тип страницы: лендинг, интернет-магазин, блог, корпоративный сайт, ...",
  "audience": "кто её целевой посетитель, одним предложением",
  "target_action": "главное действие, ради которого страница существует",
  "criteria": ["4-6 критериев оценки, важных именно для ЭТОГО типа страницы"]
}

Критерии формулируй под конкретную страницу, а не общими словами: у магазина и у
блога разные больные места. Отвечай по-русски."""

# --- Шаг 2: разбор по выбранным критериям ------------------------------------

REVIEWER_SYSTEM: Final[str] = f"""Ты UX-рецензент с опытом аудита сайтов.
Тебе дают текст веб-страницы и критерии оценки. Разбери страницу и верни строго JSON:

{{
  "summary": "2-3 предложения: что это за страница и главный вывод",
  "pros": ["сильные стороны, 3-5 пунктов"],
  "cons": ["слабые места, 3-5 пунктов"],
  "recommendations": [
    {{
      "problem": "что именно мешает посетителю",
      "action": "что конкретно сделать",
      "priority": "высокий | средний | низкий"
    }}
  ]
}}

Жёсткие правила:
1. Рекомендаций ровно {REQUIRED_RECOMMENDATIONS} — не больше и не меньше.
2. Пиши о том, что ВИДНО в переданном тексте. Ты не видишь картинки, цвета и
   вёрстку — не делай вид, что видишь. Если чего-то нет в тексте, так и скажи:
   "в тексте страницы не нашлось" — это честный вывод, а не пробел.
3. Рекомендация — это действие, а не пожелание. "Улучшить дизайн" не годится,
   "вынести цену и срок доставки в первый экран" годится.
4. Никакой воды и общих слов про "современный дизайн" и "юзабилити".
Отвечай по-русски."""


@dataclass
class Recommendation:
    """Одна рекомендация: что не так, что сделать и насколько это срочно."""

    problem: str
    action: str
    priority: str = "средний"


@dataclass
class UXReport:
    """
    Готовый отчёт — контракт этого слоя с теми, кто его вызывает
    (CLI и веб-сервис читают одно и то же).
    """

    url: str
    title: str
    page_type: str
    audience: str
    target_action: str
    summary: str
    pros: list[str] = field(default_factory=list)
    cons: list[str] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    # Служебное: разбиралась ли страница целиком. В отчёте это честная оговорка,
    # а не мелочь — на обрезанном тексте выводы слабее.
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_text(self) -> str:
        """Человекочитаемый вид для терминала и для скриншотов при сдаче."""
        lines = [
            f"UX-отчёт: {self.url}",
            f"Заголовок: {self.title or '(нет)'}",
            f"Тип страницы: {self.page_type} · аудитория: {self.audience}",
            f"Целевое действие: {self.target_action}",
            "",
            self.summary,
            "",
            "СИЛЬНЫЕ СТОРОНЫ",
        ]
        lines += [f"  + {item}" for item in self.pros] or ["  (не найдено)"]
        lines += ["", "СЛАБЫЕ МЕСТА"]
        lines += [f"  - {item}" for item in self.cons] or ["  (не найдено)"]
        lines += ["", f"РЕКОМЕНДАЦИИ ({len(self.recommendations)})"]
        for i, rec in enumerate(self.recommendations, 1):
            lines.append(f"  {i}. [{rec.priority}] {rec.problem}")
            lines.append(f"     → {rec.action}")
        if self.truncated:
            lines += ["", "⚠️ Страница длинная: разбиралась только её первая часть."]
        return "\n".join(lines)


def _plan_criteria(client: LLMClient, page: PageContent) -> dict[str, Any]:
    """
    Шаг 1: агент сам определяет тип страницы и критерии разбора.

    Ошибка здесь НЕ фатальна: без плана разбор всё равно возможен, просто по
    общим критериям. Поэтому исключение гасится, но обязательно с записью в лог —
    молчаливый откат на запасной путь и есть та самая «тихая деградация»,
    которую потом неделю ищут.
    """
    user_prompt = (
        f"Заголовок страницы: {page.title}\n"
        f"Адрес: {page.url}\n\n"
        f"Текст страницы:\n{page.text}"
    )
    try:
        plan = client.chat_json(PLANNER_SYSTEM, user_prompt)
    except LLMError as exc:
        log.warning("Шаг 1 (план) не удался: %s. Разбираю по общим критериям.", exc)
        return {}

    log.info(
        "План готов: тип=%r, критериев %d",
        plan.get("page_type", "?"),
        len(plan.get("criteria") or []),
    )
    return plan


def _normalize_recommendations(raw: Any) -> list[Recommendation]:
    """
    Привести рекомендации к нашему виду.

    Модель иногда возвращает список строк вместо списка объектов — это не повод
    ронять весь прогон, поэтому строка превращается в рекомендацию без действия.
    """
    result: list[Recommendation] = []
    for item in raw or []:
        if isinstance(item, dict):
            result.append(
                Recommendation(
                    problem=str(item.get("problem", "")).strip(),
                    action=str(item.get("action", "")).strip(),
                    priority=str(item.get("priority", "средний")).strip() or "средний",
                )
            )
        elif isinstance(item, str) and item.strip():
            result.append(Recommendation(problem="", action=item.strip()))
    return result


def analyze(page: PageContent, client: LLMClient, with_plan: bool = True) -> UXReport:
    """
    Разобрать страницу и вернуть UX-отчёт.

    :param page: результат работы слоя загрузки.
    :param client: клиент модели.
    :param with_plan: делать ли шаг 1 (агент сам выбирает критерии). False —
                      экономия одного запроса ценой глубины разбора.
    :raises LLMError: модель не ответила или ответ не разобрался.
    """
    plan = _plan_criteria(client, page) if with_plan else {}

    criteria = plan.get("criteria") or [
        "понятность предложения с первого экрана",
        "полнота ответов на вопросы посетителя",
        "заметность целевого действия",
        "доверие: контакты, гарантии, доказательства",
    ]
    criteria_block = "\n".join(f"- {c}" for c in criteria)

    user_prompt = (
        f"Адрес: {page.url}\n"
        f"Заголовок: {page.title}\n"
        f"Тип страницы (определён ранее): {plan.get('page_type', 'не определён')}\n"
        f"Аудитория: {plan.get('audience', 'не определена')}\n"
        f"Целевое действие: {plan.get('target_action', 'не определено')}\n\n"
        f"Критерии разбора:\n{criteria_block}\n\n"
        f"Текст страницы:\n{page.text}"
    )

    data = client.chat_json(REVIEWER_SYSTEM, user_prompt)

    recommendations = _normalize_recommendations(data.get("recommendations"))

    # ⭐ ПРОВЕРКА НА ГРАНИЦЕ. Модель могла ответить формально успешно и при этом
    # дать не то количество рекомендаций, что требует ТЗ. Молча принять такой
    # ответ — значит сдать работу, не выполняющую собственное ТЗ.
    if len(recommendations) != REQUIRED_RECOMMENDATIONS:
        log.warning(
            "Модель вернула %d рекомендаций вместо %d — выравниваю",
            len(recommendations),
            REQUIRED_RECOMMENDATIONS,
        )
        recommendations = recommendations[:REQUIRED_RECOMMENDATIONS]

    report = UXReport(
        url=page.url,
        title=page.title,
        page_type=str(plan.get("page_type", "не определён")),
        audience=str(plan.get("audience", "не определена")),
        target_action=str(plan.get("target_action", "не определено")),
        summary=str(data.get("summary", "")).strip(),
        pros=[str(x).strip() for x in (data.get("pros") or []) if str(x).strip()],
        cons=[str(x).strip() for x in (data.get("cons") or []) if str(x).strip()],
        recommendations=recommendations,
        truncated=page.truncated,
    )

    log.info(
        "Отчёт собран: плюсов %d, минусов %d, рекомендаций %d",
        len(report.pros),
        len(report.cons),
        len(report.recommendations),
    )
    return report
