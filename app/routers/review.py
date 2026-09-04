"""
Ручка разбора страницы.

Единственная задача роутера — перевести ошибки нижних слоёв в понятные коды HTTP.
Это и есть защита границы «веб → приложение»: наружу не должно улетать
необработанное исключение со стек-трейсом, в котором виден внутренний адрес
провайдера, а иногда и часть ключа.

Коды выбраны осознанно:
  400 — виноват тот, кто прислал адрес (страница не открылась, текста нет);
  502 — виноват внешний провайдер модели, повторить позже имеет смысл.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agent import run
from ux_reviewer.fetcher import FetchError
from ux_reviewer.llm_client import LLMError
from ux_reviewer.logging_setup import get_logger

log = get_logger("api")

router = APIRouter(tags=["разбор"])


class ReviewRequest(BaseModel):
    """Тело запроса: адрес страницы и способ разбора."""

    url: str = Field(..., description="Адрес страницы, начиная с http:// или https://")
    with_plan: bool = Field(
        True,
        description=(
            "Агент сам выбирает критерии разбора (два запроса к модели). "
            "false — быстрее и дешевле, но разбор поверхностнее."
        ),
    )

    model_config = {
        "json_schema_extra": {
            "examples": [{"url": "https://example.com", "with_plan": True}]
        }
    }


@router.post("/review", summary="Разобрать страницу и вернуть UX-отчёт")
def review(request: ReviewRequest) -> dict[str, Any]:
    """Принять адрес, вернуть отчёт. Вся работа — в agent.run()."""
    log.info("HTTP-запрос на разбор: %s", request.url)
    try:
        report = run(request.url, with_plan=request.with_plan)
    except FetchError as exc:
        log.warning("Отказ на границе загрузки: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LLMError as exc:
        log.error("Отказ на границе модели: %s", exc)
        raise HTTPException(
            status_code=502, detail=f"Модель недоступна или ответила некорректно: {exc}"
        ) from exc

    return report.to_dict()
