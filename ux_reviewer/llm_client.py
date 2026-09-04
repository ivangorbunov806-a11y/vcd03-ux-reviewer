"""
Слой общения с языковой моделью (граница «наш код → внешний API»).

Провайдер по умолчанию — **provod.ai**: российский агрегатор с OpenAI-совместимым
API, поэтому подходит официальная библиотека openai — меняется только base_url.
Выбран вместо прямого OpenAI по двум причинам: оплата рублёвой картой и работа
без VPN.

⚠️ ПРИЧУДЫ МОДЕЛЕЙ — главная грабля этого слоя.
Часть моделей у provod отвергает параметры, которые для OpenAI считаются обычными,
и отвечает generic-ошибкой БЕЗ имени виноватого параметра. Разобрано живьём:
  • ветка openai/gpt-5.4* — не принимает temperature вообще и требует явного
    управления reasoning (include_reasoning=false);
  • ветка anthropic/* — тоже не принимает temperature.
Поэтому payload собирается не «как в документации OpenAI», а через таблицу
MODEL_QUIRKS. Добавляете модель — сначала проверьте её голым запросом.

Повторы: сетевые сбои и таймауты повторяются до 3 раз с экспоненциальной задержкой
(требование ТЗ). Ошибки 4xx НЕ повторяются осознанно — это отказ по содержанию
запроса, и десять одинаковых попыток дадут десять одинаковых отказов, только
дольше и дороже.
"""

from __future__ import annotations

import json
import os
from typing import Any, Final

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ux_reviewer.logging_setup import get_logger

log = get_logger("llm")

# Базовый адрес provod. Вынесен константой, а не зашит в место вызова: смена
# провайдера на любой OpenAI-совместимый = правка одной переменной в .env.
DEFAULT_BASE_URL: Final[str] = "https://api.provod.ai/v1"

# Дефолтная модель. gpt-5.4-mini выбрана как дешёвая (≈64/383 ₽ за млн токенов
# вход/выход) и достаточная для разбора текста страницы. Смена — через .env,
# без правки кода.
DEFAULT_MODEL: Final[str] = "openai/gpt-5.4-mini"

# Запас по токенам сознательно большой: у reasoning-моделей скрытые рассуждения
# считаются в max_tokens, и при малом лимите ответ приходит ПУСТЫМ, а не обрезанным.
DEFAULT_MAX_TOKENS: Final[int] = 4000
DEFAULT_TIMEOUT: Final[float] = 180.0

# Таблица причуд: префикс модели → что сделать с payload.
#   drop — параметры, которые модель не переваривает (уйдут из запроса);
#   add  — параметры, без которых модель отвечает ошибкой.
MODEL_QUIRKS: Final[list[tuple[str, dict[str, Any]]]] = [
    ("openai/gpt-5.4", {"drop": ("temperature",), "add": {"include_reasoning": False}}),
    ("anthropic/", {"drop": ("temperature",)}),
]


class LLMError(RuntimeError):
    """Ошибка обращения к модели, понятная вызывающему слою."""


def _quirks_for(model: str) -> dict[str, Any]:
    """Правки payload под конкретную модель (пустой словарь, если причуд нет)."""
    for prefix, rules in MODEL_QUIRKS:
        if model.startswith(prefix):
            return rules
    return {}


class LLMClient:
    """
    Клиент языковой модели.

    Три метода по возрастанию строгости ответа:
      chat             — свободный текст по одному промпту;
      chat_with_system — то же, но с ролью (системным промптом);
      chat_json        — структурированный ответ, разобранный в словарь.

    system_prompt и max_tokens меняются на лету (требование ТЗ урока): один и тот
    же клиент переиспользуется для разных шагов агента, не пересоздаваясь.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        system_prompt: str = "Ты полезный ассистент. Отвечай по-русски.",
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url or os.getenv("BASE_URL") or DEFAULT_BASE_URL
        self.api_key = api_key or os.getenv("API_KEY") or ""
        self.model = model or os.getenv("MODEL") or DEFAULT_MODEL
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens

        if not self.api_key:
            # Падаем сразу и внятно. Без ключа запрос всё равно вернёт 401, но
            # разбираться в чужой ошибке дольше, чем прочитать эту строку.
            raise LLMError(
                "Не задан API_KEY. Скопируйте .env.example в .env "
                "и впишите ключ provod.ai"
            )

        self._client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=timeout,
            max_retries=0,  # повторами управляет tenacity ниже, иначе они удвоятся
        )
        log.info("Клиент LLM готов: модель=%s, база=%s", self.model, self.base_url)

    # --- внутренняя кухня -------------------------------------------------

    @retry(
        # Повторяем только то, что имеет шанс пройти со второй попытки:
        # обрыв связи и таймаут. Отказ по содержанию запроса сюда не попадает.
        # ⚠️ Ловим исключения библиотеки openai, а НЕ её внутреннего HTTP-клиента:
        # в openai 3.x им стал httpx2 вместо httpx, и прямой импорт того же httpx
        # ронял импорт модуля целиком. APIConnectionError покрывает транспортные
        # сбои независимо от того, чем библиотека ходит в сеть внутри.
        retry=retry_if_exception_type((APIConnectionError, APITimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=20),
        reraise=True,
    )
    def _call(self, messages: list[dict[str, str]], json_mode: bool = False) -> str:
        """
        Один запрос к модели с учётом причуд. Возвращает текст ответа.

        Здесь проходит ГРАНИЦА «наш код → провайдер»: наверх поднимается либо
        непустая строка, либо исключение. Пустой ответ успехом не считается —
        у reasoning-моделей он означает, что весь бюджет токенов ушёл в скрытые
        рассуждения, и снаружи это выглядело бы как «модель промолчала».
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": 0.4,
        }

        rules = _quirks_for(self.model)
        for param in rules.get("drop", ()):
            payload.pop(param, None)
        extra: dict[str, Any] = dict(rules.get("add", {}))

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            response = self._client.chat.completions.create(**payload, extra_body=extra)
        except APIStatusError as exc:
            # 4xx: повторять бессмысленно — сообщаем причину и выходим.
            # Тело ответа обрезаем: provod кладёт туда подсказку, но целиком оно
            # длинное и засоряет лог.
            log.error(
                "Отказ провайдера: HTTP %s. Тело: %s",
                exc.status_code,
                str(getattr(exc.response, "text", ""))[:400],
            )
            raise LLMError(f"Провайдер отказал: HTTP {exc.status_code}") from exc

        text = (response.choices[0].message.content or "").strip()
        usage = getattr(response, "usage", None)
        log.info(
            "Ответ модели: %d символов, токены вход/выход %s/%s",
            len(text),
            getattr(usage, "prompt_tokens", "?"),
            getattr(usage, "completion_tokens", "?"),
        )
        if not text:
            raise LLMError(
                "Модель вернула пустой ответ. Вероятная причина — весь max_tokens "
                "ушёл в скрытые reasoning-токены; увеличьте MAX_TOKENS."
            )
        return text

    # --- публичные методы -------------------------------------------------

    def chat(self, prompt: str) -> str:
        """Простой запрос: текст на входе — текст на выходе."""
        return self._call(
            [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ]
        )

    def chat_with_system(self, system_prompt: str, user_prompt: str) -> str:
        """Запрос с явной ролью — системный промпт задаётся на один вызов."""
        return self._call(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
        )

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """
        Структурированный ответ, разобранный в словарь.

        ⚠️ Даже в json-режиме модель иногда обрамляет ответ тройными обратными
        кавычками. Поэтому перед разбором снимаем обёртку — без этого шага
        ловится JSONDecodeError на ровном месте.
        """
        raw = self._call(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            json_mode=True,
        )
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            parts = cleaned.split("```")
            cleaned = parts[1] if len(parts) > 1 else cleaned
            if cleaned.lstrip().lower().startswith("json"):
                cleaned = cleaned.lstrip()[4:]
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            log.error("Ответ не разобрался как JSON. Первые 300 символов: %s", raw[:300])
            raise LLMError("Модель вернула не-JSON там, где ожидался JSON") from exc

        if not isinstance(data, dict):
            raise LLMError(f"Ожидался объект JSON, пришёл {type(data).__name__}")
        return data


if __name__ == "__main__":
    # Точка входа для проверки слоя ОТДЕЛЬНО от всего остального: если здесь
    # ответ пришёл — ключ, база и модель в порядке, и дефект надо искать выше.
    from dotenv import load_dotenv

    load_dotenv()
    client = LLMClient()
    print("chat():", client.chat("Ответь одним словом: работает?"))
    print(
        "chat_with_system():",
        client.chat_with_system("Ты отвечаешь ровно одним словом.", "Столица Франции?"),
    )
    print(
        "chat_json():",
        client.chat_json(
            'Верни строго JSON вида {"ok": true, "note": "строка"}.',
            "Подтверди, что связь есть.",
        ),
    )
