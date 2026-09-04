"""
Веб-сервис UX-рецензента (FastAPI).

Тонкий слой поверх agent.run(): принимает адрес по HTTP, отдаёт тот же отчёт,
что и командная строка. Своей логики разбора здесь НЕТ и быть не должно —
иначе CLI и веб начнут расходиться в выводах, а разойдутся они молча.

Запуск локально:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
Проверка в браузере: http://localhost:8000/docs (Swagger UI).

⚠️ POST-ручку нельзя проверить, просто открыв её адрес в браузере — будет
405 Method Not Allowed. Для проверки руками есть Swagger.
"""

from __future__ import annotations

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import review
from ux_reviewer import __version__
from ux_reviewer.logging_setup import setup_logging

# ⚠️ Настройки читаются ЗДЕСЬ, а не внутри слоёв. Грабля, пойманная живьём при
# первой же проверке: load_dotenv() стоял только в agent.py, поэтому из
# командной строки агент работал, а тот же код через HTTP падал с «не задан
# API_KEY». Две точки входа — два места, где окружение обязано быть загружено.
# В Docker переменные приходят через env_file — load_dotenv их не затирает.
load_dotenv()

log = setup_logging()

app = FastAPI(
    title="UX-рецензент сайта",
    description=(
        "Автономный агент: по адресу страницы возвращает UX-отчёт — "
        "сильные стороны, слабые места и пять рекомендаций."
    ),
    version=__version__,
)

# CORS открыт полностью, потому что сервис учебный и фронтенд может быть запущен
# с любого адреса. ⚠️ Для продакшена сюда прописывается конкретный домен:
# allow_origins=["https://ваш-домен"] — иначе к API сможет ходить любой сайт.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(review.router)


@app.get("/", tags=["служебное"])
def root() -> dict[str, str]:
    """Короткая справка: что это за сервис и куда идти дальше."""
    return {
        "service": "UX-рецензент сайта",
        "version": __version__,
        "docs": "/docs",
        "main_endpoint": "POST /review",
    }


@app.get("/health", tags=["служебное"])
def health() -> dict[str, str]:
    """Проверка живости для Docker и мониторинга: отвечает ли процесс вообще."""
    return {"status": "ok"}
