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

Охрана доступа (токен, лимит частоты, список источников) — в app/security.py.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.routers import review
from app.security import allowed_origins
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
        "сильные стороны, слабые места и пять рекомендаций.\n\n"
        "Разбор требует заголовка `X-API-Token`."
    ),
    version=__version__,
)

# CORS по списку из переменной ALLOWED_ORIGINS. Пустой список = доступа из
# браузеров нет вообще, и это правильное значение по умолчанию: сервис
# вызывается скриптами с токеном, а не чужими веб-страницами.
origins = allowed_origins()
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["POST", "GET"],
        allow_headers=["X-API-Token", "Content-Type"],
    )
    log.info("CORS разрешён для: %s", ", ".join(origins))
else:
    log.info("CORS закрыт (ALLOWED_ORIGINS пуст) — обращения только вне браузера")


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Заголовки, отключающие типовые способы навредить через браузер.

    Мелочь по объёму, но ставится один раз и работает всегда: запрет угадывания
    типа содержимого, запрет показа сервиса в чужом фрейме и просьба не слать
    наш адрес третьим сторонам.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(review.router)


# Страница читается с диска ОДИН раз при старте, а не на каждый запрос: файл
# не меняется во время работы, и лишнее обращение к диску тут ни к чему.
INDEX_HTML = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse, tags=["страница"])
def index() -> HTMLResponse:
    """
    Человеческий вход в сервис.

    ⚠️ Раньше здесь отдавался служебный JSON, и в браузере это выглядело как
    «сервис не открывается»: формально ответ верный, а человеку он ничего не
    даёт. Справочный JSON никуда не делся — он переехал на /api.
    """
    return HTMLResponse(INDEX_HTML)


@app.get("/api", tags=["служебное"])
def api_info() -> dict[str, str]:
    """Короткая справка для программ: куда обращаться и что нужно."""
    return {
        "service": "UX-рецензент сайта",
        "version": __version__,
        "docs": "/docs",
        "main_endpoint": "POST /review (нужен заголовок X-API-Token)",
    }


@app.get("/health", tags=["служебное"])
def health() -> dict[str, str]:
    """
    Проверка живости для systemd и мониторинга: отвечает ли процесс вообще.

    Осознанно БЕЗ токена и без обращения к модели: проверка живости не должна
    ни стоить денег, ни зависеть от внешнего провайдера — иначе сторож начнёт
    перезапускать здоровый сервис из-за чужой аварии.
    """
    return {"status": "ok"}
