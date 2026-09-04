"""
Защита от SSRF — самая опасная дыра сервиса, который скачивает чужие адреса.

⚠️ ЧЕМ ЭТО ГРОЗИТ. Наш сервис принимает URL от постороннего человека и идёт по
нему САМ, изнутри сервера. То есть посетитель может заставить его постучаться
туда, куда снаружи хода нет:

  http://127.0.0.1:8000/       — наши же внутренние ручки;
  http://169.254.169.254/...   — служба метаданных облака: там лежат токены
                                 доступа к панели хостера;
  http://10.0.0.5/             — соседние машины во внутренней сети;
  file:///etc/passwd           — вообще не HTTP.

Это называется SSRF (подделка запроса со стороны сервера). Пока сервис работает
на ноутбуке, дыра теоретическая. Как только он открыт в интернет — практическая.

⭐ ПОЧЕМУ ПРОВЕРЯЕМ IP, А НЕ ИМЯ. Проверять «не localhost ли в адресе» бесполезно:
любой может завести домен, который резолвится в 127.0.0.1 или в 169.254.169.254.
Поэтому имя РЕЗОЛВИТСЯ, и решение принимается по фактическим адресам — по всем,
что вернул DNS, а не по первому.

⭐ ПОЧЕМУ РЕДИРЕКТЫ ИДЁМ РУКАМИ. Внешний адрес может ответить «перейди на
127.0.0.1» — и библиотека послушно перейдёт, а проверка останется позади.
Поэтому автоматические переходы выключены, и каждый шаг цепочки проверяется
заново.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Final
from urllib.parse import urlparse

from ux_reviewer.logging_setup import get_logger

log = get_logger("safety")

# Схемы, по которым вообще можно ходить. Всё остальное (file, ftp, gopher, data)
# отвергается: они либо читают локальные файлы, либо давно служат для обхода
# подобных проверок.
ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

# Порты, кроме стандартных веб-портов, закрыты: обращение на 22 или 6379
# (ssh, redis) — это не загрузка страницы, а сканирование внутренней сети.
ALLOWED_PORTS: Final[frozenset[int]] = frozenset({80, 443, 8080, 8443})

# Служба метаданных облачных провайдеров. Формально это link-local адрес и он
# уже покрыт проверкой ниже, но вынесен отдельно: именно с него утекают ключи,
# и в логе полезно видеть точную причину отказа.
CLOUD_METADATA_IPS: Final[frozenset[str]] = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
)

# Максимальное число переходов. Три хватает любому нормальному сайту; больше —
# признак либо петли, либо попытки увести проверку в сторону.
MAX_REDIRECTS: Final[int] = 3


class UnsafeURLError(ValueError):
    """Адрес запрещён к загрузке: ведёт внутрь инфраструктуры или не по HTTP."""


def _ip_is_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """
    Вернуть причину запрета для адреса или None, если он публичный.

    Причина возвращается строкой, а не булевым значением, чтобы в журнале было
    видно, ЧТО именно сработало: «loopback» и «внутренняя сеть» расследуются
    по-разному.
    """
    if str(ip) in CLOUD_METADATA_IPS:
        return "служба метаданных облака (оттуда утекают ключи доступа)"
    if ip.is_loopback:
        return "loopback — это сам сервер"
    if ip.is_private:
        return "адрес внутренней сети"
    if ip.is_link_local:
        return "link-local адрес"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "служебный адрес"
    return None


def assert_url_is_safe(url: str) -> None:
    """
    Проверить, что по адресу можно безопасно сходить.

    :raises UnsafeURLError: схема, порт или любой из IP-адресов запрещены.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError(
            f"Схема {parsed.scheme!r} запрещена — разрешены только http и https"
        )

    host = parsed.hostname
    if not host:
        raise UnsafeURLError("В адресе не удалось разобрать имя хоста")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError(
            f"Порт {port} запрещён — разрешены только {sorted(ALLOWED_PORTS)}"
        )

    # Резолвим ВСЕ адреса имени. Проверять только первый нельзя: хост может
    # отдавать вперемешку публичный и внутренний адрес, и какой из них выберет
    # библиотека при самом запросе — не наше дело.
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"Имя {host!r} не разрешается в адрес: {exc}") from exc

    # str() обязателен: в sockaddr первый элемент типизирован как str | int
    # (для некоторых семейств сокетов там число), и без приведения mypy справедливо
    # ругается на дальнейшую работу с адресом как со строкой.
    addresses = {str(info[4][0]) for info in infos}
    if not addresses:
        raise UnsafeURLError(f"Имя {host!r} не дало ни одного адреса")

    for raw in addresses:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            raise UnsafeURLError(f"Непонятный адрес {raw!r}") from None

        reason = _ip_is_forbidden(ip)
        if reason:
            log.warning("Запрещённый адрес: %s → %s (%s)", host, ip, reason)
            raise UnsafeURLError(
                f"Адрес ведёт внутрь инфраструктуры ({reason}) — загрузка запрещена"
            )

    log.info("Адрес проверен и безопасен: %s → %s", host, ", ".join(sorted(addresses)))
