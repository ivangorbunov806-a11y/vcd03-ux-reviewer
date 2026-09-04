"""
Тесты защиты: SSRF, токен доступа, ограничение частоты.

Как и остальные тесты проекта, эти не ходят в сеть: все адреса заданы числовыми
IP, которые не требуют обращения к DNS, а веб-слой проверяется вызовом функций
напрямую с подставным запросом.

⭐ Проверяем то, что ДОЛЖНО быть запрещено. Тест «разрешённый адрес проходит»
без пары «запрещённый отвергается» ничего не доказывает: незаполненная проверка
тоже пропускает всё подряд.
"""

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from typing import Any

from fastapi import HTTPException

from app import security
from ux_reviewer.safety import UnsafeURLError, assert_url_is_safe


def fake_request(ip: str = "203.0.113.7", headers: dict[str, str] | None = None) -> Any:
    """Подставной запрос: security трогает только адрес клиента и заголовки."""
    return SimpleNamespace(
        client=SimpleNamespace(host=ip),
        headers=headers or {},
    )


class TestSSRFProtection(unittest.TestCase):
    """Адреса, ведущие внутрь инфраструктуры, обязаны отвергаться."""

    def test_loopback_is_blocked(self) -> None:
        with self.assertRaises(UnsafeURLError):
            assert_url_is_safe("http://127.0.0.1/")

    def test_cloud_metadata_is_blocked(self) -> None:
        # Самый ценный для нападающего адрес: оттуда забирают ключи от панели.
        with self.assertRaises(UnsafeURLError):
            assert_url_is_safe("http://169.254.169.254/latest/meta-data/")

    def test_private_network_is_blocked(self) -> None:
        for host in ("http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/"):
            with self.subTest(host=host), self.assertRaises(UnsafeURLError):
                assert_url_is_safe(host)

    def test_ipv6_loopback_is_blocked(self) -> None:
        with self.assertRaises(UnsafeURLError):
            assert_url_is_safe("http://[::1]/")

    def test_non_http_scheme_is_blocked(self) -> None:
        for url in ("file:///etc/passwd", "ftp://8.8.8.8/", "gopher://8.8.8.8/"):
            with self.subTest(url=url), self.assertRaises(UnsafeURLError):
                assert_url_is_safe(url)

    def test_unusual_port_is_blocked(self) -> None:
        # Обращение на 22 — это не загрузка страницы, а разведка сети.
        with self.assertRaises(UnsafeURLError):
            assert_url_is_safe("http://8.8.8.8:22/")

    def test_public_address_passes(self) -> None:
        # Контрольный положительный случай: проверка не должна запрещать всё.
        # ⚠️ Адрес именно публичный: диапазоны из документации (198.51.100.0/24,
        # 203.0.113.0/24) Python помечает is_private, и тест на них падал.
        assert_url_is_safe("http://8.8.8.8/")


class TestAccessToken(unittest.TestCase):
    """Токен: закрыто по умолчанию, открыто только верным ключом."""

    def setUp(self) -> None:
        self._saved = os.environ.get("APP_TOKEN")
        security._hits.clear()

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("APP_TOKEN", None)
        else:
            os.environ["APP_TOKEN"] = self._saved
        security._hits.clear()

    def test_missing_config_closes_the_door(self) -> None:
        # ⭐ Fail-closed: забытая настройка не должна открывать сервис всем.
        os.environ.pop("APP_TOKEN", None)
        with self.assertRaises(HTTPException) as ctx:
            security.require_token(fake_request(), None)
        self.assertEqual(ctx.exception.status_code, 503)

    def test_wrong_token_rejected(self) -> None:
        os.environ["APP_TOKEN"] = "правильный-ключ"
        with self.assertRaises(HTTPException) as ctx:
            security.require_token(fake_request(), "неправильный")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_absent_token_rejected(self) -> None:
        os.environ["APP_TOKEN"] = "правильный-ключ"
        with self.assertRaises(HTTPException) as ctx:
            security.require_token(fake_request(), None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_correct_token_passes(self) -> None:
        os.environ["APP_TOKEN"] = "правильный-ключ"
        security.require_token(fake_request(), "правильный-ключ")  # не должно бросить


class TestRateLimit(unittest.TestCase):
    """Даже свой токен не должен сжигать бюджет без ограничений."""

    def setUp(self) -> None:
        security._hits.clear()
        os.environ["RATE_LIMIT_PER_HOUR"] = "3"

    def tearDown(self) -> None:
        security._hits.clear()
        os.environ.pop("RATE_LIMIT_PER_HOUR", None)
        os.environ.pop("TRUST_PROXY", None)

    def test_limit_triggers_after_threshold(self) -> None:
        req = fake_request("198.51.100.9")
        for _ in range(3):
            security.check_rate_limit(req)
        with self.assertRaises(HTTPException) as ctx:
            security.check_rate_limit(req)
        self.assertEqual(ctx.exception.status_code, 429)

    def test_limit_is_per_address(self) -> None:
        first, second = fake_request("198.51.100.1"), fake_request("198.51.100.2")
        for _ in range(3):
            security.check_rate_limit(first)
        security.check_rate_limit(second)  # соседа чужой перебор не касается

    def test_forwarded_header_ignored_without_trust(self) -> None:
        # ⚠️ Иначе любой подставит чужой X-Forwarded-For и обнулит себе счётчик.
        req = fake_request("198.51.100.5", {"X-Forwarded-For": "1.1.1.1"})
        self.assertEqual(security.client_ip(req), "198.51.100.5")

    def test_forwarded_header_used_when_trusted(self) -> None:
        os.environ["TRUST_PROXY"] = "true"
        req = fake_request("127.0.0.1", {"X-Forwarded-For": "1.1.1.1, 10.0.0.1"})
        self.assertEqual(security.client_ip(req), "1.1.1.1")


class TestCorsDefaults(unittest.TestCase):
    """По умолчанию сервис не доступен из браузеров."""

    def tearDown(self) -> None:
        os.environ.pop("ALLOWED_ORIGINS", None)

    def test_empty_by_default(self) -> None:
        os.environ.pop("ALLOWED_ORIGINS", None)
        self.assertEqual(security.allowed_origins(), [])

    def test_parses_list(self) -> None:
        os.environ["ALLOWED_ORIGINS"] = "https://a.ru, https://b.ru"
        self.assertEqual(security.allowed_origins(), ["https://a.ru", "https://b.ru"])


if __name__ == "__main__":
    unittest.main()
