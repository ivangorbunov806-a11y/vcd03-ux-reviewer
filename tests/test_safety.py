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
import tempfile
import unittest
from pathlib import Path
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


class TestAccessControl(unittest.TestCase):
    """
    Демо-режим: пускаем всех, но под общим потолком.

    ⭐ Проверяем именно то, ради чего потолок существует: что он ОБЩИЙ и что
    владелец не оказывается заперт вместе с гостями.
    """

    def setUp(self) -> None:
        self._saved_token = os.environ.get("APP_TOKEN")
        self._saved_state = security.STATE_FILE
        # Счётчик суток подменяем на временный файл: тесты не должны трогать
        # рабочий, иначе прогон тестов съедал бы боевой лимит.
        self._tmp = tempfile.TemporaryDirectory()
        security.STATE_FILE = Path(self._tmp.name) / "usage.json"
        security._hits.clear()
        os.environ["DAILY_LIMIT"] = "2"
        os.environ["RATE_LIMIT_PER_HOUR"] = "50"

    def tearDown(self) -> None:
        security.STATE_FILE = self._saved_state
        self._tmp.cleanup()
        security._hits.clear()
        for key in ("DAILY_LIMIT", "RATE_LIMIT_PER_HOUR"):
            os.environ.pop(key, None)
        if self._saved_token is None:
            os.environ.pop("APP_TOKEN", None)
        else:
            os.environ["APP_TOKEN"] = self._saved_token

    def test_guest_without_token_is_allowed(self) -> None:
        # Сервис демонстрационный: посторонний обязан пройти, пока есть бюджет.
        os.environ["APP_TOKEN"] = "ключ-владельца"
        security.access_control(fake_request(), None)

    def test_daily_budget_is_shared_by_everyone(self) -> None:
        # ⭐ Главная проверка: потолок общий, а не на каждый адрес отдельно.
        # Иначе сто адресов дали бы сто лимитов и расход стал бы неограничен.
        os.environ["APP_TOKEN"] = "ключ-владельца"
        security.access_control(fake_request("8.8.8.8"), None)
        security.access_control(fake_request("9.9.9.9"), None)
        with self.assertRaises(HTTPException) as ctx:
            security.access_control(fake_request("1.1.1.1"), None)
        self.assertEqual(ctx.exception.status_code, 429)

    def test_owner_passes_exhausted_budget(self) -> None:
        # Владелец не должен оказаться заперт в день, когда демо разобрали.
        os.environ["APP_TOKEN"] = "ключ-владельца"
        security.access_control(fake_request("8.8.8.8"), None)
        security.access_control(fake_request("9.9.9.9"), None)
        security.access_control(fake_request("1.1.1.1"), "ключ-владельца")

    def test_owner_does_not_spend_guest_budget(self) -> None:
        os.environ["APP_TOKEN"] = "ключ-владельца"
        security.access_control(fake_request(), "ключ-владельца")
        used, _ = security.daily_usage()
        self.assertEqual(used, 0)

    def test_wrong_token_falls_back_to_guest(self) -> None:
        # Неверный токен больше не отказ, а понижение до гостя — но бюджет он
        # тратит, иначе перебором токенов можно было бы обойти потолок.
        os.environ["APP_TOKEN"] = "ключ-владельца"
        security.access_control(fake_request(), "неправильный")
        used, _ = security.daily_usage()
        self.assertEqual(used, 1)

    def test_counter_survives_restart(self) -> None:
        # ⭐ Счётчик в файле, а не в памяти: у сервиса Restart=always, и потолок
        # в памяти обходился бы обычным падением процесса.
        os.environ["APP_TOKEN"] = "ключ-владельца"
        security.access_control(fake_request(), None)
        used_before, _ = security.daily_usage()
        security._hits.clear()  # имитируем перезапуск: память очищена, файл цел
        used_after, _ = security.daily_usage()
        self.assertEqual(used_before, used_after)
        self.assertEqual(used_after, 1)

    def test_broken_state_file_does_not_crash(self) -> None:
        security.STATE_FILE.write_text("{это не json", encoding="utf-8")
        used, limit = security.daily_usage()
        self.assertEqual(used, 0)
        self.assertEqual(limit, 2)


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
