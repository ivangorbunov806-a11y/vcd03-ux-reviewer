# Развёртывание на сервере (24/7)

Сервис работает по адресу **https://ux.автопилот24.рф** — Ubuntu 26.04, systemd + Caddy.
Docker не используется: для одного питоновского процесса systemd делает всё то же самое
(автозапуск, перезапуск, лимиты памяти, журнал), а на машине его нет.

## Схема

```
интернет
   ↓  :443, TLS от Let's Encrypt (Caddy получает и продлевает сам)
Caddy  — заголовки безопасности, лимит тела запроса, X-Forwarded-For
   ↓  127.0.0.1:8000
uvicorn (systemd, пользователь ux-reviewer без права входа)
   ↓
provod.ai
```

⭐ Сервис слушает **только петлю**. Прямого хода снаружи на порт 8000 нет: адрес
`сервер:8000` работал бы в обход TLS и всех заголовков, поэтому такой возможности
просто не существует. Наружу пускает только Caddy.

## Установка с нуля

```bash
# 1. Пользователь без права входа и код
useradd --system --create-home --home-dir /opt/ux-reviewer --shell /usr/sbin/nologin ux-reviewer
git clone https://github.com/ivangorbunov806-a11y/vcd03-ux-reviewer.git /opt/ux-reviewer/src
python3 -m venv /opt/ux-reviewer/venv
/opt/ux-reviewer/venv/bin/pip install -r /opt/ux-reviewer/src/requirements.txt

# 2. Папка журнала — её нет в репозитории (logs/ в .gitignore)
install -d -o ux-reviewer -g ux-reviewer /opt/ux-reviewer/src/logs

# 3. Настройки. ⚠️ Строго UTF-8 и переводы строк LF
cp /opt/ux-reviewer/src/.env.example /opt/ux-reviewer/.env
# заполнить API_KEY; задать DAILY_LIMIT (потолок расходов) и TRUST_PROXY=true;
# APP_TOKEN — ключ владельца, он обходит суточный потолок
chmod 600 /opt/ux-reviewer/.env && chown ux-reviewer:ux-reviewer /opt/ux-reviewer/.env

# 4. Сервис
cp /opt/ux-reviewer/src/deploy/ux-reviewer.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now ux-reviewer

# 5. Веб-сервер и TLS
cp /opt/ux-reviewer/src/deploy/Caddyfile /etc/caddy/Caddyfile
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy
systemctl reload caddy
```

Обновление после правок в репозитории:

```bash
git -C /opt/ux-reviewer/src pull && systemctl restart ux-reviewer
```

## Проверка после развёртывания

Проверять надо **результатом, а не тем, что файл записан**. Каждая строка ниже —
проверка, которая должна дать именно этот ответ:

| Команда | Ожидаемый ответ |
|---|---|
| `systemctl is-active ux-reviewer caddy` | `active` дважды |
| `ss -tlnp \| grep 8000` | слушает **127.0.0.1**, не `0.0.0.0` |
| `curl https://ux.автопилот24.рф/health` | `{"status":"ok"}` |
| POST `/review` без токена | **200** — сервис открыт всем |
| `curl https://ux.автопилот24.рф/limits` | остаток бесплатных разборов на сегодня |
| POST `/review` с адресом `http://169.254.169.254/` | **400**, отказ по SSRF |
| `curl -I` на любой адрес | заголовки HSTS, nosniff, DENY, no-referrer |
| `systemctl is-enabled ux-reviewer caddy` | `enabled` дважды — переживёт перезагрузку |

## Расходы и охрана

Каждый разбор — два платных запроса к модели, поэтому открытый в интернет сервис
без охраны означает, что бюджет тратит кто угодно. Это не теория: **в течение
пятнадцати минут после появления домена** в журнале Caddy уже были обращения с пяти
разных адресов (`rust_sniffer`, `ForestEngine` и другие сканеры). Новые домены
находят через публичные журналы выданных сертификатов за минуты.

Отсюда обязательный минимум, который уже настроен: ⭐ **общий суточный потолок на
весь сервис** (`DAILY_LIMIT`, счётчик в файле — иначе он обходился бы перезапуском),
лимит 20 разборов в час с адреса, ключ владельца в обход потолка, закрытый CORS,
`ProtectSystem=strict` и потолок памяти 600 МБ в юните.

⚠️ Лимит на адрес общим потолком НЕ является: у ботов адресов много, и сто адресов
дали бы сто лимитов. Именно поэтому расходы ограничивает отдельный счётчик на сервис.

## Грабли этого развёртывания

1. **`.env` уехал в кодировке Windows** — сервис падал с `UnicodeDecodeError` на первом
   русском комментарии. При передаче файла с Windows кодировку задавать явно (UTF-8, LF).
2. **`StartLimitIntervalSec` и `StartLimitBurst` работают только в секции `[Unit]`.**
   В `[Service]` systemd пишет `Unknown key ... ignoring` — настройка записана, а
   действия нет. Ровно тот случай, когда «настройка есть» ≠ «настройка работает».
3. **Папки `logs/` нет после клона** (она в `.gitignore`), а `ReadWritePaths` требует
   существующий путь — юнит падал с `status=226/NAMESPACE`.
4. **`debian-keyring` весит больше сотни мегабайт** и держал блокировку apt бесконечно.
   Ключ репозитория Caddy берётся напрямую через `curl`, пакет не нужен.
5. **После пяти неудачных стартов systemd блокирует запуск** (`Start request repeated
   too quickly`) — после починки причины нужен `systemctl reset-failed`, иначе кажется,
   что исправление не помогло.
