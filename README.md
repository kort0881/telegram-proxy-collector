# 🛡️ Telegram Proxy Collector: Anti-Censorship Edition

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![Status](https://img.shields.io/badge/Auto_Update-Every_4_Hours-success?style=for-the-badge&logo=github-actions)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

**Умный комбайн для сбора MTProto прокси.**  
В отличие от обычных парсеров, этот скрипт анализирует секрет (Secret) каждого прокси и определяет, под какой сайт он маскируется. Это критически важно для работы в условиях жестких блокировок (DPI). [web:21][web:31]

---

## 🔥 Актуальные списки (обновляются автоматически)

Скрипт каждые 4 часа запускается через GitHub Actions, собирает свежие MTProto‑прокси, фильтрует и проверяет их, а затем обновляет файлы в этом репозитории. [web:21][web:11]

Прямые ссылки для вставки в Telegram или свои программы:

| 🇷🇺 **RU Сегмент** (Top Tier) | 🇪🇺 **EU / Global** | 🌍 **Все прокси** |
| :--- | :--- | :--- |
| **[proxy_ru.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt)** | **[proxy_eu.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt)** | **[proxy_all.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt)** |
| *Маскировка под Yandex, VK, Mail.ru, Gosuslugi и др.* | *Маскировка под Google, Amazon, Microsoft и др.* | *Полный микс всех проверенных серверов* |
| ✅ **Лучшие для РФ и Ирана** | ✅ **Высокая скорость и стабильность** | ✅ **Максимальное количество прокси** |

> ⚙️ GitHub Actions сохраняет результаты в `verified/`, а затем копирует их в `proxy_ru.txt`, `proxy_eu.txt` и `proxy_all.txt` в корне репозитория, так что ссылки выше всегда ведут на свежие списки. [web:21][web:11]

---

## 📱 Использование с телефона 

Если вы открыли этот репозиторий с телефона и хотите быстро подключить MTProto‑прокси без копипасты:

**Откройте страницу:**

https://kort0881.github.io/telegram-proxy-collector/mobile.html

Там вы увидите кнопки:

> «Подключить прокси #1», «Подключить прокси #2», ...

При нажатии:

1. Браузер откроет ссылку вида `https://t.me/proxy?server=...&port=...&secret=...`. [web:87]
2. Telegram спросит: «Подключиться к прокси?» — подтвердите, и прокси будет включён. [web:87][web:91]

Страница `mobile.html` автоматически читает файл  
`verified/proxy_links_tme_clean.txt`, который генерирует этот репозиторий,  
и превращает каждую строку в отдельную кнопку. [web:21]

---

## 🚀 Как это работает?

Скрипт запускается каждые 4 часа через GitHub Actions и выполняет 4 этапа: [web:21][web:11]

1. **Сбор (Harvesting)**
   - Скачивает «сырые» прокси из нескольких открытых источников (GitHub‑репозитории, TXT, JSON‑API). [web:21][web:31]
   - Использует агрессивный Regex‑парсинг, чтобы вытащить MTProto‑ссылки из любого мусора (tg://proxy, t.me/proxy, host:port:secret, JSON). [web:21]

2. **Декодирование (Deep Analysis)**
   - Расшифровывает `Fake‑TLS` секреты (начинаются на `ee...`). [web:21][web:33]
   - Извлекает домен, под который маскируется трафик (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon и т.д.). [web:21][web:33]

3. **Фильтрация (Smart Filter)**
   - ⛔ **Blacklist:** отбрасывает прокси, маскирующиеся под заведомо заблокированные ресурсы (Instagram, Facebook, Twitter, BBC, Meduza и т.п.), чтобы не тратить трафик впустую в РФ. [web:21]
   - ✅ **RU‑маркер:** помечает прокси как `ru`, если домен секрета содержит `yandex`, `vk.com`, `mail.ru`, `sber`, `gosuslugi`, `ozon`, `wildberries` и другие популярные RU‑сервисы. [web:21]

4. **Проверка (Checking)**
   - Пингует каждый прокси через TCP (или Telethon MTProto, если указаны `API_ID` / `API_HASH`). [web:21]
   - Измеряет реальный отклик (ping) и доступность порта (по умолчанию `timeout = 2s`). [web:21]
   - Для каждой пары `(host, port)` оставляет только самый быстрый вариант. [web:21]

Результат сохраняется в нескольких форматах:

- `proxy_ru.txt`, `proxy_eu.txt`, `proxy_all.txt` — готовые списки `tg://proxy?...` для быстрого импорта в Telegram. [web:21]
- `verified/proxy_*_verified.txt` — те же списки, разложенные по регионам (RU / EU / All). [web:21]
- `verified/proxy_all_tme_verified.txt` — ссылки в формате `https://t.me/proxy?server=...` (удобно кидать людям). [web:21]
- `verified/proxy_all_verified.json` — подробный JSON с полями `host`, `port`, `secret`, `ping`, `region`, `domain`, `method` (TCP_OK / Telethon_OK). [web:21]
- `verified/proxy_stats_verified.json` — статистика по запуску (кол‑во сырья, верифицированных прокси, лучший пинг и т.п.). [web:21]

---

## 🔗 Мои проекты

| Проект | Описание | Ссылка |
| :--- | :--- | :--- |
| **VPN KEY VLESS** | Основной канал с конфигами и новостями | [Telegram](https://t.me/vlesstrojan) |
| **KiberSos New** | Резервный канал связи | [Telegram](https://t.me/kibersosnew) |
| **VlessBots** | Бот для выдачи ключей | [Bot](https://t.me/vlessbots_bot) |
| **Internet Access** | Сайт проекта | [Website](https://kort0881.github.io/internet-access-site/) |
| **VPN Key Repo** | Репозиторий скриптов VLESS | [GitHub](https://github.com/kort0881/vpn-key-vless) | [web:21][web:117]

---

## 🛠️ Локальный запуск (для разработчиков)

Если хотите запустить сборщик на своём ПК: [web:21]

```bash
# 1. Клонировать репозиторий
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install requests telethon

# 3. Запустить (TCP-проверка)
python main.py

# или с ограничением по топу и пользовательской папкой вывода:
python main.py --top 200 --output-dir verified
