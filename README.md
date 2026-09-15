🛡️ Telegram Proxy Collector: Anti-Censorship Edition
https://api.oosmetrics.com/api/v1/badge/achievement/21322b63-7982-4e81-99f7-ada7354f9c21.svg

Smart harvester for collecting, analyzing, and filtering MTProto and SOCKS5 proxies.
Unlike ordinary parsers, this script deeply analyzes the Secret of each MTProto proxy, extracts the domain mask (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon, Microsoft, etc.), and tests resistance to active DPI (Probe Resistance).
This is especially important under strict censorship, where disguising traffic as legitimate HTTPS or using SOCKS5 can be the difference between working and completely inaccessible.

👉 GitHub — Telegram Proxy Collector

📌 What's New in Version 3.1
✅ Ping filtering — proxies with latency >3 seconds are automatically discarded (--max-ping parameter).

🔐 URL-safe Base64 support — secrets containing - and _ characters are correctly decoded.

🇷🇺 For RU proxies, the probe_resistant flag is now mandatory — this guarantees that the proxy is disguised as legitimate HTTPS and resistant to DPI probing.

⏱️ Increased timeout to 14 seconds (default in GitHub Actions) — gives slow but alive proxies a chance to respond.

⚙️ Reduced concurrency to 20 workers — prevents FloodWait from Telegram.

📡 Added collection from Telegram channels (e.g., @ProxyMTProto) via the --channel parameter.

🧹 Improved parsing — proxies are now extracted from a wider range of formats (YAML, JSON, special lists).

📊 Stricter sorting — first probe_resistant, then regular MTProto, then SOCKS5; within each group sorted by ascending ping.

🛠️ Community Tools: User-Contributed Utilities
Tool	Description	Author
Parser-telegram-proxies	Convenient Windows utility for parsing and checking MTProto proxies with real-time ping display. The updated version fixes periodic blocking of requests to TXT files on GitHub by using HTTP requests instead of direct reading.	ComradeBingo
Proxy-Telegram-Android	Android app that parses proxy lists, checks their availability, and shows server ping.	ComradeBingo
Proxy-telegram-windows	Proxy server parser for Telegram on Windows. Updated to version 1.2: redesigned GUI, added "Help" menu, improved stability and usability.	ComradeBingo
🔥 Current Lists (updated automatically every hour)
The script runs hourly via GitHub Actions, collects fresh proxies from open sources, filters, checks, and updates the lists.
GitHub Actions saves results to the verified/ folder and then copies them to the repository root — so the links below always point to fresh lists.

📦 Direct links for pasting into Telegram or your own programs:

Region / Type	List	Note
🇷🇺 RU segment (MTProto)	proxy_ru.txt	Disguised as Yandex, VK, Mail.ru, Gosuslugi, Sber, Mos.ru, etc. Aimed at better stability in Russia and Iran.
🇪🇺 EU / Global (MTProto)	proxy_eu.txt	Disguised as Google, Amazon, Microsoft, Cloudflare, and other international services. High speed and stability, especially outside Russia.
🌍 All MTProto proxies	proxy_all.txt	Full mix of all verified MTProto servers (RU + EU).
🔒 SOCKS5 proxies	socks5.txt	SOCKS5 protocol proxies (no masking, but often harder to block).
📱 Using on Mobile
If you opened the repository on your phone and don't want to copy proxies manually:

Open the page:
https://kort0881.github.io/telegram-proxy-collector/
(the same index.html file is in the repository root)

The page has three tabs:

MTProto RU – proxies disguised as Russian websites,

MTProto EU – international disguises,

SOCKS5 – proxies without masking, but often working where MTProto is blocked.

Tap any button – Telegram will offer to connect automatically.

A special mobile version is also available:
👉 mobile.html — optimized for small screens with a simplified interface.

🚀 How It Works
The script runs every hour via GitHub Actions and goes through five main stages:

1. Harvesting
Downloads "raw" proxies from two categories of sources:

MTProto (main repositories, APIs, TXT files)

SOCKS5 (specialized lists)

Uses aggressive Regex parsing to extract links from any format:

tg://proxy?server=...&port=...&secret=...

tg://socks?server=...&port=...

t.me/proxy?...

host:port:secret

socks5://[user:pass@]host:port

JSON objects.

2. Decoding (Deep Analysis)
Decrypts Fake-TLS secrets of MTProto (starting with ee...).

Extracts the domain that the traffic is disguised as (e.g., yandex.ru, vk.com, google.com, etc.).

Based on the domain, marks the MTProto proxy as ru or eu (by a set of keywords in the URL).

3. Filtering (Smart Filter)
❌ Blacklist: proxies disguised as known blocked resources (Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor, etc.) are discarded.

✅ RU marker: proxies containing yandex, vk.com, mail.ru, ok.ru, sber, tinkoff, gosuslugi, ozon, wildberries, avito, kinopoisk, etc. in the domain are marked as ru.

✅ EU marker: all other MTProto proxies are considered eu.

4. Checking — including Probe Resistance
Checks each proxy via TCP socket (fast mode) or via Telethon (full check with connection to Telegram API if API_ID and API_HASH are provided).

For MTProto proxies with a domain (ee... secret), a Probe Resistance Test is run — the script sends a regular HTTPS request GET / with the header Host: <domain> through the proxy. If the proxy responds with a real HTML page, it is considered resistant to active DPI probing and gets the flag probe_resistant: true.

SOCKS5 proxies are only checked for the ability to connect to the Telegram API (no masking).

The result is saved to verified/proxy_all_verified.json with the fields probe_resistant and type.

5. Building Final Lists
All proxies are sorted by priority:

MTProto with probe_resistant: true (most resilient)
Regular MTProto
SOCKS5
Within each group — by ascending ping.

MTProto proxies are split into RU and EU.

SOCKS5 proxies are placed in a separate file socks5.txt.

The following files are generated:

proxy_ru.txt, proxy_eu.txt, proxy_all.txt (MTProto links)

socks5.txt (SOCKS5 links)

verified/ – detailed copies with comments and JSON.

📁 Output Files
After each run, you get:

Repository root (convenient for direct links):

proxy_ru.txt, proxy_eu.txt, proxy_all.txt — MTProto tg://proxy?...

socks5.txt — SOCKS5 tg://socks?...

verified/ folder (detailed versions):

proxy_ru_verified.txt, proxy_eu_verified.txt, proxy_all_verified.txt — with headers and statistics.

socks5_proxies.txt — SOCKS5 with comments.

proxy_all_verified.json — full JSON with fields: type, host, port, ping, region, domain, method, probe_resistant.

proxy_stats_verified.json — run statistics (raw/working count, execution time, best ping).

🔗 My Projects
Project	Description	Link
VPN KEY VLESS	Main channel with configs, instructions, and news about VLESS configs and proxy networks.	Telegram
KiberSos New	Backup channel for communication, updates, and support.	Telegram
VlessBots	Bot for automatic issuance of keys and proxy links on demand.	Bot
Internet Access	Project website with detailed documentation, FAQ, and usage examples.	Website
VPN Key Repo	Repository of scripts, configurations, and utilities for working with VLESS services and proxy networks.	GitHub
🛠️ Local Run (for Developers)
If you want to run the collector on your own PC rather than only on GitHub Actions:

bash
# 1. Clone the repository
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run basic check (TCP ping only)
python main.py

# 4. Run full check (with Telethon, Probe Resistance, and SOCKS5)
python main.py --api-id YOUR_API_ID --api-hash YOUR_API_HASH --top 200 --timeout 14 --workers 20 --channel @ProxyMTProto --channel-limit 150 --max-ping 3.0 --output-dir verified

# 5. Help on arguments
python main.py --help
For a full check (Telethon), API_ID and API_HASH are required. You can get them at my.telegram.org.

⚠️ Disclaimer and Security

This repository does not guarantee anonymity, impossibility of surveillance, or protection from compromise.
All proxy servers are provided "as is", and their quality depends on external sources.

📊 AI Analytics (automatic)
<!-- AI_ANALYTICS_START -->
Report generated 2026-09-15 10:13 UTC

Proxy Status Report (2026-09-15 09:00 UTC)
Total proxies: 200, all with good ping (< 1.5 s).

Regions: EU — 198, RU — 2.

Types: SOCKS5 — 166, MTProto — 34.

Recommendation:

For most tasks, EU proxies are preferable, as they make up almost the entire base and have stable ping.

Among types, SOCKS5 (the majority of the list) is better for general use; **

<!-- AI_ANALYTICS_END -->
🛡️ Telegram Proxy Collector: Anti-Censorship Edition (Русская версия)
https://api.oosmetrics.com/api/v1/badge/achievement/21322b63-7982-4e81-99f7-ada7354f9c21.svg

Умный комбайн для сбора, анализа и отбора MTProto и SOCKS5 прокси.
В отличие от обычных парсеров, этот скрипт глубоко анализирует Secret каждого MTProto-прокси, извлекает домен-маску (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon, Microsoft и др.) и проверяет устойчивость к активному DPI (Probe Resistance).
Это особенно важно в условиях жёстких блокировок, где маскировка под легитимный HTTPS или использование SOCKS5 может быть разницей между работой и полной недоступностью.

👉 GitHub — Telegram Proxy Collector

📌 Что нового в версии 3.1
✅ Фильтрация по пингу — прокси с откликом >3 секунд автоматически отсеиваются (параметр --max-ping).

🔐 Поддержка URL-safe Base64 — корректно декодируются секреты с символами - и _.

🇷🇺 Для RU-прокси теперь обязательно наличие флага probe_resistant — это гарантирует, что прокси маскируется под легитимный HTTPS и устойчив к DPI-зондированию.

⏱️ Увеличен таймаут до 14 секунд (по умолчанию в GitHub Actions) — даёт шанс медленным, но живым прокси ответить.

⚙️ Снижена параллельность до 20 воркеров — предотвращает FloodWait от Telegram.

📡 Добавлен сбор из Telegram-каналов (например, @ProxyMTProto) через параметр --channel.

🧹 Улучшен парсинг — теперь извлекаются прокси из большего числа форматов (YAML, JSON, специальные списки).

📊 Более строгая сортировка — сначала probe_resistant, затем обычные MTProto, затем SOCKS5, внутри каждой группы по возрастанию пинга.

🛠️ Community Tools: утилиты от пользователей
Инструмент	Описание	Автор
Parser-telegram-proxies	Удобная Windows-утилита для парсинга и проверки MTProto-прокси с отображением пинга в реальном времени. Обновлённая версия исправляет периодические блокировки запросов к TXT-файлам на GitHub за счёт использования HTTP-запросов вместо прямого чтения.	ComradeBingo
Proxy-Telegram-Android	Приложение для Android, которое парсит прокси-списки, проверяет их доступность и показывает пинг серверов.	ComradeBingo
Proxy-telegram-windows	Парсер прокси-серверов для Telegram на Windows. Обновлён до версии 1.2: переработан GUI, добавлено меню «Справка», улучшена стабильность и удобство использования.	ComradeBingo
🔥 Актуальные списки (обновляются автоматически каждый час)
Скрипт ежечасно запускается через GitHub Actions, собирает свежие прокси из открытых источников, фильтрует, проверяет и обновляет списки.
GitHub Actions сохраняет результаты в папку verified/, а затем копирует их в корень репозитория — поэтому ссылки ниже всегда ведут на свежие списки.

📦 Прямые ссылки для вставки в Telegram или свои программы:

Регион / Тип	Список	Примечание
🇷🇺 RU-сегмент (MTProto)	proxy_ru.txt	Маскировка под Yandex, VK, Mail.ru, Gosuslugi, Sber, Mos.ru и др. Нацелен на лучшую стабильность в РФ и Иране.
🇪🇺 EU / Global (MTProto)	proxy_eu.txt	Маскировка под Google, Amazon, Microsoft, Cloudflare и другие международные сервисы. Высокая скорость и стабильность, особенно вне РФ.
🌍 Все MTProto прокси	proxy_all.txt	Полный микс всех проверенных MTProto-серверов (RU + EU).
🔒 SOCKS5 прокси	socks5.txt	Прокси протокола SOCKS5 (без маскировки, но часто сложнее блокируются).
📱 Использование с телефона
Если ты открыл репозиторий с телефона и не хочешь копировать прокси вручную:

Открой страницу:
https://kort0881.github.io/telegram-proxy-collector/
(этот же файл index.html находится в корне репозитория)

На странице есть три вкладки:

MTProto RU – прокси с маскировкой под российские сайты,

MTProto EU – международная маскировка,

SOCKS5 – прокси без маскировки, но часто работающие там, где MTProto блокируется.

Нажми на любую кнопку – Telegram сам предложит подключиться.

Также доступна специальная мобильная версия:
👉 mobile.html — она оптимизирована для небольших экранов и имеет упрощённый интерфейс.

🚀 Как это работает?
Скрипт запускается каждый час через GitHub Actions и последовательно проходит пять главных этапов:

1. Сбор (Harvesting)
Скачивает «сырые» прокси из двух категорий источников:

MTProto (основные репозитории, API, TXT-файлы)

SOCKS5 (специализированные списки)

Использует агрессивный Regex-парсинг для извлечения ссылок из любого формата:

tg://proxy?server=...&port=...&secret=...

tg://socks?server=...&port=...

t.me/proxy?...

host:port:secret

socks5://[user:pass@]host:port

JSON-объекты.

2. Декодирование (Deep Analysis)
Расшифровывает Fake-TLS-секреты MTProto (начинаются на ee...).

Извлекает домен, под который идёт маскировка трафика (например yandex.ru, vk.com, google.com и т.д.).

На основе домена помечает MTProto прокси как ru или eu (по набору ключевых слов в URL).

3. Фильтрация (Smart Filter)
❌ Blacklist: прокси, маскирующиеся под заведомо заблокированные ресурсы (Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor и др.), отбрасываются.

✅ RU-маркер: прокси, содержащие в домене yandex, vk.com, mail.ru, ok.ru, sber, tinkoff, gosuslugi, ozon, wildberries, avito, kinopoisk и др., помечаются как ru.

✅ EU-маркер: остальные MTProto прокси считаются eu.

4. Проверка (Checking) — включая Probe Resistance
Проверяет каждый прокси через TCP-сокет (быстрый режим) или через Telethon (полная проверка с подключением к Telegram API, если переданы API_ID и API_HASH).

Для MTProto прокси с доменом (секрет ee...) запускается Probe Resistance Test – скрипт отправляет обычный HTTPS-запрос GET / с заголовком Host: <домен> через прокси. Если прокси отвечает настоящей HTML-страницей, он считается устойчивым к активному зондированию DPI и получает флаг probe_resistant: true.

SOCKS5 прокси проверяются только на возможность подключения к Telegram API (без маскировки).

Результат сохраняется в verified/proxy_all_verified.json с полями probe_resistant и type.

5. Сборка итоговых списков
Все прокси сортируются по приоритету:

MTProto с probe_resistant: true (самые живучие)
Обычные MTProto
SOCKS5
Внутри каждой группы – по возрастанию пинга.

MTProto прокси разделяются на RU и EU.

SOCKS5 прокси выносятся в отдельный файл socks5.txt.

Формируются файлы:

proxy_ru.txt, proxy_eu.txt, proxy_all.txt (MTProto ссылки)

socks5.txt (SOCKS5 ссылки)

verified/ – подробные копии с комментариями и JSON.

📁 Итоговые файлы
После каждого запуска вы получите:

Корень репозитория (удобно для прямых ссылок):

proxy_ru.txt, proxy_eu.txt, proxy_all.txt — MTProto tg://proxy?...

socks5.txt — SOCKS5 tg://socks?...

Папка verified/ (подробные версии):

proxy_ru_verified.txt, proxy_eu_verified.txt, proxy_all_verified.txt — с заголовками и статистикой.

socks5_proxies.txt — SOCKS5 с комментариями.

proxy_all_verified.json — полный JSON с полями: type, host, port, ping, region, domain, method, probe_resistant.

proxy_stats_verified.json — статистика по запуску (количество сырых/рабочих, время выполнения, лучший ping).

🔗 Мои проекты
Проект	Описание	Ссылка
VPN KEY VLESS	Основной канал с конфигами, инструкциями и новостями по VLESS-конфигам и прокси-сети.	Telegram
KiberSos New	Резервный канал для связи, обновлений и техподдержки.	Telegram
VlessBots	Бот для автоматической выдачи ключей и прокси-ссылок по запросу.	Bot
Internet Access	Сайт проекта с подробной документацией, FAQ и примерами использования.	Website
VPN Key Repo	Репозиторий скриптов, конфигураций и утилит для работы с VLESS-сервисами и прокси-сетями.	GitHub
🛠️ Локальный запуск (для разработчиков)
Если хочешь запустить сборщик на своём ПК, а не только на GitHub Actions:

bash
# 1. Клонировать репозиторий
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить базовую проверку (только TCP-пинг)
python main.py

# 4. Запустить полную проверку (с Telethon, Probe Resistance и SOCKS5)
python main.py --api-id YOUR_API_ID --api-hash YOUR_API_HASH --top 200 --timeout 14 --workers 20 --channel @ProxyMTProto --channel-limit 150 --max-ping 3.0 --output-dir verified

# 5. Помощь по аргументам
python main.py --help
Для полной проверки (Telethon) необходимы API_ID и API_HASH. Их можно получить на my.telegram.org.

⚠️ Дисклеймер и безопасность

Этот репозиторий не гарантирует анонимность, невозможность слежки или защищённость от компрометации.
Все прокси-серверы предоставляются на условиях «как есть», и их качество зависит от внешних источников.

📊 AI-аналитика (автоматическая)
<!-- AI_ANALYTICS_START -->
Отчёт сгенерирован 2026-09-15 10:13 UTC

Отчёт о состоянии прокси (2026-09-15 09:00 UTC)
Всего прокси: 200, все с хорошим пингом (< 1.5 с).

Регионы: EU — 198, RU — 2.

Типы: SOCKS5 — 166, MTProto — 34.

Рекомендация:

Для большинства задач предпочтительнее использовать EU-прокси, так как они составляют почти всю базу и обладают стабильным пингом.

Среди типов лучше выбирать SOCKS5 (большая часть списка) для общего использования; **

<!-- AI_ANALYTICS_END -->
