🛡️ Telegram Proxy Collector: Anti‑Censorship Edition
https://github.com/kort0881/telegram-proxy-collector/actions/workflows/update_proxies.yml/badge.svg
https://github.com/kort0881/telegram-proxy-collector/actions/workflows/proxy_analytics.yml/badge.svg
https://img.shields.io/badge/dynamic/json?url=https%253A%252F%252Fraw.githubusercontent.com%252Fkort0881%252Ftelegram-proxy-collector%252Fmain%252Fverified%252Fproxy_stats_verified.json&query=%2524.by_region.ru&label=MTProto%2520RU&color=blue
https://img.shields.io/badge/dynamic/json?url=https%253A%252F%252Fraw.githubusercontent.com%252Fkort0881%252Ftelegram-proxy-collector%252Fmain%252Fverified%252Fproxy_stats_verified.json&query=%2524.by_region.eu&label=MTProto%2520EU&color=green
https://img.shields.io/badge/dynamic/json?url=https%253A%252F%252Fraw.githubusercontent.com%252Fkort0881%252Ftelegram-proxy-collector%252Fmain%252Fverified%252Fproxy_stats_verified.json&query=%2524.by_region.us&label=MTProto%2520US&color=orange
https://img.shields.io/badge/dynamic/json?url=https%253A%252F%252Fraw.githubusercontent.com%252Fkort0881%252Ftelegram-proxy-collector%252Fmain%252Fverified%252Fproxy_stats_verified.json&query=%2524.by_region.socks5&label=SOCKS5&color=purple

https://api.oosmetrics.com/api/v1/badge/achievement/21322b63-7982-4e81-99f7-ada7354f9c21.svg

Умный комбайн для сбора, анализа и отбора MTProto и SOCKS5 прокси.

В отличие от обычных парсеров, этот проект:

глубоко анализирует secret каждого MTProto-прокси,

извлекает домен-маску (Yandex, VK, Mail.ru, Gosuslugi, Google, Cloudflare и др.),

фильтрует по GeoIP (60+ доверенных стран),

отсеивает мусорные порты (SSH, MySQL, Tomcat, Minecraft),

ведёт TTL-кэш проверок (48ч),

и пишет AI-отчёт в README через Groq.

👉 GitHub — Telegram Proxy Collector

📌 Что нового в версии 3.8
🌍 GeoIP-фильтр — GeoLite2-Country.mmdb отсеивает прокси из недоверенных стран до TCP-проверки.

🚫 Фильтр мусорных портов — 45+ портов (22, 80, 3306, 5432, 8080, 25565 и др.) автоматически отбрасываются для MTProto.

🧠 TTL seen-кэш — не проверяет одни и те же прокси дважды (48ч), но и не забывает их навсегда.

⚡ --max-check — жёсткий лимит на количество прокси для проверки (по умолчанию 30 000).

🎭 Fake-TLS детектор — из secret извлекается SNI-домен, по нему определяется регион (RU/EU/US/ASIA).

🧪 AI-аналитика — Groq openai/gpt-oss-120b автоматически обновляет блок в README.

📊 ML-аналитика — analytics.py обучает RandomForest и IsolationForest, считает тренды.

🔐 Fallback GeoIP — maxminddb.open_database → geoip2.database.Reader.

⚙️ 200 воркеров — 30 000 прокси проверяются за ~40 секунд.

❓ FAQ
<details> <summary><b>Что такое MTProto-прокси и зачем он нужен?</b></summary>
MTProto — это собственный протокол Telegram. Прокси на его основе работают быстрее и стабильнее, чем SOCKS5, и позволяют маскировать трафик под обычный HTTPS.

</details><details> <summary><b>Что значит «Fake-TLS» и «золотые прокси»?</b></summary>
MTProto-прокси может маскироваться под HTTPS-сайт, отправляя фейковый SNI-домен (например, yandex.ru). DPI не может отличить такой трафик от настоящего HTTPS — это делает прокси устойчивым к блокировкам.

«Золотые» — это прокси, у которых в secret зашит известный доверенный домен: yandex.ru, vk.com, gosuslugi.ru, sber.ru. Они работают лучше всего в РФ и Иране.

</details><details> <summary><b>Почему EU-прокси так много, а RU — мало?</b></summary>
Потому что большинство открытых источников публикуют прокси из Европы. RU-прокси часто блокируются хостерами, и их сложнее найти. Мы фильтруем по GeoIP и оставляем только доверенные страны — поэтому итоговый список RU меньше, но он реально рабочий.

</details><details> <summary><b>Чем отличается `proxy_ru.txt` от `proxy_eu.txt`?</b></summary>
По SNI-домену в secret:

RU — домен из списка .ru, yandex, vk.com, mail.ru, gosuslugi, sber, mos.ru и др.

EU — всё остальное (Google, Amazon, Cloudflare, случайные домены).

Если SNI пустой — прокси попадает в EU.

</details><details> <summary><b>Что такое probe_resistant?</b></summary>
Флаг, означающий, что прокси устойчив к активному зондированию (DPI отправляет запрос и смотрит, отвечает ли сервер как настоящий HTTPS).

⚠️ Сейчас флаг всегда false — полноценный handshake-тест ещё не реализован. Это в планах.

</details><details> <summary><b>Как часто обновляются списки?</b></summary>
Каждые 2 часа через GitHub Actions. Можно запустить вручную: Actions → Update Verified Proxy Lists → Run workflow.

</details><details> <summary><b>Безопасно ли использовать эти прокси?</b></summary>
Нет. Бесплатные прокси могут логировать трафик. Не передавай через них пароли, банковские данные и личную информацию. Для приватности лучше поднять свой MTProto-сервер или использовать платный VPN.

</details><details> <summary><b>Почему некоторые прокси не работают в Telegram?</b></summary>
TCP-порт может быть открыт, но MTProto-handshake не проходит. Мы отсеиваем явный мусор (порты 22, 80, 3306), но 100% гарантии нет. Всегда проверяй в Telegram перед использованием.

</details><details> <summary><b>Как добавить свой источник прокси?</b></summary>
Форкни репозиторий, добавь URL в список SOURCES или SOCKS_SOURCES в main.py и запусти workflow. Формат — любой из поддерживаемых (tg://, t.me/, host:port:secret, JSON, YAML).

</details><details> <summary><b>Что за AI-аналитика в конце README?</b></summary>
Скрипт ai_analytics.py раз в 2 часа отправляет статистику в Groq (openai/gpt-oss-120b) и получает короткий отчёт о качестве прокси. Если ключа Groq нет — генерирует локально.

</details>
🛠️ Community Tools: утилиты от пользователей
Инструмент	Описание	Автор
Parser‑telegram‑proxies	Windows‑утилита с отображением пинга в реальном времени.	ComradeBingo
Proxy‑Telegram‑Android	Android‑приложение для парсинга прокси и пинга серверов.	ComradeBingo
Proxy‑telegram‑windows	Парсер прокси для Windows, версия 1.2.	ComradeBingo
🔥 Актуальные списки (обновляются каждые 2 часа)
Регион / Тип	Список	Примечание
🇷🇺 RU (MTProto)	proxy_ru.txt	Маскировка под Yandex, VK, Mail.ru, Gosuslugi
🇪🇺 EU (MTProto)	proxy_eu.txt	Маскировка под Google, Amazon, Cloudflare
🇺🇸 US (MTProto)	proxy_us.txt	США и Канада
🌏 ASIA (MTProto)	proxy_asia.txt	JP, KR, SG, HK, IN, TW, PH, MY, ID, VN, TH
🌍 Все MTProto	proxy_all_mtproto.txt	Все регионы вместе
🔒 SOCKS5	socks5.txt	Без маскировки
📱 Использование с телефона
Открой https://kort0881.github.io/telegram-proxy-collector/

Выбери вкладку MTProto RU / EU / US / ASIA / SOCKS5

Нажми — Telegram сам предложит подключиться

Мобильная версия: mobile.html

🚀 Как это работает?
Скрипт запускается каждые 2 часа через GitHub Actions и проходит 6 этапов:

1. Сбор (Harvesting)
40+ MTProto-источников и 9 SOCKS5-источников. Парсинг всех форматов: tg://proxy?…, t.me/proxy?…, host:port:secret, socks5://user:pass@host:port, JSON, YAML.

2. Seen-кэш (TTL 48 часов)
Ключ = (type, host, port, secret). Если проверялся < 48ч назад — пропускается.

3. Фильтрация
🚫 Порты: 45+ мусорных портов отбрасываются.

🌍 GeoIP: только 60+ доверенных стран.

❌ Blacklist: Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor.

4. Декодирование (Fake-TLS)
Расшифровка secret (ee...) → извлечение SNI-домена → определение региона.

5. TCP-проверка
200 воркеров, socket.connect(), таймаут 2s. Сортировка: probe_resistant → MTProto → SOCKS5.

6. Сборка списков
Разделение по регионам, запись в proxy_*.txt и verified/*.json.

📁 Итоговые файлы
Корень репозитория:

proxy_ru.txt, proxy_eu.txt, proxy_us.txt, proxy_asia.txt

proxy_all_mtproto.txt, proxy_all.txt, socks5.txt

Папка verified/:

proxy_*_verified.txt — с заголовками и статистикой

proxy_all_verified.json — массив с полями type, host, port, secret, link, ping, region, domain

proxy_stats_verified.json — статистика по запуску

proxy_domain_verified.txt — Fake-TLS прокси с доменами

seen.json — TTL-кэш

🌍 GeoIP-фильтрация
База GeoLite2-Country.mmdb от Dreamacro/maxmind-geoip.

Разрешённые страны:

СНГ: RU, BY, KZ, UA, MD, AM, GE, AZ, UZ, KG, TJ, TM

Европа: DE, NL, FI, GB, FR, SE, PL, CZ, AT, CH, IT, ES, NO, DK, BE, IE, LU, EE, LV, LT, PT, GR, RO, BG, HU, SK, SI, HR, RS, TR

Америка: CA, US

Азия: JP, KR, SG, HK, IN, TW, PH, MY, ID, VN, TH, MN

🛠️ Локальный запуск
bash
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector
pip install -r requirements.txt

mkdir -p data
wget -O data/GeoLite2-Country.mmdb \
  https://raw.githubusercontent.com/Dreamacro/maxmind-geoip/release/Country.mmdb

python main.py \
  --top 100 --timeout 2.0 --workers 200 \
  --max-check 30000 --output-dir verified \
  --geoip data/GeoLite2-Country.mmdb --seen-ttl 48

python analytics.py                     # ML-аналитика
export TELEGRAMPROXYCOLLECTOR=gsk_...   # ключ Groq
python ai_analytics.py                  # AI-отчёт
Параметры
Флаг	По умолчанию	Описание
--timeout	2.0	TCP timeout
--workers	100	Потоки проверки
--top	0 (все)	Топ X на регион
--output-dir	verified	Папка результатов
--geoip	—	Путь к .mmdb
--max-check	30000	Максимум прокси на проверку
--seen-file	verified/seen.json	TTL-кэш
--seen-ttl	48	TTL в часах
--manual	—	Локальный файл с доп. прокси
🧪 AI и ML
analytics.py
RandomForest (good/bad) с CV, IsolationForest для аномалий, тренды. Сохраняет reports/analytics_report.json, reports/anomalies.json, reports/analytics.log.

ai_analytics.py
Groq через OpenAI-совместимый API, модель openai/gpt-oss-120b (Apache 2.0, MoE, 5.1B активных параметров). Обновляет блок в README. Fallback — локальная генерация.

⚠️ Дисклеймер
Репозиторий не гарантирует анонимность. Прокси предоставляются «как есть».
Бесплатные прокси небезопасны — не передавай через них пароли и платёжные данные.

📊 AI-аналитика (автоматическая)
<!-- AI_ANALYTICS_START -->
Отчёт сгенерирован 2026-09-15 10:21 UTC

Отчёт о состоянии прокси-серверов (2026-09-15 12:34 UTC)
Всего прокси: 200

Качество: хорошие (ping < 1.5с) — 200, средние — 0, плохие — 0

Регионы: EU — 176, US — 8, RU — 16

Типы: MTProto — 200

Источники: данных нет

Рекомендация: для большинства задач лучше использовать MTProto-прокси из региона EU.

<!-- AI_ANALYTICS_END -->
<details> <summary>🔗 <b>Мои проекты</b> (нажми, чтобы раскрыть)</summary>
Проект	Описание	Ссылка
VPN KEY VLESS	Основной канал с конфигами и новостями	Telegram
KiberSos New	Резервный канал	Telegram
VlessBots	Бот для выдачи ключей	Bot
Internet Access	Сайт проекта	Website
VPN Key Repo	VLESS-скрипты	GitHub
</details>
