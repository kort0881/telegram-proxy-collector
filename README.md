🛡️ Telegram Proxy Collector: Anti‑Censorship Edition
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

🛠️ Community Tools: утилиты от пользователей
Инструмент	Описание	Автор
Parser‑telegram‑proxies	Удобная Windows‑утилита для парсинга и проверки MTProto‑прокси с отображением пинга в реальном времени.	ComradeBingo
Proxy‑Telegram‑Android	Приложение для Android, которое парсит прокси‑списки, проверяет их доступность и показывает пинг серверов.	ComradeBingo
Proxy‑telegram‑windows	Парсер прокси‑серверов для Telegram на Windows. Версия 1.2: переработан GUI, меню «Справка».	ComradeBingo
🔥 Актуальные списки (обновляются каждые 2 часа)
Скрипт запускается через GitHub Actions, собирает прокси, фильтрует, проверяет и обновляет списки. Результаты сохраняются в verified/ и копируются в корень репозитория.

📦 Прямые ссылки:

Регион / Тип	Список	Примечание
🇷🇺 RU (MTProto)	proxy_ru.txt	Маскировка под Yandex, VK, Mail.ru, Gosuslugi и др.
🇪🇺 EU (MTProto)	proxy_eu.txt	Маскировка под Google, Amazon, Cloudflare и др.
🇺🇸 US (MTProto)	proxy_us.txt	США и Канада.
🌏 ASIA (MTProto)	proxy_asia.txt	JP, KR, SG, HK, IN, TW, PH, MY, ID, VN, TH.
🌍 Все MTProto	proxy_all_mtproto.txt	Все регионы вместе.
🔒 SOCKS5	socks5.txt	Прокси без маскировки.
📱 Использование с телефона
Если открыл репозиторий с телефона и не хочешь копировать прокси вручную:

Открой страницу:
https://kort0881.github.io/telegram-proxy-collector/

На странице — вкладки MTProto RU / EU / US / ASIA / SOCKS5.

Нажми на любую кнопку — Telegram сам предложит подключиться.

Мобильная версия:
👉 mobile.html

🚀 Как это работает?
Скрипт запускается каждые 2 часа через GitHub Actions и проходит шесть этапов:

1. Сбор (Harvesting)
Скачивает прокси из 40+ MTProto-источников и 9 SOCKS5-источников:

GitHub-репозитории (SoliSpirit, Grim1313, ALIILAPRO, hookzof, V2RAYCONFIGSPOOL, Surfboardv2ray и др.)

mtpro.xyz, moonlunavpn.com, tgmtproxy.github.io

Парсит все форматы: tg://proxy?…, t.me/proxy?…, host:port:secret, socks5://user:pass@host:port, JSON, YAML.

2. Seen-кэш (TTL 48 часов)
Перед проверкой прокси сверяются с verified/seen.json:

ключ = (type, host, port, secret),

если проверялся < 48 часов назад — пропускается,

если старше — проверяется заново.

3. Фильтрация (Smart Filter)
🚫 Порты: SUSPICIOUS_PORTS (22, 80, 3306, 5432, 8080, 8443, 25565, …) — не бывают MTProto.

🌍 GeoIP: GeoLite2-Country.mmdb — оставляем только 60+ доверенных стран.

❌ Blacklist: Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor.

4. Dекодирование (Fake-TLS Analysis)
Расшифровывает secret формата ee....

Извлекает SNI-домен (Yandex, VK, Google, Cloudflare, …).

Определяет регион: RU / EU / US / ASIA по домену.

5. TCP-проверка
200 воркеров параллельно.

socket.connect() с таймаутом 2.0s.

Сортировка: probe_resistant → MTProto → SOCKS5, внутри — по возрастанию ping.

6. Сборка итоговых списков
Разделение по регионам.

Запись в proxy_*.txt, verified/*.json, verified/*.txt.

📁 Итоговые файлы
Корень репозитория (для прямых ссылок):

proxy_ru.txt, proxy_eu.txt, proxy_us.txt, proxy_asia.txt — MTProto tg://proxy?...

proxy_all_mtproto.txt — все MTProto

proxy_all.txt — RU + EU

socks5.txt — SOCKS5 tg://socks?...

Папка verified/ (детально):

proxy_ru_verified.txt, proxy_eu_verified.txt, … — с заголовками и статистикой.

proxy_all_verified.json — массив с полями:
type, host, port, secret, link, ping, region, domain, method, probe_resistant.

proxy_stats_verified.json — статистика по запуску.

proxy_domain_verified.txt — только прокси с Fake-TLS доменом.

seen.json — TTL-кэш проверенных прокси.

🎭 Fake-TLS: «золотые» прокси
MTProto-прокси могут маскироваться под HTTPS, отправляя фейковый SNI популярных сервисов. Это делает их устойчивыми к DPI-блокировкам.

Наш детектор извлекает домен из secret (ee...) и определяет регион:

SNI-домен	Регион
yandex.ru, vk.com, mail.ru, gosuslugi.ru, sber.ru	🇷🇺 RU
amazonaws.com, cloudflare.com, digitalocean.com	🇺🇸 US
*.jp, *.sg, *.hk, *.kr	🌏 ASIA
остальные	🇪🇺 EU
Все прокси с распознанным доменом попадают в verified/proxy_domain_verified.txt:

text
tg://proxy?server=...&port=443&secret=ee... # domain: ya.ru
🌍 GeoIP-фильтрация
Используется база GeoLite2-Country.mmdb (обновляется ежедневно из Dreamacro/maxmind-geoip).

Разрешённые страны:

СНГ + Восточная Европа: RU, BY, KZ, UA, MD, AM, GE, AZ, UZ, KG, TJ, TM

Западная Европа: DE, NL, FI, GB, FR, SE, PL, CZ, AT, CH, IT, ES, NO, DK, BE, IE, LU, EE, LV, LT, PT, GR, RO, BG, HU, SK, SI, HR, RS, TR

Северная Америка: CA, US

Азия: JP, KR, SG, HK, IN, TW, PH, MY, ID, VN, TH, MN

Прокси из других стран отбрасываются до TCP-проверки — экономит время и трафик.

🔗 Мои проекты
Проект	Описание	Ссылка
VPN KEY VLESS	Основной канал с конфигами и новостями.	Telegram
KiberSos New	Резервный канал.	Telegram
VlessBots	Бот для выдачи ключей и прокси.	Bot
Internet Access	Сайт проекта.	Website
VPN Key Repo	Репозиторий VLESS-скриптов.	GitHub
🛠️ Локальный запуск
bash
# 1. Клонировать
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Скачать GeoIP
mkdir -p data
wget -O data/GeoLite2-Country.mmdb \
  https://raw.githubusercontent.com/Dreamacro/maxmind-geoip/release/Country.mmdb

# 4. Запустить
python main.py \
  --top 100 \
  --timeout 2.0 \
  --workers 200 \
  --max-check 30000 \
  --output-dir verified \
  --geoip data/GeoLite2-Country.mmdb \
  --seen-ttl 48

# 5. ML-аналитика
python analytics.py

# 6. AI-отчёт (нужен Groq-ключ)
export TELEGRAMPROXYCOLLECTOR=gsk_...
python ai_analytics.py
Параметры main.py
Флаг	По умолчанию	Описание
--timeout	2.0	TCP timeout в секундах
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
Читает историю проверок, обучает RandomForest (good/bad) с CV.

Ищет аномалии через IsolationForest.

Считает тренды: медиана ping, stdev, направление.

Сохраняет: reports/analytics_report.json, reports/anomalies.json, reports/analytics.log.

ai_analytics.py
Читает proxy_history.json, формирует промпт.

Отправляет в Groq через OpenAI-совместимый API.

Модель: openai/gpt-oss-120b (Apache 2.0, MoE, 5.1B активных параметров).

Обновляет блок в README между <!-- AI_ANALYTICS_START --> / <!-- AI_ANALYTICS_END -->.

Fallback — локальная генерация без LLM.

⚠️ Дисклеймер и безопасность
Этот репозиторий не гарантирует анонимность и защиту от компрометации.
Все прокси предоставляются «как есть», их качество зависит от внешних источников.
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
