🛡️ Telegram Proxy Collector: Anti-Censorship Edition
Умный комбайн для сбора MTProto прокси.
В отличие от обычных парсеров, этот скрипт анализирует секрет (Secret) каждого прокси и определяет, под какой сайт он маскируется. Это критически важно для работы в условиях жестких блокировок (DPI).

🛠️ Community Tools: Утилиты от пользователей
Инструмент	Описание	Автор
Parser-telegram-proxies	Удобная Windows-утилита для парсинга и проверки прокси с отображением пинга в реальном времени.	ComradeBingo
🔥 Актуальные списки (обновляются автоматически)
Скрипт каждые 4 часа запускается через GitHub Actions, собирает свежие MTProto‑прокси, фильтрует и проверяет их, а затем обновляет файлы в этом репозитории.

Прямые ссылки для вставки в Telegram или свои программы:

🇷🇺 RU Сегмент (Top Tier)	🇪🇺 EU / Global	🌍 Все прокси
proxy_ru.txt	proxy_eu.txt	proxy_all.txt
Маскировка под Yandex, VK, Mail.ru, Gosuslugi и др.	Маскировка под Google, Amazon, Microsoft и др.	Полный микс всех проверенных серверов
✅ Лучшие для РФ и Ирана	✅ Высокая скорость и стабильность	✅ Максимальное количество прокси
⚙️ GitHub Actions сохраняет результаты в verified/, а затем копирует их в proxy_ru.txt, proxy_eu.txt и proxy_all.txt в корне репозитория, так что ссылки выше всегда ведут на свежие списки.

📱 Использование с телефона
Если вы открыли этот репозиторий с телефона и хотите быстро подключить MTProto‑прокси без копипасты:

Откройте страницу: https://kort0881.github.io/telegram-proxy-collector/mobile.html

Там вы увидите кнопки: «Подключить прокси #1», «Подключить прокси #2» и т.д. При нажатии браузер откроет ссылку вида https://t.me/proxy?..., и Telegram предложит подключиться. Страница mobile.html автоматически читает файл verified/proxy_links_tme_clean.txt.

🚀 Как это работает?
Скрипт запускается каждый час и выполняет 4 этапа:

Сбор (Harvesting): Скачивает «сырые» прокси из нескольких открытых источников (GitHub‑репозитории, TXT, JSON‑API). Использует агрессивный Regex‑парсинг для извлечения ссылок.

Декодирование (Deep Analysis): Расшифровывает Fake‑TLS секреты (начинаются на ee...) и определяет домен, под который маскируется трафик (Yandex, VK, Mail.ru, Google и т.д.).

Фильтрация (Smart Filter):

⛔ Blacklist: отбрасывает прокси, маскирующиеся под заблокированные ресурсы (Instagram, Facebook и т.п.), чтобы не тратить трафик в РФ.

✅ RU‑маркер: помечает прокси как ru, если домен секрета содержит yandex, vk.com, mail.ru, sber, gosuslugi и др.

Проверка (Checking): Пингует каждый прокси (TCP/Telethon), измеряет реальный отклик и оставляет только самый быстрый вариант для каждой пары (host, port).

Результаты сохраняются в:

proxy_*.txt — готовые списки для импорта.

verified/proxy_*_verified.txt — региональные списки.

verified/proxy_all_tme_verified.txt — ссылки https://t.me/proxy?server=....

verified/proxy_all_verified.json — подробная техническая информация.

verified/proxy_stats_verified.json — статистика запуска.

🔗 Мои проекты
Проект	Описание	Ссылка
VPN KEY VLESS	Основной канал с конфигами и новостями	Telegram
KiberSos New	Резервный канал связи	Telegram
VlessBots	Бот для выдачи ключей	Bot
Internet Access	Сайт проекта	Website
VPN Key Repo	Репозиторий скриптов VLESS	GitHub
🛠️ Локальный запуск (для разработчиков)
bash
# 1. Клонировать репозиторий
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install requests telethon

# 3. Запустить (TCP-проверка)
python main.py

# или с ограничением по топу и пользовательской папкой вывода:
python main.py --top 200 --output-dir verified
