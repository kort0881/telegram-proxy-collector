# 🛡️ Telegram Proxy Collector: Anti‑Censorship Edition

**Умный комбайн** для сбора, анализа и отбора MTProto‑прокси.  
В отличие от обычных парсеров, этот скрипт **глубоко анализирует** `Secret` каждого прокси, извлекает **домен‑маску** (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon, Microsoft и др.) и использует эту информацию при фильтрации.  
Это особенно важно в условиях жёстких DPI‑блокировок, где **маскировка под легитимный HTTPS** может быть разницей между работой и полной недоступностью.

👉 [GitHub — Telegram Proxy Collector](https://github.com/kort0881/telegram-proxy-collector)

---

## 🛠️ Community Tools: утилиты от пользователей

| Инструмент | Описание | Автор |
| --- | --- | --- |
| [Parser‑telegram‑proxies](https://github.com/ComradeBingo/Parser-telegram-proxies-list/) | Удобная Windows‑утилита для парсинга и проверки MTProto‑прокси с **отображением пинга в реальном времени**. Обновлённая версия исправляет периодические блокировки запросов к TXT‑файлам на GitHub за счёт использования HTTP‑запросов вместо прямого чтения. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑Telegram‑Android](https://github.com/ComradeBingo/Proxy-Telegram-Android) | Приложение для Android, которое **парсит прокси‑списки**, проверяет их доступность и показывает пинг серверов. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑telegram‑windows](https://github.com/ComradeBingo/Proxy-telegram-windows) | Парсер прокси‑серверов для Telegram на Windows. Обновлён до версии **1.2**: переработан GUI, добавлено меню «Справка», улучшена стабильность и удобство использования. | [ComradeBingo](https://github.com/ComradeBingo) |

---

## 🔥 **Актуальные списки** (обновляются автоматически)

Скрипт **каждый час** запускается через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions), **собирает** свежие MTProto‑прокси из открытых источников, **фильтрует**, **проверяет** и **обновляет** списки.  
GitHub Actions **сохраняет результаты** в папку `verified/`, а затем **копирует** их в `proxy_ru.txt`, `proxy_eu.txt` и `proxy_all.txt` в корне репозитория — поэтому **ссылки ниже всегда ведут на свежие списки**.

📦 **Прямые ссылки** для вставки в Telegram или свои программы:

| Регион | Список | Примечание |
| --- | --- | --- |
| 🇷🇺 RU‑сегмент (Top Tier) | [proxy_ru.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt) | Маскировка под **Yandex, VK, Mail.ru, Gosuslugi, Sber, Mos.ru** и др. Нацелен на **лучшую стабильность в РФ и Иране**. |
| 🇪🇺 EU / Global | [proxy_eu.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt) | Маскировка под **Google, Amazon, Microsoft, Cloudflare** и другие международные сервисы. Высокая скорость и стабильность, особенно вне РФ. |
| 🌍 Все прокси | [proxy_all.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt) | Полный микс всех проверенных серверов (RU + EU). Максимальное количество прокси, но без жёсткого приоритета по региону. |

---

## 📱 **Использование с телефона**

Если ты открыл репозиторий **с телефона** и не хочешь копировать прокси вручную:

1. Открой страницу:  
   [https://kort0881.github.io/telegram-proxy-collector/mobile.html](https://kort0881.github.io/telegram-proxy-collector/mobile.html)
2. На странице ты увидишь **кнопки**:  
   «Подключить прокси #1», «Подключить прокси #2», и т.д.
3. При нажатии:  
   - Откроется ссылка вида `t.me/proxy?server=...&port=...&secret=...`.  
   - Telegram спросит: **«Подключиться к прокси?»** — просто подтверди, и прокси будет **активирован**.
4. Страница `mobile.html` **автоматически** считывает файл `verified/proxy_links_tme_clean.txt` из этого репозитория, разбивает его на строки и **превращает каждую** в отдельную кнопку, обеспечивая удобный интерфейс прямо с телефона.

---

## 🚀 **Как это работает?**

Скрипт **запускается каждые 4 часа** через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions) и последовательно проходит **четыре главных этапа**:

### 1. Сбор (Harvesting)

- Скачивает **«сырые» прокси** из следующих источников:
  - GitHub‑репозитории с MTProto‑списками,  
  - TXT‑файлы,  
  - JSON‑API,  
  - API‑сервисов, публикующих прокси.
- Использует **агрессивный Regex‑парсинг** для извлечения ссылок из любого формата:
  - `tg://proxy?server=...&port=...&secret=...`  
  - `t.me/proxy?server=...&port=...&secret=...`  
  - `host:port:secret`  
  - JSON‑объекты, где прокси заданы через `server` / `host`, `port`, `secret`.

### 2. Декодирование (Deep Analysis)

- Расшифровывает **Fake‑TLS‑секреты** (начинаются на `ee...`).
- Извлекает **домен**, под который идёт маскировка трафика (например `yandex.ru`, `vk.com`, `google.com`, `amazon.com` и т.д.).
- На основе домена **помечает** прокси как `ru` или `eu` (по набору ключевых слов в URL).

### 3. Фильтрация (Smart Filter)

- ❌ **Blacklist:** прокси, маскирующиеся под **заведомо заблокированные ресурсы** (Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor и др.), **отбрасываются**, чтобы не тратить трафик и время на проверку.
- ✅ **RU‑маркер:** прокси, содержащие в домене `yandex`, `vk.com`, `mail.ru`, `ok.ru`, `sber`, `tinkoff`, `vtb`, `gosuslugi`, `ozon`, `wildberries`, `avito`, `kinopoisk` и др., помечаются как `ru`.  
- ✅ **EU‑маркер:** остальные прокси, не попавшие в RU‑список, считаются `eu` и группируются отдельно.

### 4. Проверка (Checking)

- Пингует каждый прокси через **TCP‑сокет** (или через **Telethon MTProto**, если переданы `API_ID` и `API_HASH`).
- Измеряет **реальное время ответа** (ping) и доступность порта (по умолчанию `timeout = 2.0` с).
- Для каждой пары `host:port` оставляет **только самый быстрый** вариант (минимальный ping).

---

## 📁 **Итоговые файлы**

После прохождения всех этапов результат записывается **в несколько форматов**:

- `proxy_ru.txt`, `proxy_eu.txt`, `proxy_all.txt` — **готовые списки** `tg://proxy?...`, удобные для **импорта в Telegram** и других клиентов.
- `verified/proxy_*_verified.txt` — те же списки, **разложенные по регионам** (RU / EU / All), с дополнительными комментариями (метод проверки, лучший ping).
- `verified/proxy_all_tme_verified.txt` — удобные ссылки `t.me/proxy?server=...`, подходящие для **быстрого обмена** с пользователями.
- `verified/proxy_all_verified.json` — подробный JSON с полями:
  - `host`, `port`, `secret`,  
  - `ping`, `region` (`ru` / `eu`),  
  - `domain` (домен‑маска),  
  - `method` (`TCP_OK` / `Telethon_OK`).
- `verified/proxy_stats_verified.json` — **статистика** по запуску:
  - количество «сырых» прокси,  
  - количество верифицированных,  
  - лучший ping,  
  - время выполнения,  
  - режим проверки (TCP / Telethon).

---

## 🔗 **Мои проекты**

| Проект | Описание | Ссылка |
| --- | --- | --- |
| [VPN KEY VLESS](https://t.me/vlesstrojan) | Основной канал с конфигами, инструкциями и новостями по VLESS‑конфигам и прокси‑сети. | [Telegram](https://t.me/vlesstrojan) |
| [KiberSos New](https://t.me/kibersosnew) | Резервный канал для связи, обновлений и техподдержки. | [Telegram](https://t.me/kibersosnew) |
| [VlessBots](https://t.me/vlessbots_bot) | Бот для **автоматической выдачи ключей** и прокси‑ссылок по запросу. | [Bot](https://t.me/vlessbots_bot) |
| [Internet Access](https://kort0881.github.io/internet-access-site/) | Сайт проекта с подробной документацией, FAQ и примерами использования. | [Website](https://kort0881.github.io/internet-access-site/) |
| [VPN Key Repo](https://github.com/kort0881/vpn-key-vless) | Репозиторий скриптов, конфигураций и утилит для работы с VLESS‑сервисами и прокси‑сетями. | [GitHub](https://github.com/kort0881/vpn-key-vless) |

---

## 🛠️ **Локальный запуск (для разработчиков)**

Если хочешь запустить сборщик **на своём ПК**, а не только на GitHub Actions:

```bash
# 1. Клонировать репозиторий
git clone https://github.com/kort0881/telegram-proxy-collector.git
cd telegram-proxy-collector

# 2. Установить зависимости
pip install requests telethon

# 3. Запустить (по умолчанию: TCP‑проверка)
python main.py

# или с ограничением по топу и пользовательской папкой вывода:
python main.py --top 200 --output-dir verified
```

- Скрипт **самостоятельно** обновит списки в `verified/`, а **дальнейший механизм обновления** (через `copy` в `proxy_ru.txt` и остальные файлы) можно повторить практически в любой системе (Bash, PowerShell, GitHub‑Actions, `cron` и т.п.), следуя той же логике.

---

Теперь ты можешь **просто заменить** всё содержимое `README.md` этим текстом — он уже в **чистом Markdown**, **все ссылки кликабельны**, и **вся логика обновления** остается **точно** как в твоём оригинальном описании.
