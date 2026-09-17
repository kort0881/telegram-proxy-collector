# 🛡️ Telegram Proxy Collector: Anti‑Censorship Edition

[![oosmetrics — Топ‑5 в категории Crypto](https://api.oosmetrics.com/api/v1/badge/achievement/21322b63-7982-4e81-99f7-ada7354f9c21.svg)](https://oosmetrics.com/repo/kort0881/telegram-proxy-collector)

**Умный комбайн** для сбора, анализа и отбора **MTProto** и **SOCKS5** прокси.  
В отличие от обычных парсеров, этот скрипт **глубоко анализирует** `Secret` каждого MTProto‑прокси, извлекает **домен‑маску** (Yandex, VK, Mail.ru, Gosuslugi, Google, Amazon, Cloudflare и др.), **фильтрует по GeoIP** (60+ доверенных стран) и **отсеивает мусорные порты** (SSH, MySQL, Tomcat, Minecraft).  
Это особенно важно в условиях жёстких блокировок, где **маскировка под легитимный HTTPS** или использование SOCKS5 может быть разницей между работой и полной недоступностью.

👉 [GitHub — Telegram Proxy Collector](https://github.com/kort0881/telegram-proxy-collector)

---

## 📌 Что нового в версии 3.8

- **🌍 GeoIP‑фильтрация** — используется база `GeoLite2-Country.mmdb` (обновляется ежедневно). Прокси из недоверенных стран отбрасываются **до** TCP‑проверки — экономит время и трафик.
- **🚫 Фильтр мусорных портов** — 45+ портов (22, 80, 3306, 5432, 8080, 8443, 25565 и др.) автоматически отбрасываются для MTProto.
- **🧠 TTL seen‑кэш** — прокси не проверяются дважды в течение 48 часов. Ключ кэша включает `secret`, поэтому разные MTProto на одном IP не считаются дубликатами.
- **⚡ Ограничение объёма** — параметр `--max-check` (по умолчанию 30 000) защищает от «тяжёлых» прогонов.
- **🎭 Fake‑TLS детектор** — из `secret` извлекается SNI‑домен, по нему определяется регион (`ru` / `eu` / `us` / `asia`).
- **🌏 Расширенная география** — добавлены регионы ASIA (JP, KR, SG, HK, IN, TW, PH, MY, ID, VN, TH, MN) и US.
- **🧪 AI‑аналитика** — Groq `openai/gpt-oss-120b` автоматически обновляет блок в README.
- **📊 ML‑аналитика** — `analytics.py` обучает RandomForest (качество) + IsolationForest (аномалии) и считает тренды между запусками.
- **🔐 Fallback GeoIP** — `maxminddb.open_database` → `geoip2.database.Reader` для совместимости.
- **⚙️ 200 воркеров** — 30 000 прокси проверяются за ~40 секунд.

---

## 🛠️ Community Tools: утилиты от пользователей

| Инструмент | Описание | Автор |
| --- | --- | --- |
| [Parser‑telegram‑proxies](https://github.com/ComradeBingo/Parser-telegram-proxies-list/) | Удобная Windows‑утилита для парсинга и проверки MTProto‑прокси с **отображением пинга в реальном времени**. Обновлённая версия исправляет периодические блокировки запросов к TXT‑файлам на GitHub за счёт использования HTTP‑запросов вместо прямого чтения. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑Telegram‑Android](https://github.com/ComradeBingo/Proxy-Telegram-Android) | Приложение для Android, которое **парсит прокси‑списки**, проверяет их доступность и показывает пинг серверов. | [ComradeBingo](https://github.com/ComradeBingo) |
| [Proxy‑telegram‑windows](https://github.com/ComradeBingo/Proxy-telegram-windows) | Парсер прокси‑серверов для Telegram на Windows. Обновлён до версии **1.2**: переработан GUI, добавлено меню «Справка», улучшена стабильность и удобство использования. | [ComradeBingo](https://github.com/ComradeBingo) |

---

## 🔥 **Актуальные списки** (обновляются автоматически **каждые 2 часа**)

Скрипт **раз в 2 часа** запускается через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions), **собирает** свежие прокси из открытых источников, **фильтрует** по GeoIP и портам, **проверяет** через TCP‑ping и **обновляет** списки.  
GitHub Actions **сохраняет результаты** в папку `verified/`, а затем **копирует** их в корень репозитория — поэтому **ссылки ниже всегда ведут на свежие списки**.

📦 **Прямые ссылки** для вставки в Telegram или свои программы:

| Регион / Тип | Список | Примечание |
| --- | --- | --- |
| 🇷🇺 RU‑сегмент (MTProto) | [proxy_ru.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt) | Маскировка под **Yandex, VK, Mail.ru, Gosuslugi, Sber, Mos.ru** и др. Нацелен на **лучшую стабильность в РФ и Иране**. |
| 🇪🇺 EU / Global (MTProto) | [proxy_eu.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt) | Маскировка под **Google, Amazon, Cloudflare** и другие международные сервисы. Высокая скорость и стабильность, особенно вне РФ. |
| 🇺🇸 US (MTProto) | [proxy_us.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_us.txt) | США и Канада. |
| 🌏 ASIA (MTProto) | [proxy_asia.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_asia.txt) | JP, KR, SG, HK, IN, TW, PH, MY, ID, VN, TH, MN. |
| 🌍 Все MTProto прокси | [proxy_all_mtproto.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all_mtproto.txt) | Полный микс всех проверенных MTProto‑серверов (RU + EU + US + ASIA). |
| 🇷🇺🇪🇺 RU + EU | [proxy_all.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt) | Только RU и EU вместе. |
| 🔒 **SOCKS5 прокси** | [socks5.txt](https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt) | Прокси протокола SOCKS5 (без маскировки, но часто сложнее блокируются). |

---

## 📱 **Использование с телефона**

Если ты открыл репозиторий **с телефона** и не хочешь копировать прокси вручную:

1. Открой страницу:  
   [https://kort0881.github.io/telegram-proxy-collector/](https://kort0881.github.io/telegram-proxy-collector/)  
   (этот же файл `index.html` находится в корне репозитория)
2. На странице есть вкладки:  
   - **MTProto RU** – прокси с маскировкой под российские сайты,  
   - **MTProto EU** – международная маскировка,  
   - **MTProto US** – США и Канада,  
   - **MTProto ASIA** – Азиатско‑Тихоокеанский регион,  
   - **SOCKS5** – прокси без маскировки, но часто работающие там, где MTProto блокируется.
3. Нажми на любую кнопку – Telegram сам предложит подключиться.

Также доступна специальная мобильная версия:  
👉 [mobile.html](https://kort0881.github.io/telegram-proxy-collector/mobile.html) — она оптимизирована для небольших экранов и имеет упрощённый интерфейс.

---

## 🚀 **Как это работает?**

Скрипт **запускается каждые 2 часа** через [GitHub Actions](https://github.com/kort0881/telegram-proxy-collector/actions) и последовательно проходит **шесть главных этапов**:

### 1. Сбор (Harvesting)

- Скачивает «сырые» прокси из **двух категорий источников**:
  - **MTProto** — 40+ источников (GitHub‑репозитории, `mtpro.xyz`, `moonlunavpn.com`, `tgmtproxy.github.io`).
  - **SOCKS5** — 9 специализированных списков.
- Использует **агрессивный Regex‑парсинг** для извлечения ссылок из любого формата:
  - `tg://proxy?server=...&port=...&secret=...`
  - `tg://socks?server=...&port=...`
  - `t.me/proxy?...`
  - `host:port:secret`
  - `socks5://[user:pass@]host:port`
  - JSON‑объекты, YAML‑списки.

### 2. Seen‑кэш (TTL 48 часов)

- Ключ кэша — `(type, host, port, secret)`. Разные `secret` на одном IP считаются разными прокси.
- Если прокси проверялся менее 48 часов назад — он пропускается.
- Файл кэша: `verified/seen.json`.

### 3. Фильтрация (Smart Filter)

- 🚫 **Порты:** `SUSPICIOUS_PORTS` (22, 80, 3306, 5432, 8080, 8443, 25565 и др.) — 45+ мусорных портов отбрасываются.
- 🌍 **GeoIP:** через `GeoLite2-Country.mmdb` оставляем только 60+ доверенных стран.
- ❌ **Blacklist:** прокси, маскирующиеся под **заведомо заблокированные ресурсы** (Instagram, Facebook, Twitter, BBC, Meduza, LinkedIn, Tor и др.), **отбрасываются**.

### 4. Декодирование (Fake‑TLS Analysis)

- Расшифровывает **Fake‑TLS‑секреты** MTProto (начинаются на `ee...`).
- Извлекает **домен**, под который идёт маскировка трафика (например `yandex.ru`, `vk.com`, `google.com`).
- На основе домена **помечает** MTProto прокси как `ru` / `eu` / `us` / `asia`:
  - `yandex`, `vk.com`, `mail.ru`, `ok.ru`, `sber`, `tinkoff`, `gosuslugi`, `ozon`, `wildberries`, `avito`, `kinopoisk` → `ru`
  - `amazonaws.com`, `digitalocean.com`, `cloudflare.com`, `.gov` → `us`
  - `*.jp`, `*.sg`, `*.hk`, `*.kr`, `*.in` и др. → `asia`
  - всё остальное → `eu`

### 5. Проверка (TCP Ping)

- Проверяет каждый прокси через **TCP‑сокет** (`socket.connect()`) с таймаутом 2 секунды.
- 200 воркеров параллельно — 30 000 прокси за ~40 секунд.
- Результат сохраняется в `verified/proxy_all_verified.json` с полями `type`, `host`, `port`, `secret`, `link`, `ping`, `region`, `domain`, `probe_resistant`.

### 6. Сборка итоговых списков

- Все прокси **сортируются по приоритету**:
  1. MTProto с `probe_resistant: true` (задел на будущее — сейчас всегда `false`)
  2. Обычные MTProto
  3. SOCKS5
- Внутри каждой группы – по возрастанию пинга.
- MTProto прокси разделяются на **RU / EU / US / ASIA**.
- SOCKS5 прокси выносятся в отдельный файл `socks5.txt`.
- Формируются файлы:
  - `proxy_ru.txt`, `proxy_eu.txt`, `proxy_us.txt`, `proxy_asia.txt`, `proxy_all_mtproto.txt`, `proxy_all.txt`
  - `socks5.txt`
  - `verified/` – подробные копии с комментариями и JSON.

---

## 📁 **Итоговые файлы**

После каждого запуска вы получите:

- **Корень репозитория** (удобно для прямых ссылок):
  - `proxy_ru.txt`, `proxy_eu.txt`, `proxy_us.txt`, `proxy_asia.txt` — MTProto `tg://proxy?...`
  - `proxy_all_mtproto.txt`, `proxy_all.txt` — все MTProto
  - `socks5.txt` — SOCKS5 `tg://socks?...`
- **Папка `verified/`** (подробные версии):
  - `proxy_ru_verified.txt`, `proxy_eu_verified.txt`, `proxy_us_verified.txt`, `proxy_asia_verified.txt`, `proxy_all_verified.txt` — с заголовками и статистикой.
  - `socks5_proxies.txt` — SOCKS5 с комментариями.
  - `proxy_all_verified.json` — полный JSON с полями: `type`, `host`, `port`, `secret`, `link`, `ping`, `region`, `domain`, `method`, `probe_resistant`.
  - `proxy_stats_verified.json` — статистика по запуску (количество прокси по регионам, время, geoip_mode).
  - `proxy_domain_verified.txt` — только прокси с Fake‑TLS доменом.
  - `seen.json` — TTL‑кэш проверенных прокси.

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
pip install -r requirements.txt

# 3. Скачать GeoIP базу
mkdir -p data
wget -O data/GeoLite2-Country.mmdb \
  https://raw.githubusercontent.com/Dreamacro/maxmind-geoip/release/Country.mmdb

# 4. Запустить базовую проверку (TCP-пинг + GeoIP + фильтр портов)
python main.py --geoip data/GeoLite2-Country.mmdb

# 5. Запустить полную проверку с лимитами
python main.py \
  --top 100 \
  --timeout 2.0 \
  --workers 200 \
  --max-check 30000 \
  --output-dir verified \
  --geoip data/GeoLite2-Country.mmdb \
  --seen-ttl 48

# 6. ML-аналитика
python analytics.py

# 7. AI-отчёт (нужен ключ Groq)
export TELEGRAMPROXYCOLLECTOR=gsk_...
python ai_analytics.py

# 8. Помощь по аргументам
python main.py --help
```

### Параметры `main.py`

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--timeout` | `2.0` | TCP timeout в секундах |
| `--workers` | `100` | Количество потоков проверки |
| `--top` | `0` (все) | Топ X прокси на регион |
| `--output-dir` | `verified` | Папка для результатов |
| `--geoip` | — | Путь к файлу `.mmdb` для GeoIP-фильтрации |
| `--max-check` | `30000` | Максимум прокси для TCP-проверки |
| `--seen-file` | `verified/seen.json` | Файл TTL-кэша |
| `--seen-ttl` | `48` | TTL кэша в часах |
| `--manual` | — | Путь к локальному файлу с дополнительными прокси |

---

## ⚠️ Дисклеймер и безопасность

Этот репозиторий **не гарантирует анонимность**, невозможность слежки или защищённость от компрометации.  
Все прокси‑серверы предоставляются на условиях **«как есть»**, и их качество зависит от внешних источников.  
**Бесплатные прокси небезопасны** — не передавай через них пароли, банковские данные и личную информацию.

---

## 📊 AI-аналитика (автоматическая)

<!-- AI_ANALYTICS_START -->
*Отчёт сгенерирован 2026-09-17 00:09 UTC*

**Отчёт о состоянии прокси‑серверов (2026‑09‑17 12:34)**  

- Всего прокси в истории: **200** (все с хорошим качеством, пинг < 1.5 с).  
- Распределение по регионам: **EU – 192**, **US – 4**, **RU – 4**.  
- Типы: **MTProto – 76**, **SOCKS5 – 124**.  

### Рекомендация
- **Регион:** отдавайте предпочтение европейским (EU) прокси – они составляют 96 % списка и обладают лучшим качеством.  
- **Тип:** для большинства задач подойдёт **SOCKS5** (62 % всех прокси), но если требуется работа с Telegram, выбирайте **MTProto**.  

### Аномалии
- Плохих прокси не обнаружено, статистика по источникам отсутствует.  

*Отчёт актуален на момент генерации.*
<!-- AI_ANALYTICS_END -->

---

