#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI Analytics — работает с Groq (бесплатно) через OpenAI-совместимый API

import os
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from openai import OpenAI   # <--- заменили requests

DATA_DIR = Path("data")
VERIFIED_DIR = Path("verified")
README_FILE = Path("README.md")
HISTORY_FILE = DATA_DIR / "proxy_history.json"
SOURCE_STATS_FILE = VERIFIED_DIR / "source_stats.json"

def load_history():
    if not HISTORY_FILE.exists():
        return []
    with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_source_stats():
    if not SOURCE_STATS_FILE.exists():
        return {}
    with open(SOURCE_STATS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def _compute_stats(history):
    """Единый расчёт метрик — используется и промптом, и локальным отчётом."""
    return {
        'total': len(history),
        'good': sum(1 for p in history if p.get('ping', 999) < 1.5),
        'medium': sum(1 for p in history if 1.5 <= p.get('ping', 999) < 5.0),
        'bad': sum(1 for p in history if p.get('ping', 999) >= 5.0),
        'regions': Counter(p.get('region', 'unknown') for p in history),
        'types': Counter(p.get('type', 'mtproto') for p in history),
    }

def _clean_markdown(text):
    """Убирает вступление модели («Sure, here is...») — режем до первого # или **."""
    if not text:
        return text
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:]) if len(lines) >= 2 else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    cuts = [i for i in (text.find('#'), text.find('**')) if i != -1]
    if cuts:
        text = text[min(cuts):]
    return text.strip()

def build_prompt(history, stats):
    m = _compute_stats(history)
    total = m['total']
    if total == 0:
        return "Нет данных для анализа."

    good, medium, bad = m['good'], m['medium'], m['bad']
    regions, types = m['regions'], m['types']

    prompt = f"""
Проанализируй следующие данные о прокси-серверах и сформируй краткий отчёт (на русском языке) для раздела README.md.

Данные:
- Всего прокси в истории: {total}
- Качество: хороших (пинг < 1.5с) — {good}, средних (1.5–5с) — {medium}, плохих (>5с) — {bad}
- Регионы: {dict(regions)}
- Типы: {dict(types)}
- Статистика по источникам: {json.dumps(stats, indent=2, ensure_ascii=False)}

Задача:
1. Напиши краткое введение (1–2 предложения) о текущем состоянии списков.
2. Дай рекомендацию, какие прокси лучше использовать (по региону, типу).
3. Если есть аномалии (слишком много плохих прокси) — предупреди.
4. Добавь дату и время отчёта.

Ответ должен быть в формате Markdown (без лишнего текста, только готовый блок для вставки в README).
"""
    return prompt

def call_openai_api(prompt, api_key):
    """Вызов OpenAI-совместимого API Groq (бесплатно)"""
    client = OpenAI(
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1",
        timeout=30.0
    )
    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",   # новая модель
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=800
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"⚠️ Ошибка запроса к Groq через OpenAI-клиент: {e}")
        return None

def generate_local_report(history, stats):
    """Локальная генерация (если нет API-ключа или API недоступен)"""
    m = _compute_stats(history)
    total = m['total']
    if total == 0:
        return "Нет данных для анализа."

    good, medium, bad = m['good'], m['medium'], m['bad']
    regions, types = m['regions'], m['types']

    lines = []
    lines.append(f"**📊 Текущее состояние списков**")
    lines.append(f"- Всего прокси в истории: **{total}**")
    lines.append(f"- 🟢 Хорошие (пинг < 1.5с): **{good}**")
    lines.append(f"- 🟡 Средние (1.5–5с): **{medium}**")
    lines.append(f"- 🔴 Плохие (>5с): **{bad}**")
    
    if regions:
        lines.append(f"\n**🌍 Регионы:**")
        for reg, count in regions.most_common():
            lines.append(f"- {reg}: {count}")
    
    if types:
        lines.append(f"\n**📦 Типы:**")
        for t, count in types.most_common():
            lines.append(f"- {t}: {count}")
    
    lines.append(f"\n**💡 Рекомендации:**")
    if good > 0:
        best_region = regions.most_common(1)[0][0] if regions else 'RU'
        lines.append(f"- Используйте прокси из региона **{best_region}** — они показывают лучший пинг.")
    else:
        lines.append("- Рекомендуется проверить источники — хороших прокси пока нет.")
    
    if bad > total * 0.5:
        lines.append("- ⚠️ Обнаружено много плохих прокси — возможно, источники устарели.")
    
    if medium > 0:
        lines.append("- Средние прокси можно использовать как запасной вариант.")

    return "\n".join(lines)

def update_readme_with_report(report_text):
    if not README_FILE.exists():
        print("⚠️ README.md не найден")
        return

    with open(README_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    start_marker = "<!-- AI_ANALYTICS_START -->"
    end_marker = "<!-- AI_ANALYTICS_END -->"
    full_report = f"*Отчёт сгенерирован {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n\n{report_text}"

    if start_marker not in content or end_marker not in content:
        content += f"\n\n## 📊 AI-аналитика (автоматическая)\n\n{start_marker}\n{full_report}\n{end_marker}"
    else:
        pattern = re.compile(rf'{re.escape(start_marker)}.*?{re.escape(end_marker)}', re.DOTALL)
        replacement = f"{start_marker}\n{full_report}\n{end_marker}"
        content = pattern.sub(replacement, content)

    with open(README_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✅ README.md обновлён с аналитикой")

def main():
    # Секрет TELEGRAMPROXYCOLLECTOR — это Groq API ключ (gsk_...)
    api_key = os.environ.get("TELEGRAMPROXYCOLLECTOR")
    
    print("🧠 Запуск AI-аналитики...")
    history = load_history()
    stats = load_source_stats()

    if not history:
        print("⚠️ Нет истории для анализа. Завершение.")
        return

    # Если есть ключ Groq
    if api_key:
        print("📤 Отправка запроса к Groq API через OpenAI-клиент...")
        prompt = build_prompt(history, stats)
        report_text = call_openai_api(prompt, api_key)
        if report_text:
            update_readme_with_report(_clean_markdown(report_text))
            print("✅ README обновлён через Groq (openai/gpt-oss-120b)")
            return
        else:
            print("⚠️ Groq не ответил, используем локальную генерацию...")
    else:
        print("ℹ️ Groq API ключ не найден, используем локальную генерацию...")

    # Локальная генерация (если нет ключа или Groq упал)
    report_text = generate_local_report(history, stats)
    update_readme_with_report(report_text)
    print("✅ README обновлён локально")

if __name__ == "__main__":
    main()
