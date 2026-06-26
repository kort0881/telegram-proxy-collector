#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI Analytics — использует внешний LLM (Grok/OpenAI) для генерации отчётов и обновления README

import os
import json
import re
import requests
from datetime import datetime
from pathlib import Path
from collections import Counter

DATA_DIR = Path("data")
REPORT_DIR = Path("reports")
README_FILE = Path("README.md")
HISTORY_FILE = DATA_DIR / "proxy_history.json"
SOURCE_STATS_FILE = DATA_DIR / "source_stats.json"

def load_history():
    if not HISTORY_FILE.exists():
        return []
    with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def load_source_stats():
    if not SOURCE_STATS_FILE.exists():
        return {}
    with open(SOURCE_STATS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def build_prompt(history, stats):
    total = len(history)
    if total == 0:
        return "Нет данных для анализа."

    good = sum(1 for p in history if p.get('ping', 999) < 1.5)
    medium = sum(1 for p in history if 1.5 <= p.get('ping', 999) < 5.0)
    bad = sum(1 for p in history if p.get('ping', 999) >= 5.0)
    regions = Counter(p.get('region', 'unknown') for p in history)
    types = Counter(p.get('type', 'mtproto') for p in history)

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
2. Укажи, сколько прокси добавлено за последний час (если есть данные).
3. Дай рекомендацию, какие прокси лучше использовать (по региону, типу).
4. Если есть аномалии (слишком много плохих прокси) — предупреди.
5. Добавь дату и время отчёта.

Ответ должен быть в формате Markdown (без лишнего текста, только готовый блок для вставки в README).
"""
    return prompt

def call_llm_api(prompt, api_key, provider="auto", model=None):
    """
    Вызов LLM API с поддержкой Grok (xAI) и OpenAI.
    
    Args:
        prompt: Текст запроса
        api_key: API ключ
        provider: "grok", "openai" или "auto" (автоопределение)
        model: Название модели (опционально)
    """
    
    # Определяем провайдера
    if provider == "auto":
        # Пытаемся определить по формату ключа
        if api_key.startswith("xai-"):
            provider = "grok"
        else:
            provider = "openai"
    
    # Настраиваем endpoint и модель
    if provider == "grok":
        url = "https://api.x.ai/v1/chat/completions"
        if model is None:
            model = "grok-2-latest"
    else:  # openai
        url = "https://api.openai.com/v1/chat/completions"
        if model is None:
            model = "gpt-3.5-turbo"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 500
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()['choices'][0]['message']['content']
        else:
            print(f"⚠️ Ошибка API ({provider}): {resp.status_code} – {resp.text}")
            return None
    except Exception as e:
        print(f"⚠️ Ошибка запроса к LLM ({provider}): {e}")
        return None

def update_readme_with_ai_report(report_text):
    if not README_FILE.exists():
        print("⚠️ README.md не найден")
        return

    with open(README_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    start_marker = "<!-- AI_ANALYTICS_START -->"
    end_marker = "<!-- AI_ANALYTICS_END -->"

    if start_marker not in content or end_marker not in content:
        # Если маркеров нет, добавим их в конец README
        content += f"\n\n## 📊 AI-аналитика (автоматическая)\n\n{start_marker}\n{report_text}\n{end_marker}"
    else:
        pattern = re.compile(rf'{re.escape(start_marker)}.*?{re.escape(end_marker)}', re.DOTALL)
        replacement = f"{start_marker}\n{report_text}\n{end_marker}"
        content = pattern.sub(replacement, content)

    with open(README_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✅ README.md обновлён с AI-аналитикой")

def main():
    # Поддержка нескольких переменных окружения для гибкости
    api_key = os.environ.get("XAI_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("TELEGRAMPROXYCOLLECTOR")
    provider = os.environ.get("LLM_PROVIDER", "auto")  # "grok", "openai" или "auto"
    
    if not api_key:
        print("⚠️ API-ключ не найден. Установите XAI_API_KEY, OPENAI_API_KEY или TELEGRAMPROXYCOLLECTOR. Пропускаем AI-аналитику.")
        return

    print("🧠 Запуск AI-аналитики с использованием внешнего LLM...")
    history = load_history()
    stats = load_source_stats()

    if not history:
        print("⚠️ Нет истории для анализа. Завершение.")
        return

    prompt = build_prompt(history, stats)
    print("📤 Отправка запроса к LLM...")
    report_text = call_llm_api(prompt, api_key, provider=provider)

    if report_text:
        report_text = f"*Отчёт сгенерирован {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}*\n\n" + report_text
        update_readme_with_ai_report(report_text)
        print("✅ AI-аналитика завершена и README обновлён")
    else:
        print("⚠️ Не удалось получить ответ от LLM.")

if __name__ == "__main__":
    main()
