#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Proxy Analytics v1.0 — AI-аналитика качества прокси

import json
import os
import pickle
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import requests

# ─── Конфигурация ──────────────────────────────────────────────────────────────
DATA_DIR = Path("data")
MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")
DATA_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

HISTORY_FILE = DATA_DIR / "proxy_history.json"
SOURCE_STATS_FILE = DATA_DIR / "source_stats.json"
MODEL_QUALITY_FILE = MODEL_DIR / "quality_model.pkl"
MODEL_ANOMALY_FILE = MODEL_DIR / "anomaly_model.pkl"
REPORT_FILE = REPORT_DIR / "analytics_report.json"
RECOMMENDATIONS_FILE = REPORT_DIR / "recommendations.txt"

class ProxyAnalytics:
    def __init__(self):
        self.history_df = None
        self.quality_model = None
        self.anomaly_model = None
        self.source_stats = {}

    # ─── 1. Сбор исторических данных ────────────────────────────────────────
    def collect_history(self, force=False):
        if HISTORY_FILE.exists() and not force:
            print("📂 Загрузка сохранённой истории...")
            df = pd.read_json(HISTORY_FILE)
            self.history_df = df
            return df

        print("📊 Сбор истории из verified/...")
        records = []
        verified_path = Path("verified")
        if not verified_path.exists():
            print("⚠️ Папка verified/ не найдена. Сначала запустите main.py.")
            return pd.DataFrame()

        # Ищем все JSON файлы в verified/
        json_files = list(verified_path.glob("*.json"))
        if not json_files:
            print("⚠️ В папке verified/ нет JSON файлов.")
            return pd.DataFrame()

        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if not content:
                        print(f"⚠️ Файл {json_file} пуст, пропускаем.")
                        continue
                    
                    data = json.loads(content)
                    if isinstance(data, list):
                        if len(data) == 0:
                            print(f"⚠️ Файл {json_file} содержит пустой список, пропускаем.")
                            continue
                        
                        for item in data:
                            records.append({
                                "host": item.get("host"),
                                "port": item.get("port"),
                                "type": item.get("type", "mtproto"),
                                "ping": item.get("ping", 999),
                                "region": item.get("region", "unknown"),
                                "domain": item.get("domain", ""),
                                "method": item.get("method", ""),
                                "probe_resistant": item.get("probe_resistant", False),
                                "timestamp": datetime.now().isoformat()
                            })
                    else:
                        print(f"⚠️ Файл {json_file} не содержит список, пропускаем.")
            except json.JSONDecodeError as e:
                print(f"⚠️ Ошибка парсинга JSON в {json_file}: {e}")
            except Exception as e:
                print(f"⚠️ Ошибка чтения {json_file}: {e}")

        if not records:
            print("⚠️ Нет данных для истории после обработки всех файлов.")
            self.history_df = pd.DataFrame()
            return self.history_df

        df = pd.DataFrame(records)
        df.to_json(HISTORY_FILE, orient="records", indent=2, force_ascii=False)
        print(f"✅ Сохранено {len(df)} записей в историю")
        self.history_df = df
        return df

    # ─── 2. Обучение модели качества (живучесть) ────────────────────────────
    def train_quality_model(self):
        if self.history_df is None or self.history_df.empty:
            print("⚠️ Нет истории для обучения модели качества")
            return None

        df = self.history_df.copy()
        
        def quality_label(ping):
            if ping < 1.5:
                return "good"
            elif ping < 5.0:
                return "medium"
            else:
                return "bad"

        df['quality'] = df['ping'].apply(quality_label)

        # Сначала кодируем признаки
        le_region = LabelEncoder()
        le_type = LabelEncoder()
        df['region_encoded'] = le_region.fit_transform(df['region'].fillna('unknown').astype(str))
        df['type_encoded'] = le_type.fit_transform(df['type'].fillna('mtproto').astype(str))
        df['probe_resistant'] = df['probe_resistant'].astype(int)

        # Теперь определяем features
        features = ['ping', 'region_encoded', 'type_encoded', 'probe_resistant']
        X = df[features].fillna(0)
        y = df['quality']

        if len(X) < 10:
            print("⚠️ Недостаточно данных для обучения (нужно минимум 10 записей)")
            return None

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"✅ Модель качества обучена. Точность: {acc:.2f}")
        print(classification_report(y_test, y_pred, zero_division=0))

        with open(MODEL_QUALITY_FILE, 'wb') as f:
            pickle.dump({
                'model': model, 
                'le_region': le_region, 
                'le_type': le_type,
                'features': features
            }, f)

        self.quality_model = model
        return model

    # ─── 3. Обнаружение аномалий в секретах и доменах ──────────────────────
    def train_anomaly_detector(self):
        if self.history_df is None or self.history_df.empty:
            print("⚠️ Нет истории для обучения детектора аномалий")
            return None

        df = self.history_df.copy()
        df['secret_len'] = df['domain'].apply(lambda x: len(str(x)) if x else 0)
        df['domain_len'] = df['domain'].apply(lambda x: len(str(x)) if x else 0)
        df['special_chars'] = df['domain'].apply(lambda x: sum(1 for c in str(x) if not c.isalnum() and c not in '.-'))
        df['numeric_ratio'] = df['domain'].apply(lambda x: sum(1 for c in str(x) if c.isdigit()) / max(len(str(x)), 1))

        X = df[['secret_len', 'domain_len', 'special_chars', 'numeric_ratio']].fillna(0)

        if len(X) < 10:
            print("⚠️ Недостаточно данных для обучения детектора аномалий")
            return None

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        preds = model.predict(X)
        anomalies = np.sum(preds == -1)
        print(f"🔍 Обнаружено {anomalies} аномалий в обучающем наборе")

        with open(MODEL_ANOMALY_FILE, 'wb') as f:
            pickle.dump(model, f)

        self.anomaly_model = model
        return model

    # ─── 4. Классификация источников ────────────────────────────────────────
    def classify_sources(self):
        if self.history_df is None or self.history_df.empty:
            print("⚠️ Нет истории для классификации источников")
            return {}

        stats = {}
        for region in self.history_df['region'].unique():
            region_df = self.history_df[self.history_df['region'] == region]
            good_count = region_df[region_df['ping'] < 1.5].shape[0]
            stats[str(region)] = {
                'total': len(region_df),
                'good_percent': round(good_count / len(region_df) * 100, 2) if len(region_df) > 0 else 0,
                'avg_ping': round(region_df['ping'].mean(), 2) if len(region_df) > 0 else 999,
                'probe_resistant_percent': round(region_df[region_df['probe_resistant']].shape[0] / len(region_df) * 100, 2) if len(region_df) > 0 else 0
            }

        with open(SOURCE_STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)

        print("📊 Классификация источников завершена")
        self.source_stats = stats
        return stats

    # ─── 5. Оптимизация параметров ──────────────────────────────────────────
    def optimize_parameters(self):
        if self.history_df is None or self.history_df.empty:
            print("⚠️ Нет данных для оптимизации параметров")
            return {}

        df = self.history_df
        avg_ping = df['ping'].mean()
        max_ping_recommended = min(max(round(avg_ping * 1.5, 1), 5.0), 10.0)
        timeout_recommended = int(max(avg_ping * 3, 20))
        workers_recommended = 200 if avg_ping < 3 else 150

        rec = {
            'recommended_timeout_mt': timeout_recommended,
            'recommended_max_ping': max_ping_recommended,
            'recommended_workers': workers_recommended,
            'current_avg_ping': round(avg_ping, 2),
            'total_proxies': len(df)
        }

        with open(RECOMMENDATIONS_FILE, 'w', encoding='utf-8') as f:
            f.write(f"Рекомендации по параметрам запуска (на основе {len(df)} проверок):\n")
            f.write(f"- Таймаут MTProto: {timeout_recommended} сек (текущий: 30)\n")
            f.write(f"- Максимальный пинг: {max_ping_recommended} сек (текущий: 5.0)\n")
            f.write(f"- Количество воркеров: {workers_recommended} (текущий: 200)\n")
            f.write(f"\nСредний пинг: {avg_ping:.2f} сек\n")
            f.write(f"Всего прокси в истории: {len(df)}\n")

        print("⚙️ Оптимизация параметров завершена")
        return rec

    # ─── 6. Генерация отчётов ───────────────────────────────────────────────
    def generate_report(self):
        # Получаем рекомендации один раз
        recommendations = self.optimize_parameters() if self.history_df is not None and not self.history_df.empty else {}
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "history_size": len(self.history_df) if self.history_df is not None else 0,
            "source_stats": self.source_stats,
            "model_quality": "available" if MODEL_QUALITY_FILE.exists() else "not trained",
            "model_anomaly": "available" if MODEL_ANOMALY_FILE.exists() else "not trained",
            "recommendations": recommendations,
            "quality_distribution": {}
        }

        if self.history_df is not None and not self.history_df.empty:
            def quality_label(ping):
                if ping < 1.5: return "good"
                elif ping < 5.0: return "medium"
                else: return "bad"
            self.history_df['quality'] = self.history_df['ping'].apply(quality_label)
            report['quality_distribution'] = self.history_df['quality'].value_counts().to_dict()

        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("📄 Отчёт сохранён в", REPORT_FILE)
        return report

    # ─── 7. Парсинг новых источников (упрощённый) ──────────────────────────
    def find_new_sources(self, github_token=None):
        if github_token is None:
            github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            print("⚠️ Нет GitHub токена для поиска новых источников. Пропускаем.")
            return []

        print("🔍 Поиск новых источников на GitHub...")
        headers = {'Authorization': f'token {github_token}'}
        query = "tg://proxy OR tg://socks OR mtproto proxy list"
        url = f"https://api.github.com/search/code?q={query}&per_page=10"

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get('items', [])
                new_urls = []
                for item in items:
                    repo_full_name = item['repository']['full_name']
                    path = item['path']
                    
                    # Пробуем обе основные ветки
                    for branch in ['main', 'master']:
                        raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/{path}"
                        try:
                            content_resp = requests.get(raw_url, timeout=5)
                            if content_resp.status_code == 200:
                                content = content_resp.text
                                if 'tg://proxy' in content or 'tg://socks' in content:
                                    new_urls.append(raw_url)
                                    print(f"  ✅ Найден новый источник: {raw_url}")
                                    break  # Нашли в этой ветке, не ищем дальше
                        except:
                            continue
                
                return new_urls
            else:
                print(f"⚠️ Ошибка GitHub API: {resp.status_code}")
                return []
        except Exception as e:
            print(f"⚠️ Ошибка поиска: {e}")
            return []

    # ─── Запуск всех этапов ──────────────────────────────────────────────────
    def run_all(self, github_token=None):
        print("🧠 Запуск полной ИИ-аналитики...")
        print("=" * 48)

        self.collect_history()
        if self.history_df is None or self.history_df.empty:
            print("⚠️ Недостаточно данных для аналитики. Завершение.")
            return

        self.train_quality_model()
        self.train_anomaly_detector()
        self.classify_sources()
        
        rec = self.optimize_parameters()
        if rec:
            print("📌 Рекомендации:")
            for k, v in rec.items():
                print(f"   {k}: {v}")
        
        self.generate_report()
        new_sources = self.find_new_sources(github_token)
        if new_sources:
            print(f"🔗 Найдено {len(new_sources)} новых источников. Их можно добавить в main.py.")

        print("=" * 48)
        print("✅ Аналитика завершена")


if __name__ == "__main__":
    analytics = ProxyAnalytics()
    github_token = os.environ.get("GITHUB_TOKEN")
    analytics.run_all(github_token=github_token)
