#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI Analytics v2.0 — полная аналитика прокси
# - Читает и списки, и словари
# - Двухклассовая модель (good/bad) с кросс-валидацией
# - Тренды относительно прошлого запуска
# - Аномалии в отдельный файл
# - Динамические пороги по медиане
# - Рекомендации по таймауту/воркерам/max_ping

import os
import json
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

# ------------------ ПУТИ ------------------
DATA_DIR = Path("data")
VERIFIED_DIR = Path("verified")
REPORTS_DIR = Path("reports")
HISTORY_FILE = DATA_DIR / "proxy_history.json"
PREV_REPORT_FILE = REPORTS_DIR / "analytics_report.json"
REPORT_FILE = REPORTS_DIR / "analytics_report.json"
ANOMALIES_FILE = REPORTS_DIR / "anomalies.json"
LOG_FILE = REPORTS_DIR / "analytics.log"

DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ------------------ ЛОГИРОВАНИЕ ------------------
def log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ------------------ ЗАГРУЗКА ------------------
def _extract_proxy_list(obj):
    """Достаёт список прокси из list/dict любой вложенности."""
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        # частые ключи
        for key in ("proxies", "items", "data", "results", "all", "list"):
            if key in obj and isinstance(obj[key], list):
                return [x for x in obj[key] if isinstance(x, dict)]
        # если это один прокси — оборачиваем
        if "host" in obj and "port" in obj:
            return [obj]
    return []

def collect_history_from_verified():
    """Обходит verified/ и собирает все прокси в один список."""
    history = []
    if not VERIFIED_DIR.exists():
        log(f"⚠️ Папка {VERIFIED_DIR} не найдена")
        return history

    for f in sorted(VERIFIED_DIR.glob("*.json")):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            items = _extract_proxy_list(data)
            if items:
                history.extend(items)
                log(f"  ✓ {f.name}: +{len(items)}")
            else:
                log(f"  ⚠️ {f.name}: не содержит список, пропускаем")
        except json.JSONDecodeError as e:
            log(f"  ✗ {f.name}: JSON ошибка — {e}")
        except Exception as e:
            log(f"  ✗ {f.name}: {e}")
    return history

def load_history():
    """Приоритет — накопленная история, fallback — verified/."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            items = _extract_proxy_list(data)
            if items:
                log(f"✅ Загружено {len(items)} записей из {HISTORY_FILE}")
                return items
        except Exception as e:
            log(f"⚠️ Не удалось прочитать {HISTORY_FILE}: {e}")

    log("📊 Сбор истории из verified/...")
    items = collect_history_from_verified()
    # сохраняем на будущее
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
        log(f"✅ Сохранено {len(items)} записей в историю")
    except Exception as e:
        log(f"⚠️ Не удалось сохранить историю: {e}")
    return items

def load_prev_report():
    if PREV_REPORT_FILE.exists():
        try:
            with open(PREV_REPORT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

# ------------------ МЕТРИКИ ------------------
def compute_metrics(history):
    pings = [p.get("ping") for p in history if isinstance(p.get("ping"), (int, float))]
    if not pings:
        return {}
    median_ping = statistics.median(pings)
    mean_ping = statistics.mean(pings)
    stdev_ping = statistics.pstdev(pings) if len(pings) > 1 else 0.0
    # динамические пороги
    good_thr = median_ping
    bad_thr = median_ping * 2.5

    good = sum(1 for x in pings if x <= good_thr)
    medium = sum(1 for x in pings if good_thr < x <= bad_thr)
    bad = sum(1 for x in pings if x > bad_thr)

    regions = Counter(p.get("region", "unknown") for p in history)
    types = Counter(p.get("type", "mtproto") for p in history)

    return {
        "total": len(history),
        "pings_count": len(pings),
        "median_ping": round(median_ping, 3),
        "mean_ping": round(mean_ping, 3),
        "stdev_ping": round(stdev_ping, 3),
        "good_thr": round(good_thr, 3),
        "bad_thr": round(bad_thr, 3),
        "good": good,
        "medium": medium,
        "bad": bad,
        "regions": dict(regions),
        "types": dict(types),
    }

# ------------------ ОБУЧЕНИЕ МОДЕЛИ ------------------
def build_dataset(history):
    """X — фичи, y — метка (1=good, 0=bad) по динамическому порогу."""
    rows = []
    pings = [p.get("ping") for p in history if isinstance(p.get("ping"), (int, float))]
    if not pings:
        return None, None, None
    median_ping = statistics.median(pings)
    threshold = median_ping * 1.5

    for p in history:
        ping = p.get("ping")
        if not isinstance(ping, (int, float)):
            continue
        region = p.get("region", "unknown")
        typ = p.get("type", "mtproto")
        rows.append({
            "ping": ping,
            "region_ru": 1 if region == "ru" else 0,
            "region_eu": 1 if region == "eu" else 0,
            "region_us": 1 if region == "us" else 0,
            "region_asia": 1 if region == "asia" else 0,
            "is_mtproto": 1 if typ == "mtproto" else 0,
            "is_socks5": 1 if typ == "socks5" else 0,
            "label": 1 if ping <= threshold else 0,
        })
    if not rows:
        return None, None, None
    X = np.array([[r[k] for k in r if k != "label"] for r in rows], dtype=float)
    y = np.array([r["label"] for r in rows], dtype=int)
    return X, y, threshold

def train_quality_model(history):
    if not SKLEARN_OK:
        log("⚠️ sklearn не установлен — пропускаем обучение")
        return None, {}

    X, y, threshold = build_dataset(history)
    if X is None or len(X) < 10:
        log("⚠️ Слишком мало данных для обучения")
        return None, {}

    if len(set(y)) < 2:
        log(f"⚠️ В обучающем наборе только один класс (label={set(y)}). Модель обучена условно.")
        # всё равно обучим, чтобы не падать
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model, {"accuracy": 1.0, "note": "single-class"}

    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    cv = StratifiedKFold(n_splits=min(5, len(set(y)) * 2), shuffle=True, random_state=42)
    try:
        scores = cross_val_score(model, X, y, cv=cv, scoring="f1")
        cv_f1 = round(float(scores.mean()), 4)
    except Exception as e:
        log(f"⚠️ Кросс-валидация не удалась: {e}")
        cv_f1 = None

    model.fit(X, y)
    y_pred = model.predict(X)
    report = classification_report(y, y_pred, output_dict=True, zero_division=0)
    log(f"✅ Модель качества обучена. CV F1: {cv_f1}")
    log(classification_report(y, y_pred, zero_division=0))
    return model, {"cv_f1": cv_f1, "report": report, "threshold": threshold}

# ------------------ АНОМАЛИИ ------------------
def detect_anomalies(history):
    if not SKLEARN_OK:
        return []
    rows = []
    for p in history:
        ping = p.get("ping")
        if not isinstance(ping, (int, float)):
            continue
        rows.append([
            ping,
            1 if p.get("region") == "ru" else 0,
            1 if p.get("type") == "mtproto" else 0,
        ])
    if len(rows) < 20:
        return []
    X = np.array(rows, dtype=float)
    iso = IsolationForest(contamination=0.05, random_state=42)
    preds = iso.fit_predict(X)
    anomalies = []
    for p, pred in zip(history, preds):
        if pred == -1:
            anomalies.append(p)
    log(f"🔍 Обнаружено {len(anomalies)} аномалий")
    return anomalies

# ------------------ РЕКОМЕНДАЦИИ ------------------
def make_recommendations(metrics, prev_report):
    rec = {
        "recommended_timeout_mt": 10,
        "recommended_max_ping": 3.0,
        "recommended_workers": 100,
    }
    if not metrics:
        return rec

    median = metrics.get("median_ping", 0.5)
    stdev = metrics.get("stdev_ping", 0.0)
    total = metrics.get("total", 0)

    # max_ping: медиана + 2*sigma, но не меньше 1.5 и не больше 8
    max_ping = median + 2 * stdev
    max_ping = max(1.5, min(8.0, round(max_ping, 2)))

    # timeout: если сеть шумная — больше, иначе 8-10
    timeout = 8 if stdev < 0.5 else 12 if stdev < 1.5 else 20

    # workers: 50..300 в зависимости от объёма
    workers = 50 if total < 100 else 100 if total < 300 else 200 if total < 800 else 300

    rec.update({
        "recommended_timeout_mt": int(timeout),
        "recommended_max_ping": float(max_ping),
        "recommended_workers": int(workers),
        "current_avg_ping": round(metrics.get("mean_ping", 0.0), 3),
        "current_median_ping": round(median, 3),
        "current_stdev_ping": round(stdev, 3),
        "total_proxies": total,
    })

    # тренд
    if prev_report:
        prev_median = prev_report.get("metrics", {}).get("median_ping")
        if isinstance(prev_median, (int, float)) and prev_median > 0:
            delta = median - prev_median
            rec["trend_median_ping"] = round(delta, 3)
            rec["trend_direction"] = "better" if delta < -0.05 else "worse" if delta > 0.05 else "stable"
    return rec

# ------------------ ОТЧЁТ ------------------
def save_report(metrics, rec, anomalies, model_info):
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "recommendations": rec,
        "anomalies_count": len(anomalies),
        "model": model_info,
    }
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log(f"📄 Отчёт сохранён в {REPORT_FILE}")
    except Exception as e:
        log(f"⚠️ Не удалось сохранить отчёт: {e}")

    if anomalies:
        try:
            with open(ANOMALIES_FILE, "w", encoding="utf-8") as f:
                json.dump(anomalies, f, indent=2, ensure_ascii=False)
            log(f"📄 Аномалии сохранены в {ANOMALIES_FILE}")
        except Exception as e:
            log(f"⚠️ Не удалось сохранить аномалии: {e}")

# ------------------ MAIN ------------------
def main():
    log("🧠 Запуск полной ИИ-аналитики...")
    log("=" * 48)

    history = load_history()
    if not history:
        log("⚠️ Нет данных для анализа. Завершение.")
        return

    prev_report = load_prev_report()
    metrics = compute_metrics(history)
    log(f"📊 Метрики: total={metrics.get('total')}, "
        f"median={metrics.get('median_ping')}s, "
        f"mean={metrics.get('mean_ping')}s, "
        f"stdev={metrics.get('stdev_ping')}s")

    # модель качества
    model, model_info = train_quality_model(history)

    # аномалии
    anomalies = detect_anomalies(history)

    # рекомендации
    rec = make_recommendations(metrics, prev_report)
    log("📌 Рекомендации:")
    for k, v in rec.items():
        log(f"   {k}: {v}")

    # сохранение
    save_report(metrics, rec, anomalies, model_info)

    if not os.environ.get("GITHUB_TOKEN"):
        log("⚠️ Нет GitHub токена для поиска новых источников. Пропускаем.")

    log("=" * 48)
    log("✅ Аналитика завершена")

if __name__ == "__main__":
    main()
