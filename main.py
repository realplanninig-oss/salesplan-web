# File: main.py — веб-приложение Salesplan (тексты в стиле Хакамады)

import logging
import sqlite3
import os
import requests
import uuid
import re
import asyncio
import base64
import secrets
import csv
import io
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn
import pandas as pd

load_dotenv()

# Конфигурация
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

LOGS_DIR = Path("./logs")
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler(LOGS_DIR / "salesplan.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = "salesplan.db"
REPORTS_DIR = Path("./reports")
REPORTS_DIR.mkdir(exist_ok=True)

# Хранилище сессий админа
admin_sessions = {}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, phone TEXT, name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS business_data (user_id TEXT PRIMARY KEY, business_name TEXT, business_description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS forms (user_id TEXT PRIMARY KEY, q1 TEXT, q2 TEXT, q3 TEXT, q4 TEXT, q5 TEXT, q6 TEXT, q7 TEXT, completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, report_type TEXT NOT NULL, report_text TEXT, file_path TEXT, status TEXT DEFAULT 'generating', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ready_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS consultations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, time TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, phone TEXT, yookassa_payment_id TEXT, amount TEXT, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="Salesplan")

# Middleware для защиты от ботов
BLOCKED_PATHS = [
    "/_next", "/api/route", "/app", "/wp-content", "/wp-admin", "/cgi-bin",
    "/.env", "/.git", "/robots.txt", "/api", "/_next/server"
]

@app.middleware("http")
async def block_malicious_requests(request: Request, call_next):
    path = request.url.path
    user_agent = request.headers.get("user-agent", "").lower()
    client_ip = request.client.host if request.client else "unknown"
    
    if path == "/favicon.ico":
        return await call_next(request)
    
    for blocked in BLOCKED_PATHS:
        if path.startswith(blocked):
            logger.warning(f"Blocked malicious path: {path} from {client_ip}")
            return Response(status_code=404)
    
    bad_bots = ["bot", "crawler", "scanner", "nikto", "sqlmap", "wget", "curl", "python-requests", "java"]
    for bot in bad_bots:
        if bot in user_agent and "yandex" not in user_agent and "google" not in user_agent:
            logger.warning(f"Blocked bot: {user_agent} from {client_ip}")
            return Response(status_code=403)
    
    response = await call_next(request)
    return response

security = HTTPBasic()

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Admin not configured")
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# Функции для статистики
def get_admin_stats():
    conn = sqlite3.connect(DB_PATH)
    
    users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    reports_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    consultations_count = conn.execute("SELECT COUNT(*) FROM consultations").fetchone()[0]
    payments_count = conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0]
    payments_succeeded = conn.execute("SELECT COUNT(*) FROM payments WHERE status = 'succeeded'").fetchone()[0]
    payments_total = conn.execute("SELECT SUM(CAST(amount AS REAL)) FROM payments WHERE status = 'succeeded'").fetchone()[0] or 0
    
    daily_stats = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        users_day = conn.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (date,)).fetchone()[0]
        reports_day = conn.execute("SELECT COUNT(*) FROM reports WHERE DATE(created_at) = ?", (date,)).fetchone()[0]
        payments_day = conn.execute("SELECT COUNT(*) FROM payments WHERE DATE(created_at) = ? AND status = 'succeeded'", (date,)).fetchone()[0]
        daily_stats.append({"date": date, "users": users_day, "reports": reports_day, "payments": payments_day})
    
    report_statuses = {
        "ready": conn.execute("SELECT COUNT(*) FROM reports WHERE status = 'ready'").fetchone()[0],
        "generating": conn.execute("SELECT COUNT(*) FROM reports WHERE status = 'generating'").fetchone()[0],
        "failed": conn.execute("SELECT COUNT(*) FROM reports WHERE status = 'failed'").fetchone()[0]
    }
    
    recent_payments = conn.execute("SELECT phone, amount, created_at FROM payments WHERE status = 'succeeded' ORDER BY created_at DESC LIMIT 5").fetchall()
    
    conn.close()
    
    return {
        "total": {
            "users": users_count,
            "reports": reports_count,
            "consultations": consultations_count,
            "payments": payments_count,
            "payments_succeeded": payments_succeeded,
            "revenue": payments_total
        },
        "daily": daily_stats,
        "report_statuses": report_statuses,
        "recent_payments": [{"phone": p[0], "amount": p[1], "date": p[2]} for p in recent_payments]
    }

def get_all_data_for_export():
    conn = sqlite3.connect(DB_PATH)
    users = conn.execute("SELECT * FROM users").fetchall()
    business_data = conn.execute("SELECT * FROM business_data").fetchall()
    forms = conn.execute("SELECT * FROM forms").fetchall()
    reports = conn.execute("SELECT * FROM reports").fetchall()
    consultations = conn.execute("SELECT * FROM consultations").fetchall()
    payments = conn.execute("SELECT * FROM payments").fetchall()
    conn.close()
    return {
        "users": users,
        "business_data": business_data,
        "forms": forms,
        "reports": reports,
        "consultations": consultations,
        "payments": payments
    }

def format_phone(phone: str) -> str:
    if not phone:
        return None
    digits = re.sub(r'\D', '', phone)
    if digits.startswith('7') or digits.startswith('8'):
        digits = '7' + digits[1:]
    if len(digits) == 11 and digits.startswith('7'):
        return '+' + digits
    if len(digits) == 10:
        return '+7' + digits
    return phone

def save_user(user_id: str, phone: str, name: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO users (user_id, phone, name) VALUES (?, ?, ?)", (user_id, phone, name))
    conn.commit()
    conn.close()

def save_business_data(user_id: str, name: str, description: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO business_data (user_id, business_name, business_description) VALUES (?, ?, ?)", (user_id, name, description))
    conn.commit()
    conn.close()

def get_business_data(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT business_name, business_description FROM business_data WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"name": row[0], "description": row[1]}
    return None

def get_form_data(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT q1, q2, q3, q4, q5 FROM forms WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"q1": row[0], "q2": row[1], "q3": row[2], "q4": row[3], "q5": row[4]}
    return None

def save_form(user_id: str, answers: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO forms (user_id, q1, q2, q3, q4, q5, q6, q7) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                 (user_id, answers.get("q1"), answers.get("q2"), answers.get("q3"), answers.get("q4"), answers.get("q5"), answers.get("q6"), answers.get("q7")))
    conn.commit()
    conn.close()

def save_report(user_id: str, report_type: str, report_text: str, file_path: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO reports (user_id, report_type, report_text, file_path, status) VALUES (?, ?, ?, ?, 'ready')", 
                 (user_id, report_type, report_text, file_path))
    conn.commit()
    conn.close()

def update_report_status(report_id: int, status: str, file_path: str = None):
    conn = sqlite3.connect(DB_PATH)
    if status == 'ready':
        conn.execute("UPDATE reports SET status = ?, file_path = ?, ready_at = CURRENT_TIMESTAMP WHERE id = ?", (status, file_path, report_id))
    else:
        conn.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id))
    conn.commit()
    conn.close()

def get_report(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT id, report_text, file_path, status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY created_at DESC LIMIT 1", (user_id, report_type))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "text": row[1], "file_path": row[2], "status": row[3]}
    return None

def save_consultation(user_id: str, time: str, phone: str = None, username: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO consultations (user_id, time) VALUES (?, ?)", (user_id, time))
    conn.commit()
    conn.close()

def save_payment_request(user_id: str, phone: str, payment_id: str = None, amount: str = "490.00", status: str = "pending"):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO payments (user_id, phone, yookassa_payment_id, amount, status) VALUES (?, ?, ?, ?, ?)", 
                 (user_id, phone, payment_id, amount, status))
    conn.commit()
    conn.close()

def update_payment_status(payment_id: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE payments SET status = ? WHERE yookassa_payment_id = ?", (status, payment_id))
    conn.commit()
    conn.close()

def get_payment_by_yookassa_id(payment_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT user_id, phone, amount, status FROM payments WHERE yookassa_payment_id = ? ORDER BY id DESC LIMIT 1", (payment_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"user_id": row[0], "phone": row[1], "amount": row[2], "status": row[3]}
    return None

def get_last_succeeded_payment():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT user_id FROM payments WHERE status = 'succeeded' ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def call_deepseek_diagnostic(name: str, description: str, answers: dict) -> str:
    q1_map = {"Услугу": "Услугу", "Инфопродукт": "Инфопродукт", "Консультацию": "Консультацию", "Пока не продаю": "Пока не продаю"}
    q2_map = {"до 5k": "до 5000 ₽", "5k-20k": "5000-20000 ₽", "20k-50k": "20000-50000 ₽", ">50k": "более 50000 ₽"}
    q3_map = {"<10": "менее 10", "10-50": "10-50", "50-200": "50-200", ">200": "более 200"}
    q4_map = {"300k/мес": "300 000 ₽/мес", "500k/мес": "500 000 ₽/мес", "1M/мес": "1 000 000 ₽/мес", "Масштаб": "масштабирование"}
    q5_map = {"Да": "да", "Нет": "нет", "В разработке": "в разработке"}
    
    survey_info = f"ДАННЫЕ О БИЗНЕСЕ:\n• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}\n• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}\n• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}\n• Цель на 2026: {q4_map.get(answers.get('q4'), 'не указано')}\n• Есть автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}"
    
    if not DEEPSEEK_API_KEY:
        return None
    
    prompt = f"""Сделай профессиональный маркетинговый разбор онлайн-бизнеса.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши отчет в разговорном стиле Вероники. НЕ ИСПОЛЬЗУЙ символы *, #, _, `, ~. Для списков используй просто дефис. Для заголовков используй ЗАГЛАВНЫЕ БУКВЫ.

1. ОБЩАЯ ИНФОРМАЦИЯ (ниша, ЦА, оценка 0-100)
2. АНАЛИЗ (3 сильные стороны, 3 зоны роста)
3. РЕКОМЕНДАЦИИ (3 конкретных шага)"""
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {"model": "deepseek-chat", "messages": [{"role": "system", "content": "Ты Вероника, продюсер экспертов. Говоришь разговорно, с эмодзи, на 'ты'. НИКОГДА не используй символы *, #, _, `, ~. Только обычный текст и эмодзи."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 2000}
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=120)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        return None
    except Exception as e:
        logger.error(f"DeepSeek failed: {e}")
        return None

def generate_premium_report_sync(user_id: str, name: str, description: str, answers: dict, report_id: int):
    logger.info(f"Starting premium report generation for user {user_id}")
    q1_map = {"Услугу": "Услугу", "Инфопродукт": "Инфопродукт", "Консультацию": "Консультацию", "Пока не продаю": "Пока не продаю"}
    q2_map = {"до 5k": "до 5k", "5k-20k": "5k-20k", "20k-50k": "20k-50k", ">50k": ">50k"}
    q3_map = {"<10": "<10", "10-50": "10-50", "50-200": "50-200", ">200": ">200"}
    q4_map = {"300k/мес": "300k/мес", "500k/мес": "500k/мес", "1M/мес": "1M/мес", "Масштаб": "Масштаб"}
    q5_map = {"Да": "да", "Нет": "нет", "В разработке": "в разработке"}
    
    survey_info = f"ДАННЫЕ О БИЗНЕСЕ:\n• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}\n• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}\n• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}\n• Цель: {q4_map.get(answers.get('q4'), 'не указано')}\n• Автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}"
    
    prompt = f"""Сделай профессиональный план запуска продаж для онлайн-бизнеса.

ДАННЫЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши план в разговорном стиле Вероники. НЕ ИСПОЛЬЗУЙ символы *, #, _, `, ~. Для списков используй просто дефис. Для заголовков используй ЗАГЛАВНЫЕ БУКВЫ.

1. ОЦЕНКА СИТУАЦИИ
2. АНАЛИЗ КОНКУРЕНТОВ (3-5 игроков)
3. КОМУ ПРОДАВАТЬ (ЦА)
4. СИЛЬНЫЕ И СЛАБЫЕ СТОРОНЫ
5. ВОРОНКА ПРОДАЖ ШАГ ЗА ШАГОМ
6. ПЛАН ДЕЙСТВИЙ НА МЕСЯЦ"""
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {"model": "deepseek-chat", "messages": [{"role": "system", "content": "Ты Вероника, продюсер экспертов. НИКОГДА не используй символы *, #, _, `, ~. Только обычный текст и эмодзи."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 4000}
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=300)
        if response.status_code == 200:
            report_text = response.json()["choices"][0]["message"]["content"]
            filename = f"premium_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = REPORTS_DIR / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_text)
            update_report_status(report_id, 'ready', str(filepath))
            return True
        else:
            update_report_status(report_id, 'failed')
            return False
    except Exception as e:
        update_report_status(report_id, 'failed')
        logger.error(f"Premium report error: {e}")
        return False

async def generate_premium_report_background(user_id: str, name: str, description: str, answers: dict, report_id: int):
    logger.info(f"Background task started for user {user_id}")
    loop = asyncio.get_event_loop()
    success = await loop.run_in_executor(None, generate_premium_report_sync, user_id, name, description, answers, report_id)
    if success:
        logger.info(f"Premium report generated for user {user_id}")

# HTML шаблоны
HTML_HEAD = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Salesplan</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#fff;color:#1d1d1f}
        .container{max-width:1000px;margin:0 auto;padding:40px 20px}
        .hero{text-align:center;margin-bottom:60px}
        .hero h1{font-size:44px;font-weight:700;margin-bottom:20px;letter-spacing:-0.02em}
        .hero p{font-size:20px;color:#6e6e73}
        .features{display:flex;flex-wrap:wrap;gap:20px;justify-content:center;margin-bottom:60px}
        .feature{flex:1;min-width:200px;background:#fff;border-radius:20px;padding:24px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
        .feature-icon{font-size:36px;margin-bottom:12px}
        .feature h3{font-size:18px;font-weight:600;margin-bottom:8px}
        .feature p{font-size:14px;color:#6e6e73}
        .btn{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;font-size:16px;font-weight:500;border-radius:12px;cursor:pointer;border:none;transition:all 0.2s ease}
        .btn:hover{background:#005fc5;transform:scale(1.02)}
        .btn-outline{background:transparent;border:1px solid #007aff;color:#007aff}
        .btn-outline:hover{background:#007aff10;transform:scale(1.02)}
        .form-card{background:#fff;border-radius:24px;padding:32px;box-shadow:0 4px 12px rgba(0,0,0,0.05);max-width:600px;margin:0 auto}
        .form-group{margin-bottom:24px}
        label{font-size:15px;font-weight:500;display:block;margin-bottom:8px}
        input,textarea{width:100%;padding:12px;font-size:15px;border:1px solid #ccc;border-radius:10px;font-family:inherit}
        .radio-group{display:flex;flex-direction:column;gap:12px;margin-top:8px}
        .radio-group label{display:flex;align-items:center;gap:8px;font-weight:normal;cursor:pointer;padding:8px 12px;background:#f5f5f7;border-radius:12px;transition:background 0.2s}
        .radio-group label:hover{background:#e5e5ea}
        .radio-group input[type="radio"]{width:20px;height:20px;margin:0;cursor:pointer}
        .footer{text-align:center;margin-top:60px;padding-top:24px;border-top:1px solid #e5e5e5;font-size:12px;color:#8e8e93}
        .social-links{margin-top:16px;display:flex;flex-wrap:wrap;justify-content:center;gap:16px}
        .social-links a{color:#007aff;text-decoration:none;font-size:12px}
        hr{margin:30px 0;border:none;border-top:1px solid #e5e5e5}
        .price-old{font-size:20px;color:#8e8e93;text-decoration:line-through}
        .price-new{font-size:36px;font-weight:700;color:#007aff}
        @media (max-width:700px){
            .container{padding:20px 16px}
            .hero h1{font-size:32px}
            .hero p{font-size:16px}
            .form-card{padding:20px}
        }
    </style>
</head>
<body>
<div class="container">
"""
HTML_FOOT = """
    <div class="footer">
        <p>Вероника Макаревич | Продюсер в кармане</p>
        <div class="social-links">
            <a href="https://max.ru/id781407988795_biz">MAX-канал</a>
            <a href="https://vk.ru/makarevichveronika">ВКонтакте</a>
        </div>
        <p>© 2026 Все права защищены</p>
    </div>
</div>
</body>
</html>"""

def render_page(content: str):
    return HTML_HEAD + content + HTML_FOOT

def render_waiting_page(user_id: str, report_type: str, redirect_url: str):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Анализируем рынок | Salesplan</title>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#fff;color:#1d1d1f}}
        .container{{max-width:600px;margin:0 auto;padding:60px 20px;text-align:center}}
        .spinner{{width:50px;height:50px;border:4px solid #e5e5e5;border-top-color:#007aff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}
        @keyframes spin{{to{{transform:rotate(360deg)}}}}
        .progress-bar{{width:100%;height:8px;background:#e5e5e5;border-radius:4px;margin:30px 0;overflow:hidden}}
        .progress-fill{{width:0%;height:100%;background:#007aff;border-radius:4px;transition:width 0.5s ease}}
        .status-item{{display:flex;align-items:center;justify-content:center;gap:10px;margin:15px 0;padding:10px;border-radius:12px;background:#f5f5f7}}
        .status-item.active{{background:#007aff10;border-left:3px solid #007aff}}
        .timer{{font-size:24px;font-weight:600;color:#007aff;margin:20px 0}}
        .subtext{{font-size:14px;color:#8e8e93;margin-top:20px}}
    </style>
    <script>
        let attempts = 0;
        let isRedirected = false;
        let startTime = Date.now();
        
        function updateProgress() {{
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const timerEl = document.getElementById('timer');
            if (timerEl) timerEl.textContent = elapsed;
            const progress = Math.min(90, Math.floor(elapsed / 35 * 100));
            const fillEl = document.getElementById('progressFill');
            if (fillEl) fillEl.style.width = progress + '%';
        }}
        
        function checkStatus() {{
            if (isRedirected) return;
            fetch('/check_status?user_id={user_id}&report_type={report_type}')
                .then(res => res.json())
                .then(data => {{
                    if (data.ready) {{
                        isRedirected = true;
                        window.location.href = '{redirect_url}';
                    }} else {{
                        attempts++;
                        updateProgress();
                        if (attempts < 120) setTimeout(checkStatus, 3000);
                    }}
                }})
                .catch(() => setTimeout(checkStatus, 3000));
        }}
        
        setTimeout(checkStatus, 1000);
        setInterval(updateProgress, 1000);
    </script>
</head>
<body>
<div class="container">
    <div class="spinner"></div>
    <h1>🔍 Анализируем конкурентов и рынок</h1>
    <div class="timer" id="timer">0</div>
    <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
    <p class="subtext">Пока нейросеть копается в вашей нише — это займёт 1-2 минуты. Страница обновится сама.</p>
</div>
</body>
</html>"""

# ==================== АДМИН-ПАНЕЛЬ ====================

def check_admin_session(session_token: str = Cookie(None)):
    if not session_token or session_token not in admin_sessions:
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    session = admin_sessions[session_token]
    if datetime.now() > session["expires_at"]:
        del admin_sessions[session_token]
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    return True

@app.get("/admin/login")
async def admin_login_page():
    content = """
    <div class="hero"><h1>🔐 Вход в админ-панель</h1></div>
    <div class="form-card">
        <form action="/admin/login" method="post">
            <div class="form-group"><label>👤 Логин</label><input type="text" name="username" required></div>
            <div class="form-group"><label>🔒 Пароль</label><input type="password" name="password" required></div>
            <button type="submit" class="btn" style="width:100%">Войти</button>
        </form>
    </div>
    """
    return HTMLResponse(content=render_page(content))

@app.post("/admin/login")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session_token = secrets.token_urlsafe(32)
        admin_sessions[session_token] = {"username": username, "created_at": datetime.now(), "expires_at": datetime.now() + timedelta(hours=1)}
        response = RedirectResponse(url="/admin/dashboard", status_code=303)
        response.set_cookie(key="admin_session", value=session_token, httponly=True, max_age=3600)
        return response
    content = '<div class="hero"><h1>❌ Неверный логин или пароль</h1></div><div style="text-align:center"><a href="/admin/login" class="btn">Попробовать снова</a></div>'
    return HTMLResponse(content=render_page(content))

@app.get("/admin/dashboard")
async def admin_dashboard(auth: bool = Depends(check_admin_session)):
    stats = get_admin_stats()
    content = f"""
    <style>
        .admin-header{{display:flex;justify-content:space-between;margin-bottom:30px}}
        .admin-stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:40px}}
        .stat-card{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:20px;border-radius:16px;text-align:center}}
        .stat-number{{font-size:36px;font-weight:bold}}
        .admin-section{{background:#f5f5f7;border-radius:16px;padding:20px;margin-bottom:30px}}
        .status-ready{{background:#34c759;color:white;padding:4px 12px;border-radius:12px}}
        .status-generating{{background:#ff9f0a;color:white;padding:4px 12px;border-radius:12px}}
        .status-failed{{background:#ff3b30;color:white;padding:4px 12px;border-radius:12px}}
        table{{width:100%;border-collapse:collapse}}
        th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd}}
        th{{background:#007aff;color:white}}
        .btn-small{{padding:8px 16px;font-size:14px;margin:5px}}
    </style>
    <div class="admin-header"><h1>📊 Админ-панель Salesplan</h1><div><a href="/admin/logs" class="btn btn-small">📋 Логи</a><a href="/admin/logout" class="btn btn-small btn-outline">🚪 Выйти</a></div></div>
    <div class="admin-stats">
        <div class="stat-card"><h3>👥 Пользователей</h3><div class="stat-number">{stats['total']['users']}</div></div>
        <div class="stat-card"><h3>📄 Отчетов</h3><div class="stat-number">{stats['total']['reports']}</div></div>
        <div class="stat-card"><h3>💰 Платежей</h3><div class="stat-number">{stats['total']['payments_succeeded']}</div><div>{stats['total']['revenue']:,.0f} ₽</div></div>
        <div class="stat-card"><h3>📞 Консультаций</h3><div class="stat-number">{stats['total']['consultations']}</div></div>
    </div>
    <div class="admin-section"><h2>📊 Статусы отчетов</h2><table><thead><tr><th>Статус</th><th>Количество</th></tr></thead><tbody>
    <tr><td><span class="status-ready">✅ Готово</span></td><td>{stats['report_statuses']['ready']}</td></tr>
    <tr><td><span class="status-generating">⚙️ Генерация</span></td><td>{stats['report_statuses']['generating']}</td></tr>
    <tr><td><span class="status-failed">❌ Ошибка</span></td><td>{stats['report_statuses']['failed']}</td></tr>
    </tbody></table></div>
    <div class="admin-section"><h2>💳 Последние платежи</h2><table><thead><tr><th>Телефон</th><th>Сумма</th><th>Дата</th></tr></thead><tbody>
    {''.join([f"<tr><td>{p['phone']}</td><td>{p['amount']} ₽</td><td>{p['date']}</td></tr>" for p in stats['recent_payments']])}
    </tbody></table></div>
    <div class="export-buttons" style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px">
        <a href="/admin/export/excel" class="btn btn-small">📊 Скачать Excel</a>
        <a href="/admin/export/csv" class="btn btn-small">📄 Скачать CSV</a>
    </div>
    """
    return HTMLResponse(content=render_page(content))

@app.get("/admin/export/excel")
async def export_excel(auth: bool = Depends(check_admin_session)):
    data = get_all_data_for_export()
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame(data['users'], columns=['user_id', 'phone', 'name', 'created_at']).to_excel(writer, sheet_name='Пользователи', index=False)
        pd.DataFrame(data['business_data'], columns=['user_id', 'business_name', 'business_description', 'created_at']).to_excel(writer, sheet_name='Бизнес данные', index=False)
        pd.DataFrame(data['forms'], columns=['user_id', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'completed_at']).to_excel(writer, sheet_name='Опросы', index=False)
        pd.DataFrame(data['reports'], columns=['id', 'user_id', 'report_type', 'report_text', 'file_path', 'status', 'created_at', 'ready_at']).to_excel(writer, sheet_name='Отчеты', index=False)
        pd.DataFrame(data['consultations'], columns=['id', 'user_id', 'time', 'created_at']).to_excel(writer, sheet_name='Консультации', index=False)
        pd.DataFrame(data['payments'], columns=['id', 'user_id', 'phone', 'yookassa_payment_id', 'amount', 'status', 'created_at']).to_excel(writer, sheet_name='Платежи', index=False)
    output.seek(0)
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment; filename=salesplan_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"})

@app.get("/admin/export/csv")
async def export_csv(auth: bool = Depends(check_admin_session)):
    data = get_all_data_for_export()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['=== ПОЛЬЗОВАТЕЛИ ==='])
    writer.writerow(['user_id', 'phone', 'name', 'created_at'])
    writer.writerows(data['users'])
    writer.writerow([])
    writer.writerow(['=== ПЛАТЕЖИ ==='])
    writer.writerow(['id', 'user_id', 'phone', 'amount', 'status', 'created_at'])
    writer.writerows([[p[0], p[1], p[2], p[4], p[5], p[6]] for p in data['payments']])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue().encode('utf-8-sig')]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=salesplan_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"})

@app.get("/admin/logs")
async def admin_logs(auth: bool = Depends(check_admin_session)):
    try:
        with open(LOGS_DIR / "salesplan.log", "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]
            content = "".join(lines)
            html = f'<div class="admin-header"><h1>📋 Логи</h1><div><a href="/admin/dashboard" class="btn btn-small">← Назад</a><a href="/admin/logout" class="btn btn-small btn-outline">Выйти</a></div></div><pre style="background:#1e1e1e;color:#d4d4d4;padding:20px;border-radius:8px;overflow-x:auto;max-height:600px">{content}</pre>'
            return HTMLResponse(content=render_page(html))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.delete_cookie("admin_session")
    return response

# ==================== ОСНОВНЫЕ ЭНДПОИНТЫ ====================

@app.get("/")
async def index():
    content = '''
<div class="hero"><h1>Вероника Макаревич | Продюсер в кармане</h1><p>«Я не волшебник, я практик. За моими плечами 33 эксперта, которые перестали ныть и начали продавать.»</p></div>
<div class="features">
    <div class="feature"><div class="feature-icon">⭐️</div><h3>Бесплатный аудит — 2 минуты</h3><p>Узнайте 3 конкретных шага для роста</p></div>
    <div class="feature"><div class="feature-icon">🔥</div><h3>Готовая стратегия — 5 минут</h3><p>План продаж с анализом конкурентов</p></div>
    <div class="feature"><div class="feature-icon">⚡️</div><h3>Первое действие — 15 минут</h3><p>Внедрите работающее решение</p></div>
</div>
<div style="text-align:center"><a href="/survey" class="btn">Начать диагностику</a></div>
'''
    return HTMLResponse(content=render_page(content))

@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<div class="hero"><h1>Шаг 1 из 2. Давайте знакомиться</h1><p>«Чем честнее ответите — тем точнее будет разбор.»</p></div>
<div class="form-card">
    <form action="/survey/submit" method="post" id="surveyForm">
        <div class="form-group"><label>1. Название бизнеса</label><input type="text" name="business_name" required></div>
        <div class="form-group"><label>2. Короткое описание</label><textarea name="business_description" rows="3" required></textarea></div>
        <div class="form-group"><label>3. Что вы продаёте?</label><div class="radio-group"><label><input type="radio" name="q1" value="Услугу" required> Услугу</label><label><input type="radio" name="q1" value="Инфопродукт"> Инфопродукт</label><label><input type="radio" name="q1" value="Консультацию"> Консультацию</label><label><input type="radio" name="q1" value="Пока не продаю"> Пока не продаю</label></div></div>
        <div class="form-group"><label>4. Средний чек (₽)</label><div class="radio-group"><label><input type="radio" name="q2" value="до 5k" required> до 5k</label><label><input type="radio" name="q2" value="5k-20k"> 5k-20k</label><label><input type="radio" name="q2" value="20k-50k"> 20k-50k</label><label><input type="radio" name="q2" value=">50k"> >50k</label></div></div>
        <div class="form-group"><label>5. Клиентов в месяц</label><div class="radio-group"><label><input type="radio" name="q3" value="<10" required> меньше 10</label><label><input type="radio" name="q3" value="10-50"> 10-50</label><label><input type="radio" name="q3" value="50-200"> 50-200</label><label><input type="radio" name="q3" value=">200"> более 200</label></div></div>
        <div class="form-group"><label>6. Цель на 2026</label><div class="radio-group"><label><input type="radio" name="q4" value="300k/мес" required> 300k/мес</label><label><input type="radio" name="q4" value="500k/мес"> 500k/мес</label><label><input type="radio" name="q4" value="1M/мес"> 1M/мес</label><label><input type="radio" name="q4" value="Масштаб"> Масштаб</label></div></div>
        <div class="form-group"><label>7. Уже есть автоворонка?</label><div class="radio-group"><label><input type="radio" name="q5" value="Да" required> Да</label><label><input type="radio" name="q5" value="Нет"> Нет</label><label><input type="radio" name="q5" value="В разработке"> В разработке</label></div></div>
        <button type="submit" class="btn" style="width:100%">Получить диагностику</button>
    </form>
</div>
"""
    return HTMLResponse(content=render_page(content))

@app.post("/survey/submit")
async def survey_submit(
    business_name: str = Form(...),
    business_description: str = Form(...),
    q1: str = Form(...),
    q2: str = Form(...),
    q3: str = Form(...),
    q4: str = Form(...),
    q5: str = Form(...)
):
    user_id = str(uuid.uuid4())
    logger.info(f"New survey: user_id={user_id}")
    save_user(user_id, None, None)
    save_business_data(user_id, business_name, business_description)
    save_form(user_id, {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5})
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'free', 'generating')", (user_id,))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    async def generate_and_save():
        loop = asyncio.get_event_loop()
        diagnostic_text = await loop.run_in_executor(None, call_deepseek_diagnostic, business_name, business_description, {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5})
        conn = sqlite3.connect(DB_PATH)
        if diagnostic_text:
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (diagnostic_text, report_id))
        else:
            fallback = f"Диагностика для бизнеса \"{business_name}\"\n\nРекомендации:\n- Проанализируйте ЦА\n- Настройте воронку\n- Добавьте призывы к действию"
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (fallback, report_id))
        conn.commit()
        conn.close()
    
    asyncio.create_task(generate_and_save())
    return HTMLResponse(content=render_waiting_page(user_id, "free", f"/diagnostic?user_id={user_id}"))

@app.get("/check_status")
async def check_status(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    return {"ready": row and row[0] == 'ready'}

@app.get("/diagnostic", response_class=HTMLResponse)
async def diagnostic(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT report_text FROM reports WHERE user_id = ? AND report_type = 'free' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not row or not row[0]:
        return HTMLResponse(content=render_waiting_page(user_id, "free", f"/diagnostic?user_id={user_id}"))
    
    report_text_html = row[0].replace("\n", "<br>")
    content = f'''
<div class="hero"><h1>✨ Ваша персональная диагностика готова</h1></div>
<div class="form-card">
    <div style="background:#f5f5f7;border-radius:20px;padding:20px;margin:20px 0;max-height:500px;overflow-y:auto"><div style="white-space:pre-wrap">{report_text_html}</div></div>
    <hr>
    <div class="price-old">4 900 ₽</div>
    <div class="price-new">490 ₽</div>
    <form action="/payment/create" method="post"><input type="hidden" name="user_id" value="{user_id}"><button type="submit" class="btn" style="width:100%">🔥 Забрать план за 490 ₽</button></form>
</div>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/payment/create")
async def payment_create(user_id: str = Form(...)):
    return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)

@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str):
    content = f'''
<div class="hero"><h1>💰 План продаж — 490 ₽</h1></div>
<div class="form-card">
    <form action="/create_yookassa_payment" method="post">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group"><label>📞 Телефон</label><input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required></div>
        <button type="submit" class="btn" style="width:100%">💳 Оплатить 490 ₽</button>
    </form>
</div>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/create_yookassa_payment")
async def create_yookassa_payment(request: Request, user_id: str = Form(...), phone: str = Form(...)):
    phone = format_phone(phone)
    save_user(user_id, phone, None)
    save_payment_request(user_id, phone, None, "490.00", "pending")
    # Для теста просто показываем успех
    return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)

@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str):
    biz = get_business_data(user_id)
    answers = get_form_data(user_id)
    premium_text = f"""ПРОФЕССИОНАЛЬНЫЙ МАРКЕТИНГОВЫЙ ПЛАН

Данные о бизнесе:
Название: {biz['name'] if biz else 'Не указано'}
Описание: {biz['description'] if biz else 'Не указано'}

Рекомендации для увеличения продаж:
1. Проанализируйте целевую аудиторию
2. Настройте автоворонку
3. Добавьте триггерные сообщения
"""
    save_report(user_id, "premium", premium_text)
    report_text_html = premium_text.replace("\n", "<br>")
    content = f'''
<div class="hero"><h1>🎉 План готов!</h1></div>
<div class="form-card"><div style="background:#f5f5f7;border-radius:20px;padding:20px"><div style="white-space:pre-wrap">{report_text_html}</div></div></div>
'''
    return HTMLResponse(content=render_page(content))

@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str):
    content = f'''
<div class="hero"><h1>🔥 Бесплатная консультация</h1></div>
<div class="form-card">
    <form action="/consultation/submit" method="post">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group"><label>📞 Телефон</label><input type="tel" name="phone" required></div>
        <div class="form-group"><label>🕐 Удобное время</label><input type="text" name="time" placeholder="например: завтра в 15:00" required></div>
        <button type="submit" class="btn" style="width:100%">📅 Записаться</button>
    </form>
</div>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/consultation/submit")
async def consultation_submit(user_id: str = Form(...), time: str = Form(...), phone: str = Form(None)):
    save_consultation(user_id, time, phone, None)
    return RedirectResponse(url=f"/subscribe?user_id={user_id}", status_code=303)

@app.get("/subscribe", response_class=HTMLResponse)
async def subscribe_page(user_id: str):
    content = f'''
<div class="hero"><h1>🤝 Остался последний шаг</h1></div>
<div class="form-card" style="text-align:center">
    <a href="https://max.ru/id781407988795_biz" target="_blank" class="btn" style="width:100%">📢 Подписаться на канал в MAX</a>
    <hr style="margin:20px 0">
    <p>После подписки я свяжусь с вами для согласования времени</p>
    <a href="/" class="btn-outline" style="display:inline-block;margin-top:20px">→ На главную</a>
</div>
'''
    return HTMLResponse(content=render_page(content))

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
