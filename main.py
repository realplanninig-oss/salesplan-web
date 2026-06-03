# File: main.py — веб-приложение Salesplan (финальная версия с обновлёнными лендингами, подвалом, чекбоксами и стилем Apple+Хакамада)

import logging
import sqlite3
import os
import requests
import uuid
import re
import asyncio
import base64
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn

load_dotenv()

# === ДИАГНОСТИКА ПРИ ЗАПУСКЕ ===
print("=" * 60)
print("ENVIRONMENT VARIABLES CHECK - Salesplan Web")
print("=" * 60)
print(f"DEEPSEEK_API_KEY: {'✓ SET' if os.getenv('DEEPSEEK_API_KEY') else '✗ MISSING'}")
print(f"YOOKASSA_SHOP_ID: {os.getenv('YOOKASSA_SHOP_ID', '✗ MISSING')}")
print(f"YOOKASSA_SECRET_KEY: {'✓ SET' if os.getenv('YOOKASSA_SECRET_KEY') else '✗ MISSING'}")
print(f"ADMIN_USERNAME: {os.getenv('ADMIN_USERNAME', 'admin')}")
print(f"ADMIN_PASSWORD: {'✓ SET' if os.getenv('ADMIN_PASSWORD') else '✗ MISSING'}")
print(f"PORT: {os.getenv('PORT', '8000')}")
print("=" * 60)

# === КОНФИГУРАЦИЯ ===
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
MAX_BOT_TOKEN = os.getenv("MAX_BOT_TOKEN")
ADMIN_CHANNEL_ID = os.getenv("ADMIN_CHANNEL_ID")

missing_vars = []
if not DEEPSEEK_API_KEY:
    missing_vars.append("DEEPSEEK_API_KEY")
if not YOOKASSA_SHOP_ID:
    missing_vars.append("YOOKASSA_SHOP_ID")
if not YOOKASSA_SECRET_KEY:
    missing_vars.append("YOOKASSA_SECRET_KEY")

if missing_vars:
    print(f"⚠️ WARNING: Missing environment variables: {missing_vars}")

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

logger.info("=" * 50)
logger.info("APPLICATION STARTING WITH CONFIGURATION:")
logger.info(f"DEEPSEEK_API_KEY: {'✓ SET' if DEEPSEEK_API_KEY else '✗ MISSING'}")
logger.info(f"YOOKASSA_SHOP_ID: {YOOKASSA_SHOP_ID if YOOKASSA_SHOP_ID else '✗ MISSING'}")
logger.info(f"YOOKASSA_SECRET_KEY: {'✓ SET' if YOOKASSA_SECRET_KEY else '✗ MISSING'}")
logger.info("=" * 50)

DB_PATH = "salesplan.db"
REPORTS_DIR = Path("./reports")
REPORTS_DIR.mkdir(exist_ok=True)

# === БАЗА ДАННЫХ ===
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, phone TEXT, name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS business_data (user_id TEXT PRIMARY KEY, business_name TEXT, business_description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS forms (user_id TEXT PRIMARY KEY, q1 TEXT, q2 TEXT, q3 TEXT, q4 TEXT, q5 TEXT, q6 TEXT, q7 TEXT, completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, report_type TEXT NOT NULL, report_text TEXT, file_path TEXT, status TEXT DEFAULT 'generating', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ready_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS consultations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, phone TEXT, time TEXT, question TEXT, status TEXT DEFAULT 'new', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, phone TEXT, yookassa_payment_id TEXT, amount INTEGER, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_date TEXT NOT NULL,
            user_id TEXT,
            ip TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_consents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            consent_type TEXT NOT NULL,
            consent_given_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    try:
        conn.execute("ALTER TABLE reports ADD COLUMN paid_at TIMESTAMP")
        logger.info("Added paid_at column to reports table")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="Salesplan Web")

# === MIDDLEWARE ===
BLOCKED_PATHS = [
    "/_next", "/api/route", "/app", "/wp-content", "/wp-admin", "/cgi-bin",
    "/.env", "/.git", "/robots.txt", "/api", "/_next/server"
]

@app.middleware("http")
async def track_and_block_requests(request: Request, call_next):
    path = request.url.path
    user_agent = request.headers.get("user-agent", "").lower()
    client_ip = request.client.host if request.client else "unknown"
    if path in ["/", "/survey", "/diagnostic", "/payment", "/payment/success", "/launch-online-school", "/funnel-7-days", "/consultation", "/subscribe"]:
        track_visit(ip=client_ip, user_agent=user_agent)
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

# === ФУНКЦИИ ДЛЯ ОТСЛЕЖИВАНИЯ ПОСЕЩЕНИЙ ===
def track_visit(user_id=None, ip=None, user_agent=None):
    conn = sqlite3.connect(DB_PATH)
    today = datetime.now().strftime('%Y-%m-%d')
    if ip:
        cursor = conn.execute("SELECT id FROM visits WHERE ip = ? AND visit_date = ? LIMIT 1", (ip, today))
        if not cursor.fetchone():
            conn.execute("INSERT INTO visits (visit_date, ip, user_agent) VALUES (?, ?, ?)",
                         (today, ip, user_agent[:500] if user_agent else None))
    conn.commit()
    conn.close()

def get_unique_visitors(days=7):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT visit_date, COUNT(DISTINCT ip) as unique_visitors, COUNT(*) as total_visits
        FROM visits WHERE visit_date >= date('now', ?) GROUP BY visit_date ORDER BY visit_date DESC
    """, (f'-{days} days',))
    results = [{"date": r[0], "visitors": r[1], "total_visits": r[2]} for r in cursor.fetchall()]
    conn.close()
    return results

def get_sales_funnel_stats(days=7):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT date(created_at) as date,
        COUNT(DISTINCT CASE WHEN status = 'succeeded' THEN user_id END) as payments,
        SUM(CASE WHEN status = 'succeeded' THEN amount ELSE 0 END) as revenue
        FROM payments WHERE created_at >= date('now', ?) GROUP BY date(created_at) ORDER BY date DESC
    """, (f'-{days} days',))
    results = [{"date": r[0], "payments": r[1], "revenue": r[2]} for r in cursor.fetchall()]
    conn.close()
    return results

def get_free_diagnostics_stats(days=7):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT date(completed_at) as date, COUNT(*) as total
        FROM forms WHERE completed_at >= date('now', ?) GROUP BY date(completed_at) ORDER BY date DESC
    """, (f'-{days} days',))
    results = [{"date": d[0], "diagnostics": d[1]} for d in cursor.fetchall()]
    conn.close()
    return results

def get_report_downloads_stats(days=7):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT date(ready_at) as date, COUNT(*) as downloads
        FROM reports WHERE report_type = 'premium' AND status = 'ready' AND ready_at >= date('now', ?)
        GROUP BY date(ready_at) ORDER BY date DESC
    """, (f'-{days} days',))
    results = [{"date": d[0], "downloads": d[1]} for d in cursor.fetchall()]
    conn.close()
    return results

def get_full_funnel(days=7):
    visitors = {v['date']: v['visitors'] for v in get_unique_visitors(days)}
    diagnostics = {d['date']: d['diagnostics'] for d in get_free_diagnostics_stats(days)}
    payments = {p['date']: p['payments'] for p in get_sales_funnel_stats(days)}
    downloads = {d['date']: d['downloads'] for d in get_report_downloads_stats(days)}
    all_dates = sorted(set(visitors.keys()) | set(diagnostics.keys()) | set(payments.keys()) | set(downloads.keys()), reverse=True)[:days]
    funnel = [{"date": d, "visitors": visitors.get(d,0), "diagnostics": diagnostics.get(d,0), "payments": payments.get(d,0), "downloads": downloads.get(d,0)} for d in all_dates]
    return funnel

def get_all_premium_clients():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT p.user_id, p.phone, p.created_at as payment_date,
               b.business_name, b.business_description, f.q1, f.q2, f.q3, f.q4, f.q5,
               r.file_path, r.status as report_status, r.ready_at
        FROM payments p
        LEFT JOIN business_data b ON p.user_id = b.user_id
        LEFT JOIN forms f ON p.user_id = f.user_id
        LEFT JOIN reports r ON p.user_id = r.user_id AND r.report_type = 'premium'
        WHERE p.status = 'succeeded' ORDER BY p.created_at DESC
    """)
    columns = ['user_id','phone','payment_date','business_name','business_description','q1','q2','q3','q4','q5','report_path','report_status','report_ready_at']
    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return results

def get_all_free_diagnostics():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT 
            f.user_id, 
            f.completed_at, 
            b.business_name, 
            b.business_description,
            f.q1, f.q2, f.q3, f.q4, f.q5, 
            r.status as report_status, 
            r.report_text
        FROM forms f
        LEFT JOIN business_data b ON f.user_id = b.user_id
        LEFT JOIN (
            SELECT user_id, report_type, status, report_text, id
            FROM reports 
            WHERE report_type = 'free'
            AND id IN (SELECT MAX(id) FROM reports WHERE report_type = 'free' GROUP BY user_id)
        ) r ON f.user_id = r.user_id
        ORDER BY f.completed_at DESC LIMIT 100
    """)
    columns = ['user_id','date','business_name','business_description','q1','q2','q3','q4','q5','report_status','report_text']
    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return results

def get_new_consultations():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT id, user_id, phone, time, question, status, created_at
        FROM consultations WHERE status = 'new' ORDER BY created_at DESC LIMIT 50
    """)
    columns = ['id','user_id','phone','time','question','status','created_at']
    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return results

security = HTTPBasic()
def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Admin not configured")
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

def format_phone(phone: str) -> str:
    if not phone: return None
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
    row = conn.execute("SELECT business_name, business_description FROM business_data WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return {"name": row[0], "description": row[1]} if row else None

def get_form_data(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT q1, q2, q3, q4, q5 FROM forms WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return {"q1": row[0], "q2": row[1], "q3": row[2], "q4": row[3], "q5": row[4]} if row else None

def save_form(user_id: str, answers: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO forms (user_id, q1, q2, q3, q4, q5, q6, q7) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (user_id, answers.get("q1"), answers.get("q2"), answers.get("q3"), answers.get("q4"), answers.get("q5"), None, None))
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
    row = conn.execute("SELECT id, report_text, file_path, status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY created_at DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    return {"id": row[0], "text": row[1], "file_path": row[2], "status": row[3]} if row else None

def save_consultation_request(user_id: str, phone: str, time: str, question: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO consultations (user_id, phone, time, question, status) VALUES (?, ?, ?, ?, 'new')", (user_id, phone, time, question))
    conn.commit()
    conn.close()

def save_payment_request(user_id: str, phone: str, payment_id: str = None, amount: int = None, status: str = "pending"):
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
    row = conn.execute("SELECT user_id, phone, amount, status FROM payments WHERE yookassa_payment_id = ? ORDER BY id DESC LIMIT 1", (payment_id,)).fetchone()
    conn.close()
    return {"user_id": row[0], "phone": row[1], "amount": row[2], "status": row[3]} if row else None

def get_last_succeeded_payment():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT user_id FROM payments WHERE status = 'succeeded' ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return row[0] if row else None

def save_consent(user_id: str, consent_type: str, ip: str = None, user_agent: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO user_consents (user_id, consent_type, ip, user_agent) VALUES (?, ?, ?, ?)",
                 (user_id, consent_type, ip, user_agent[:500] if user_agent else None))
    conn.commit()
    conn.close()
    logger.info(f"Consent saved: user_id={user_id}, type={consent_type}")

def get_moscow_time():
    return datetime.utcnow() + timedelta(hours=3)

def format_moscow_time(dt=None):
    if dt is None: dt = get_moscow_time()
    return dt.strftime('%Y-%m-%d %H:%M:%S')

# === ОТПРАВКА УВЕДОМЛЕНИЙ В КАНАЛ MAX ===
async def send_notification_to_channel(text: str):
    if not ADMIN_CHANNEL_ID or not MAX_BOT_TOKEN:
        logger.error("ADMIN_CHANNEL_ID or MAX_BOT_TOKEN not configured")
        return
    url = f"https://platform-api.max.ru/messages?channel_id={ADMIN_CHANNEL_ID}"
    payload = {"text": text}
    headers = {"Authorization": MAX_BOT_TOKEN, "Content-Type": "application/json"}
    def _send_sync():
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code != 200:
                logger.error(f"send_notification_to_channel failed: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"send_notification_to_channel exception: {e}")
    await asyncio.get_event_loop().run_in_executor(None, _send_sync)

# === DEEPSEEK ===
def call_deepseek_diagnostic(name: str, description: str, answers: dict) -> str:
    if not DEEPSEEK_API_KEY:
        logger.error("DEEPSEEK_API_KEY not configured")
        return None
    q1_map = {"Услугу": "Услугу", "Инфопродукт": "Инфопродукт", "Консультацию": "Консультацию", "Пока не продаю": "Пока не продаю"}
    q2_map = {"до 5k": "до 5000 ₽", "5k-20k": "5000-20000 ₽", "20k-50k": "20000-50000 ₽", ">50k": "более 50000 ₽"}
    q3_map = {"<10": "менее 10", "10-50": "10-50", "50-200": "50-200", ">200": "более 200"}
    q4_map = {"300k/мес": "300 000 ₽/мес", "500k/мес": "500 000 ₽/мес", "1M/мес": "1 000 000 ₽/мес", "Масштаб": "масштабирование"}
    q5_map = {"Да": "да", "Нет": "нет", "В разработке": "в разработке"}
    survey_info = f"""
ДАННЫЕ О БИЗНЕСЕ:
• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}
• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}
• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}
• Цель на 2026: {q4_map.get(answers.get('q4'), 'не указано')}
• Есть автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}
"""
    prompt = f"""Сделай профессиональный маркетинговый разбор онлайн-бизнеса.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши отчет в деловом, мудром стиле. Без лишних слов. Используй метафоры, говори прямо. Обращайся на "ты". НЕ используй символы форматирования (*, #, _, `, ~). Для списков используй дефис.

Структура:
1. ЧТО СЕЙЧАС? (ниша, ЦА, оценка от 0 до 100, честно)
2. ГДЕ РАСТИ? (3 сильные стороны, 3 точки роста)
3. ПЕРВЫЙ ШАГ (3 конкретных действия прямо сейчас)"""
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {"model": "deepseek-chat", "messages": [{"role": "system", "content": "Ты — профессиональный бизнес-консультант в мудром, прямом стиле. Без воды."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 2000}
    try:
        response = requests.post(url, headers=headers, json=data, timeout=120)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        logger.error(f"DeepSeek error: {response.status_code}")
        return None
    except Exception as e:
        logger.error(f"DeepSeek failed: {e}")
        return None

def generate_premium_report_sync(user_id: str, name: str, description: str, answers: dict, report_id: int):
    logger.info(f"Starting premium report generation for user {user_id}")
    if not DEEPSEEK_API_KEY:
        update_report_status(report_id, 'failed')
        return False
    q1_map = {"Услугу": "Услугу", "Инфопродукт": "Инфопродукт", "Консультацию": "Консультацию", "Пока не продаю": "Пока не продаю"}
    q2_map = {"до 5k": "до 5k", "5k-20k": "5k-20k", "20k-50k": "20k-50k", ">50k": ">50k"}
    q3_map = {"<10": "<10", "10-50": "10-50", "50-200": "50-200", ">200": ">200"}
    q4_map = {"300k/мес": "300k/мес", "500k/мес": "500k/мес", "1M/мес": "1M/мес", "Масштаб": "Масштаб"}
    q5_map = {"Да": "да", "Нет": "нет", "В разработке": "в разработке"}
    survey_info = f"""
ДАННЫЕ О БИЗНЕСЕ:
• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}
• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}
• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}
• Цель: {q4_map.get(answers.get('q4'), 'не указано')}
• Автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}
"""
    prompt = f"""Сделай профессиональный план запуска продаж для онлайн-бизнеса.

ДАННЫЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши план в деловом, мудром стиле. Без воды. Конкретно. Обращайся на "ты". НЕ используй символы форматирования.

Структура:
1. РЕАЛЬНОСТЬ
2. КОНКУРЕНТЫ (3-5 игроков)
3. КЛИЕНТ (кто, что хочет, что мешает)
4. СИЛЬНЫЕ И СЛАБЫЕ СТОРОНЫ
5. ВОРОНКА (шаг за шагом)
6. ПЛАН НА МЕСЯЦ (по неделям)"""
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {"model": "deepseek-chat", "messages": [{"role": "system", "content": "Ты — профессиональный бизнес-консультант в мудром, прямом стиле. Без воды."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 4000}
    try:
        response = requests.post(url, headers=headers, json=data, timeout=300)
        if response.status_code == 200:
            report_text = response.json()["choices"][0]["message"]["content"]
            filename = f"premium_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = REPORTS_DIR / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_text)
            update_report_status(report_id, 'ready', str(filepath))
            logger.info(f"Premium report generated for user {user_id}")
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
        logger.info(f"Premium report generation completed for user {user_id}")

# === HEALTH CHECK ===
@app.get("/health")
async def health():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}

# === HTML ШАБЛОНЫ (ОБНОВЛЁННЫЙ ПОДВАЛ) ===
HTML_HEAD = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Продюсер экспертов + ИИ — первые клиенты за 2 недели</title>
    <meta name="description" content="Продюсер экспертов + ИИ. Первые клиенты за 2 недели, готовая воронка за 7 дней. Кейсы до 2 млн руб.">
    <script type="text/javascript">
        (function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};
        m[i].l=1*new Date();
        for (var j = 0; j < document.scripts.length; j++) {if (document.scripts[j].src === r) { return; }}
        k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)})
        (window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
        ym(108348240, "init", { clickmap:true, trackLinks:true, accurateTrackBounce:true, webvisor:true, ecommerce:"dataLayer" });
    </script>
    <noscript><div><img src="https://mc.yandex.ru/watch/108348240" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#fff;color:#1d1d1f}
        .container{max-width:1000px;margin:0 auto;padding:40px 20px}
        .hero{text-align:center;margin-bottom:60px}
        .hero h1{font-size:52px;font-weight:700;margin-bottom:20px;letter-spacing:-0.02em}
        .hero p{font-size:21px;color:#6e6e73;max-width:700px;margin-left:auto;margin-right:auto}
        .btn-main{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:16px 48px;font-size:20px;font-weight:600;border-radius:48px;box-shadow:0 2px 8px rgba(0,122,255,0.3);transition:transform 0.2s,box-shadow 0.2s;border:none;cursor:pointer}
        .btn-main:hover{background:#005fc5;transform:scale(1.02);box-shadow:0 4px 12px rgba(0,122,255,0.4)}
        .benefits-grid{display:flex;justify-content:center;gap:30px;flex-wrap:wrap;margin:40px auto}
        .benefit-item{flex:1;min-width:200px;text-align:center}
        .benefit-icon{font-size:32px;margin-bottom:12px}
        .benefit-title{font-size:17px;font-weight:600;color:#1d1d1f}
        .cases-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin:40px 0}
        .case-card{background:#f5f5f7;border-radius:20px;padding:20px;text-align:center}
        .case-icon{font-size:48px;margin-bottom:12px}
        .case-title{font-weight:600;margin-bottom:8px}
        .case-result{font-size:24px;font-weight:700;color:#34c759}
        .case-desc{font-size:12px;color:#6e6e73}
        .footer{text-align:center;margin-top:60px;padding-top:24px;border-top:1px solid #e5e5e5;font-size:12px;color:#8e8e93}
        .social-links{margin-top:8px;display:flex;flex-wrap:wrap;justify-content:center;gap:16px}
        .social-links a{color:#007aff;text-decoration:none;font-size:12px}
        hr{margin:30px 0;border:none;border-top:1px solid #e5e5e5}
        .form-card{background:#fff;border-radius:24px;padding:32px;box-shadow:0 4px 12px rgba(0,0,0,0.05);max-width:600px;margin:0 auto}
        .form-group{margin-bottom:24px}
        label{font-size:15px;font-weight:500;display:block;margin-bottom:8px}
        input,textarea{width:100%;padding:12px;font-size:15px;border:1px solid #ccc;border-radius:10px;font-family:inherit}
        .radio-group{display:flex;flex-direction:column;gap:12px;margin-top:8px}
        .radio-group label{display:flex;align-items:center;gap:8px;font-weight:normal;cursor:pointer;padding:8px 12px;background:#f5f5f7;border-radius:12px}
        .pricing-grid{display:flex;gap:24px;justify-content:center;margin:32px 0;flex-wrap:wrap}
        .pricing-card{flex:1;min-width:260px;background:#fff;border-radius:24px;padding:24px;box-shadow:0 4px 12px rgba(0,0,0,0.08);position:relative}
        .pricing-card.featured{border:2px solid #ff9f0a;background:linear-gradient(135deg,#fff8e8,#fff)}
        .popular-badge{position:absolute;top:-12px;right:20px;background:#ff9f0a;color:#fff;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600}
        .pricing-card h2{font-size:22px;margin-bottom:16px;text-align:center}
        .pricing-card .price{font-size:32px;font-weight:700;color:#007aff;margin:16px 0;text-align:center}
        .pricing-card ul{list-style:none;padding:0;margin:20px 0}
        .pricing-card li{padding:8px 0;display:flex;align-items:center;gap:10px;border-bottom:1px solid #e5e5ea;font-size:14px}
        .bot-link-block{background:#e8f0fe;border-radius:20px;padding:24px;margin:32px 0;text-align:center}
        @media (max-width:700px){
            .container{padding:20px 16px}
            .hero h1{font-size:32px}
            .hero p{font-size:18px}
            .btn-main{padding:12px 24px;font-size:18px}
            .benefits-grid{gap:20px}
            .benefit-item{min-width:140px}
            .cases-grid{grid-template-columns:repeat(2,1fr)}
            .pricing-grid{flex-direction:column}
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
        <div style="margin-top: 8px;">
            <a href="/oferta">Публичная оферта</a> | <a href="/privacy">Политика персональных данных</a>
        </div>
        <p>© 2026 Все права защищены</p>
    </div>
</div>
</body>
</html>"""

def render_page(content: str):
    return HTML_HEAD + content + HTML_FOOT

# === ОСТАЛЬНЫЕ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (render_waiting_page, render_premium_waiting_page) ===
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
        .status-icon{{width:24px;height:24px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center}}
        .status-icon.pending{{border:2px solid #ccc;background:white}}
        .status-icon.active{{border:2px solid #007aff;background:#007aff;color:white}}
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
            const statusItems = [
                {{id: 'status1', time: 0}},
                {{id: 'status2', time: 10}},
                {{id: 'status3', time: 20}},
                {{id: 'status4', time: 30}}
            ];
            statusItems.forEach(item => {{
                const el = document.getElementById(item.id);
                if (el) {{
                    if (elapsed >= item.time + 5) {{
                        el.className = 'status-item';
                        const icon = el.querySelector('.status-icon');
                        if (icon) icon.innerHTML = '✓';
                    }} else if (elapsed >= item.time) {{
                        el.className = 'status-item active';
                        const icon = el.querySelector('.status-icon');
                        if (icon) icon.innerHTML = '●';
                    }}
                }}
            }});
        }}
        function checkStatus() {{
            if (isRedirected) return;
            fetch('/check_status?user_id={user_id}&report_type={report_type}')
                .then(res => res.json())
                .then(data => {{
                    if (data.ready) {{
                        const fillEl = document.getElementById('progressFill');
                        if (fillEl) fillEl.style.width = '100%';
                        isRedirected = true;
                        setTimeout(() => {{ window.location.href = '{redirect_url}'; }}, 500);
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
    <div class="status-item" id="status1"><span class="status-icon pending">○</span><span>🔍 Анализируем вашу нишу — кто ваши клиенты и где они тусуются</span></div>
    <div class="status-item" id="status2"><span class="status-icon pending">○</span><span>📊 Изучаем целевую аудиторию — что они хотят на самом деле</span></div>
    <div class="status-item" id="status3"><span class="status-icon pending">○</span><span>🎯 Ищем точки роста — где вы теряете деньги</span></div>
    <div class="status-item" id="status4"><span class="status-icon pending">○</span><span>📝 Формируем рекомендации — что делать прямо сейчас</span></div>
    <p class="subtext">Пока нейросеть копается в вашей нише — я налью себе чай. Вы тоже можете. Это займёт 1-2 минуты. Страница обновится сама. Не обновляйте вручную — нейросеть обидится.</p>
</div>
</body>
</html>"""

def render_premium_waiting_page(user_id: str, amount: int):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Готовим стратегию | Salesplan</title>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#fff;color:#1d1d1f}}
        .container{{max-width:600px;margin:0 auto;padding:60px 20px;text-align:center}}
        .spinner{{width:50px;height:50px;border:4px solid #e5e5e5;border-top-color:#007aff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}
        @keyframes spin{{to{{transform:rotate(360deg)}}}}
        .step{{display:inline-block;margin:20px 10px;padding:8px 16px;border-radius:20px;background:#f5f5f7;font-size:14px}}
        .step.active{{background:#007aff;color:#fff}}
        .subtext{{font-size:14px;color:#8e8e93;margin-top:20px}}
    </style>
    <script>
        let attempts = 0;
        let isRedirected = false;
        let step = 1;
        function checkStatus() {{
            if (isRedirected) return;
            fetch('/check_premium_status?user_id={user_id}')
                .then(res => res.json())
                .then(data => {{
                    if (data.ready) {{
                        isRedirected = true;
                        window.location.href = '/payment/success?user_id={user_id}&amount={amount}';
                    }} else {{
                        attempts++;
                        step = Math.min(3, Math.floor(attempts / 20) + 1);
                        const step1 = document.getElementById('step1');
                        const step2 = document.getElementById('step2');
                        const step3 = document.getElementById('step3');
                        if(step1) step1.className = step >= 1 ? 'step active' : 'step';
                        if(step2) step2.className = step >= 2 ? 'step active' : 'step';
                        if(step3) step3.className = step >= 3 ? 'step active' : 'step';
                        if (attempts < 60) setTimeout(checkStatus, 3000);
                    }}
                }})
                .catch(() => setTimeout(checkStatus, 3000));
        }}
        setTimeout(checkStatus, 3000);
    </script>
</head>
<body>
<div class="container">
    <div class="spinner"></div>
    <h1>📊 Анализируем рынок и конкурентов</h1>
    <p>Нейросеть уже пишет ваш план. Я пока схожу за печеньками. Вы тоже можете отвлечься — это займёт 1-3 минуты.</p>
    <div style="margin: 30px 0;">
        <span id="step1" class="step active">1. Анализ конкурентов — кто платит и почему</span>
        <span id="step2" class="step">2. Сбор стратегии — собираем пазл</span>
        <span id="step3" class="step">3. Формирование плана — почти готово</span>
    </div>
    <p class="subtext">Страница обновится сама. Не нужно сидеть и сверлить экран взглядом.</p>
</div>
</body>
</html>"""

# ========================
# ГЛАВНАЯ СТРАНИЦА (обновлённый дизайн, без FAQ)
# ========================
@app.get("/")
async def index():
    content = '''
<div class="hero">
    <h1>Ты эксперт. А продаж — нет?</h1>
    <p>Знаешь, в чём главная боль экспертов?<br>
    Воронка есть. Клиентов — нет.<br>
    Ты вкладываешь время, деньги, душу. А они уходят к кому-то другому.<br>
    Почему?<br>
    Я 10 лет продюсирую экспертов. 50+ ниш. И знаю одно:<br>
    <strong>Ты не видишь, где именно сливаешь клиентов.</strong><br>
    Диагностика за 2 минуты покажет это как на рентгене. Бесплатно. Без обязательств. Только факты.</p>
</div>

<div class="benefits-grid">
    <div class="benefit-item"><div class="benefit-icon">🔍</div><div class="benefit-title">Где именно ты теряешь клиентов прямо сейчас</div></div>
    <div class="benefit-item"><div class="benefit-icon">🎯</div><div class="benefit-title">Какие 3 точки роста принесут первые деньги</div></div>
    <div class="benefit-item"><div class="benefit-icon">🤖</div><div class="benefit-title">Как сделать, чтобы клиенты писали сами, а не ты их искал</div></div>
    <div class="benefit-item"><div class="benefit-icon">📈</div><div class="benefit-title">Честный план действий — не общие советы, а конкретные шаги под твою нишу</div></div>
</div>

<p style="text-align: center; font-style: italic; color: #6e6e73; margin: 20px 0;">Никакой магии. Только разбор от продюсера с реальными кейсами в 50+ нишах. Без фантазий.</p>

<div style="text-align: center; margin: 40px 0;">
    <a href="/survey" class="btn-main" onclick="ym(108348240,'reachGoal','click_get_plan_top'); return true;">Бесплатно диагностика — план роста клиентов</a>
</div>

<p style="text-align: center; font-style: italic; color: #8e8e93; margin-bottom: 40px;">«Я не уговариваю. Я показываю путь. Дальше — твоё решение.»</p>

<h2 style="text-align: center; margin-bottom: 30px; font-size: 28px;">🔥 Реальные кейсы клиентов</h2>
<div class="cases-grid">
    <div class="case-card"><div class="case-icon">🇨🇳</div><div class="case-title">Эксперт по китайскому</div><div class="case-result">+120 000 ₽</div><div class="case-desc">за 2 недели без блога</div></div>
    <div class="case-card"><div class="case-icon">🎓</div><div class="case-title">Психолог Ольга</div><div class="case-result">+187 000 ₽</div><div class="case-desc">запуск курса с одного вебинара</div></div>
    <div class="case-card"><div class="case-icon">🌊</div><div class="case-title">Мастер Фен Шуй</div><div class="case-result">+195 000 ₽</div><div class="case-desc">первый запуск при рекламе 30 000 ₽</div></div>
    <div class="case-card"><div class="case-icon">🏫</div><div class="case-title">Онлайн-школа коучинга</div><div class="case-result">+2 000 000 ₽</div><div class="case-desc">марафон в ВК за 2 недели</div></div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# ========================
# СТРАНИЦА "ЗАПУСК ОНЛАЙН-ШКОЛЫ"
# ========================
@app.get("/launch-online-school")
async def launch_online_school():
    content = '''
<div class="hero">
    <h1>Хочешь запустить онлайн-школу? Я покажу, как это сделать без команды и бюджета. Узнай на диагностике.</h1>
    <p>«Хватит откладывать. Твои знания — это готовый продукт. Нужна только система.<br>
    Я настрою воронку, чат-бота, рекламу. Ты просто отвечаешь на 7 вопросов.<br>
    Через 14 дней твоя школа принимает учеников, а ты не занимаешься техничкой.»</p>
</div>

<div class="benefits-grid">
    <div class="benefit-item"><div class="benefit-icon">🎓</div><div class="benefit-title">Ученики сами приходят — не нужно их искать</div></div>
    <div class="benefit-item"><div class="benefit-icon">⚙️</div><div class="benefit-title">Всё работает без тебя: чат-бот, рассылки, оплата</div></div>
    <div class="benefit-item"><div class="benefit-icon">📈</div><div class="benefit-title">Если я возьмусь за твой проект — ты увидишь первые деньги уже через две недели. Но сначала надо понять, подходим ли мы друг другу. Начни с диагностики.</div></div>
</div>

<p style="text-align: center; font-style: italic; color: #6e6e73; margin: 20px 0;">Никакой магии. Только системный подход продюсера с 50+ нишами.</p>

<div style="text-align: center; margin: 40px 0;">
    <a href="/survey" class="btn-main" onclick="ym(108348240,'reachGoal','click_launch_school'); return true;">Бесплатно диагностика — план роста клиентов</a>
</div>

<p style="text-align: center; font-style: italic; color: #8e8e93; margin-bottom: 40px;">Пройди диагностику — я скажу, сколько ты можешь заработать на учениках за первый месяц.</p>

<h2 style="text-align: center; margin-bottom: 30px; font-size: 28px;">🔥 Реальные кейсы клиентов</h2>
<div class="cases-grid">
    <div class="case-card"><div class="case-icon">🇨🇳</div><div class="case-title">Эксперт по китайскому</div><div class="case-result">+120 000 ₽</div><div class="case-desc">за 2 недели без блога</div></div>
    <div class="case-card"><div class="case-icon">🎓</div><div class="case-title">Психолог Ольга</div><div class="case-result">+187 000 ₽</div><div class="case-desc">запуск курса с одного вебинара</div></div>
    <div class="case-card"><div class="case-icon">🌊</div><div class="case-title">Мастер Фен Шуй</div><div class="case-result">+195 000 ₽</div><div class="case-desc">первый запуск при рекламе 30 000 ₽</div></div>
    <div class="case-card"><div class="case-icon">🏫</div><div class="case-title">Онлайн-школа коучинга</div><div class="case-result">+2 000 000 ₽</div><div class="case-desc">марафон в ВК за 2 недели</div></div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# ========================
# СТРАНИЦА "ВОРОНКА ПРОДАЖ ЗА 7 ДНЕЙ"
# ========================
@app.get("/funnel-7-days")
async def funnel_7_days():
    content = '''
<div class="hero">
    <h1>Воронка за 7 дней. Работает 24/7 без тебя.</h1>
    <p>«Твоя воронка не продаёт? Я найду дыры. Настроим под MAX, VK, Telegram, Яндекс Директ.<br>
    Ты спишь — она собирает заявки. Бесплатная диагностика покажет, почему клиенты уходят.»</p>
</div>

<div class="benefits-grid">
    <div class="benefit-item"><div class="benefit-icon">🚀</div><div class="benefit-title">Воронка готова через 7 дней</div></div>
    <div class="benefit-item"><div class="benefit-icon">🤖</div><div class="benefit-title">AI на каждом шагу, без твоего участия</div></div>
    <div class="benefit-item"><div class="benefit-icon">📞</div><div class="benefit-title">Клиенты приходят сами, ты только отвечаешь</div></div>
</div>

<div style="text-align: center; margin: 40px 0;">
    <a href="/survey" class="btn-main" onclick="ym(108348240,'reachGoal','click_funnel'); return true;">Бесплатно диагностика — план роста клиентов</a>
</div>

<p style="text-align: center; font-style: italic; color: #8e8e93; margin-bottom: 40px;">Я покажу, как превратить твой трафик в деньги. Решение за тобой.</p>

<h2 style="text-align: center; margin-bottom: 30px; font-size: 28px;">🔥 Реальные кейсы клиентов</h2>
<div class="cases-grid">
    <div class="case-card"><div class="case-icon">🇨🇳</div><div class="case-title">Эксперт по китайскому</div><div class="case-result">+120 000 ₽</div><div class="case-desc">за 2 недели без блога</div></div>
    <div class="case-card"><div class="case-icon">🎓</div><div class="case-title">Психолог Ольга</div><div class="case-result">+187 000 ₽</div><div class="case-desc">запуск курса с одного вебинара</div></div>
    <div class="case-card"><div class="case-icon">🌊</div><div class="case-title">Мастер Фен Шуй</div><div class="case-result">+195 000 ₽</div><div class="case-desc">первый запуск при рекламе 30 000 ₽</div></div>
    <div class="case-card"><div class="case-icon">🏫</div><div class="case-title">Онлайн-школа коучинга</div><div class="case-result">+2 000 000 ₽</div><div class="case-desc">марафон в ВК за 2 недели</div></div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# ========================
# СТРАНИЦА АНКЕТЫ (survey) — без ссылок в чекбоксе
# ========================
@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<div class="hero">
    <h1>Честный разбор от продюсера экспертов. Узнай 3 скрытые точки роста за 2 минуты.</h1>
    <p style="font-size: 18px;">«Отвечай честно — это поможет точнее. 2 минуты.»</p>
</div>
<div class="form-card">
    <form action="/survey/submit" method="post" id="surveyForm">
        <div class="form-group"><label>1. Название бизнеса</label><input type="text" name="business_name" placeholder="например: Продюсирую экспертов" required></div>
        <div class="form-group"><label>2. Короткое описание (чем занимаешься, кому помогаешь)</label><textarea name="business_description" rows="3" placeholder="Пример: Воронка: бесплатная диагностика бизнеса → план запуска продаж → бесплатный разбор плана за подписку в MAX" required></textarea></div>
        <div class="form-group"><label>3. Что продаёшь?</label><div class="radio-group"><label><input type="radio" name="q1" value="Услугу" required> Услугу</label><label><input type="radio" name="q1" value="Инфопродукт"> Инфопродукт</label><label><input type="radio" name="q1" value="Консультацию"> Консультацию</label><label><input type="radio" name="q1" value="Пока не продаю"> Пока не продаю</label></div></div>
        <div class="form-group"><label>4. Средний чек (₽)</label><div class="radio-group"><label><input type="radio" name="q2" value="до 5k" required> до 5k</label><label><input type="radio" name="q2" value="5k-20k"> 5k-20k</label><label><input type="radio" name="q2" value="20k-50k"> 20k-50k</label><label><input type="radio" name="q2" value=">50k"> >50k</label></div></div>
        <div class="form-group"><label>5. Клиентов в месяц (примерно)</label><div class="radio-group"><label><input type="radio" name="q3" value="<10" required> меньше 10</label><label><input type="radio" name="q3" value="10-50"> 10-50</label><label><input type="radio" name="q3" value="50-200"> 50-200</label><label><input type="radio" name="q3" value=">200"> более 200</label></div></div>
        <div class="form-group"><label>6. Цель на 2026</label><div class="radio-group"><label><input type="radio" name="q4" value="300k/мес" required> 300k/мес</label><label><input type="radio" name="q4" value="500k/мес"> 500k/мес</label><label><input type="radio" name="q4" value="1M/мес"> 1M/мес</label><label><input type="radio" name="q4" value="Масштаб"> Масштаб</label></div></div>
        <div class="form-group"><label>7. Уже есть автоворонка?</label><div class="radio-group"><label><input type="radio" name="q5" value="Да" required> Да</label><label><input type="radio" name="q5" value="Нет"> Нет</label><label><input type="radio" name="q5" value="В разработке"> В разработке</label></div></div>
        
        <div class="form-group">
            <label style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" name="consent" required style="width: 20px; height: 20px;">
                <span>Я принимаю условия публичной оферты и даю согласие на обработку персональных данных</span>
            </label>
        </div>
        
        <div style="text-align:center"><p style="margin-bottom: 20px; font-size: 14px; color: #6e6e73;">Ты просто отвечаешь на 7 вопросов. Я нахожу, где ты теряешь клиентов, и даю готовую воронку под MAX, VK, Telegram, Яндекс.Директ. Бесплатно. Честно.</p><button type="submit" class="btn-main" id="submitBtn" onclick="ym(108348240,'reachGoal','survey_submit'); return true;">Отправить и получить разбор</button></div>
    </form>
</div>
<script>
    document.getElementById('surveyForm').addEventListener('submit', function(e) {
        const submitBtn = document.getElementById('submitBtn');
        submitBtn.disabled = true;
        submitBtn.textContent = '⏳ Отправляю...';
    });
</script>
"""
    return HTMLResponse(content=render_page(content))

# ========================
# ОБРАБОТЧИК АНКЕТЫ (без изменений логики, только добавил сохранение согласия)
# ========================
@app.post("/survey/submit")
async def survey_submit(
    request: Request,
    business_name: str = Form(...),
    business_description: str = Form(...),
    q1: str = Form(...),
    q2: str = Form(...),
    q3: str = Form(...),
    q4: str = Form(...),
    q5: str = Form(...),
    consent: str = Form(...)
):
    user_id = str(uuid.uuid4())
    logger.info(f"New survey submission: user_id={user_id}, business={business_name}")
    save_user(user_id, None, None)
    save_business_data(user_id, business_name, business_description)
    save_form(user_id, {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5})
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    save_consent(user_id, 'survey_and_offer', client_ip, user_agent)
    
    answers = {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5}
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'free', 'generating')", (user_id,))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    logger.info(f"Free report {report_id} created for user {user_id}")
    async def generate_and_save():
        logger.info(f"Starting free report generation for user {user_id}")
        loop = asyncio.get_event_loop()
        diagnostic_text = await loop.run_in_executor(None, call_deepseek_diagnostic, business_name, business_description, answers)
        conn = sqlite3.connect(DB_PATH)
        if diagnostic_text:
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (diagnostic_text, report_id))
            logger.info(f"Free report {report_id} generated successfully")
        else:
            fallback_text = f"Диагностика для бизнеса \"{business_name}\"\n\nОписание: {business_description}\n\nРекомендации:\n- Проанализируй целевую аудиторию\n- Настрой воронку продаж\n- Добавь призывы к действию"
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (fallback_text, report_id))
            logger.warning(f"Free report {report_id} using fallback text")
        conn.commit()
        conn.close()
    asyncio.create_task(generate_and_save())
    return HTMLResponse(content=render_waiting_page(user_id, "free", f"/diagnostic?user_id={user_id}"))

# ========================
# ВСПОМОГАТЕЛЬНЫЕ ЭНДПОИНТЫ ДЛЯ ПРОВЕРКИ СТАТУСА
# ========================
@app.get("/check_status")
async def check_status(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    return {"ready": row and row[0] == 'ready'}

@app.get("/check_premium_status")
async def check_premium_status(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = 'premium' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    return {"ready": row and row[0] == 'ready'}

# ========================
# СТРАНИЦА ДИАГНОСТИКИ (с блоком "Взгляд на ситуацию", убрана ссылка на отзывы)
# ========================
@app.get("/diagnostic", response_class=HTMLResponse)
async def diagnostic(user_id: str):
    logger.info(f"Diagnostic page requested for user {user_id}")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT report_text FROM reports WHERE user_id = ? AND report_type = 'free' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not row or not row[0]:
        logger.warning(f"Diagnostic not ready for user {user_id}, showing waiting page")
        return HTMLResponse(content=render_waiting_page(user_id, "free", f"/diagnostic?user_id={user_id}"))
    report_text_full = row[0]
    report_text_html = report_text_full.replace("\n", "<br>")
    content = f'''
<div class="hero">
    <h1>Пройди диагностику бизнеса перед запуском клиентов</h1>
    <p style="font-size: 18px;">«Узнай скрытые точки роста за 2 минуты»</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: #e8f0fe; border-radius: 16px; padding: 12px 16px; margin-bottom: 20px; text-align: center;">
        <span style="font-size: 24px;">📜</span>
        <p style="font-size: 14px; margin: 0;">Твой отчёт находится ниже. Прокрути окно вниз — там вся диагностика.</p>
    </div>
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left;">
        <div style="text-align: center; margin-bottom: 10px; font-size: 12px; color: #007aff;">⬇️ Прокрути вниз ⬇️</div>
        <div style="max-height: 500px; overflow-y: auto;">
            <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
        </div>
    </div>
    <hr style="margin: 32px 0;">
    <div style="background: #f8f8fa; border-radius: 24px; padding: 28px; margin: 32px 0; text-align: left; border-left: 4px solid #ff9f0a;">
        <p style="font-size: 18px; font-weight: 500; margin-bottom: 16px;">🎯 Взгляд на ситуацию:</p>
        <p style="font-size: 16px; line-height: 1.5; margin-bottom: 16px;">
            «Диагностика — это как рентген. Ты увидел проблему. Но рентген не лечит.<br><br>
            Я нашёл, где ты теряешь клиентов. Теперь выбор: ничего не менять или начать действовать.<br><br>
            Маркетинговый план — твой первый шаг. AI-чат — поддержка 24/7. Челлендж — ежедневная практика.<br><br>
            Я не уговариваю. Я показываю путь. Решение за тобой.»
        </p>
    </div>
    <h2 style="font-size: 28px; margin-bottom: 16px; text-align: center;" id="pricing">🚀 Выбери свой путь</h2>
    <div class="pricing-grid">
        <div class="pricing-card">
            <h2>📄 Старт</h2>
            <div class="price">490 ₽ <small>вместо 4 900 ₽</small></div>
            <ul>
                <li>✅ Маркетинговый план (ЦА, конкуренты, воронка, контент-план)</li>
                <li class="highlight">⚡ План через 2 минуты после оплаты</li>
            </ul>
            <form action="/payment/create" method="post">
                <input type="hidden" name="user_id" value="{user_id}">
                <input type="hidden" name="amount" value="490">
                <button type="submit" class="btn-main" style="width: 100%;" onclick="ym(108348240,'reachGoal','select_basic_plan'); return true;">Выбрать</button>
            </form>
        </div>
        <div class="pricing-card featured">
            <div class="popular-badge">🔥 Выбирают 70%</div>
            <h2>🚀 Профи</h2>
            <div class="price">4 900 ₽ <small>вместо 14 900 ₽</small></div>
            <ul>
                <li>✅ Всё из Старта</li>
                <li>✅ 30 дней AI‑консультаций в MAX</li>
                <li>✅ 21‑дневный челлендж с проверкой заданий от продюсера</li>
                <li>✅ Доступ в закрытый MAX‑канал</li>
                <li class="highlight">💬 Чат с AI‑ассистентом 24/7</li>
                <li>📱 Работает в MAX, VK, Telegram, Яндекс.Директ</li>
            </ul>
            <form action="/payment/create" method="post">
                <input type="hidden" name="user_id" value="{user_id}">
                <input type="hidden" name="amount" value="4900">
                <button type="submit" class="btn-main" style="width: 100%;" onclick="ym(108348240,'reachGoal','select_premium_plan'); return true;">🔥 Получить доступ</button>
            </form>
            <p style="font-size: 12px; margin-top: 12px; color: #6e6e73; text-align: center;">* AI-чат работает в MAX, отвечает на вопросы 24/7</p>
        </div>
        <div class="pricing-card" style="border-color: #ff9f0a; background: linear-gradient(135deg, #fff8e8, #fff);">
            <div class="popular-badge" style="background: #ff9f0a;">🔥 Под ключ</div>
            <h2>💎 Внедрение под ключ</h2>
            <div class="price">14 900 ₽ <small>вместо 45 000 ₽</small></div>
            <ul>
                <li>✅ Всё из Профи</li>
                <li>✅ Личная настройка воронки под твой бизнес</li>
                <li>✅ Скрипты продаж и возражений</li>
                <li>✅ Настройка чат-бота</li>
                <li class="highlight">⚡ Гарантия первой сделки в течение 14 дней</li>
            </ul>
            <form action="/payment/create" method="post">
                <input type="hidden" name="user_id" value="{user_id}">
                <input type="hidden" name="amount" value="14900">
                <button type="submit" class="btn-main" style="width: 100%; background: #ff9f0a;" onclick="ym(108348240,'reachGoal','select_producer_offer'); return true;">🔥 Заказать внедрение</button>
            </form>
            <p style="font-size: 12px; margin-top: 12px; color: #6e6e73; text-align: center;">* После оплаты я свяжусь с тобой в течение часа</p>
        </div>
    </div>
    <hr style="margin: 32px 0;">
    <div style="background: #e8f0fe; border-radius: 20px; padding: 24px; margin: 32px 0; text-align: center;">
        <div style="font-size: 32px; margin-bottom: 12px;">🎧</div>
        <h3 style="font-size: 20px; margin-bottom: 8px;">Нужен личный разговор?</h3>
        <p style="font-size: 16px; color: #1d1d1f; margin-bottom: 16px;">Запишись на бесплатные 30 минут. После подписки на канал я свяжусь. Без спама.</p>
        <a href="/consultation?user_id={user_id}" class="btn-main" style="background: #007aff;" onclick="ym(108348240,'reachGoal','consultation_link'); return true;">📅 Записаться на консультацию</a>
        <p style="font-size: 12px; color: #6e6e73; margin-top: 12px;">* После записи нужно будет подписаться на канал в MAX — это обязательное условие.</p>
    </div>
</div>
<script> ym(108348240,'reachGoal','diagnostic_got'); </script>
'''
    return HTMLResponse(content=render_page(content))

# ========================
# ПЛАТЁЖНЫЕ ЭНДПОИНТЫ (с чекбоксом без ссылок)
# ========================
@app.post("/payment/create")
async def payment_create(user_id: str = Form(...), amount: int = Form(...)):
    logger.info(f"Payment create for user {user_id}, amount={amount}")
    return RedirectResponse(url=f"/payment?user_id={user_id}&amount={amount}", status_code=303)

@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str, amount: int, status: str = None):
    error_message = ""
    if status == "cancelled":
        error_message = '<p style="color: red; margin-bottom: 20px;">❌ Платеж был отменен. Попробуйте снова.</p>'
    if amount == 490:
        plan_name = "Маркетинговый план"
    elif amount == 4900:
        plan_name = "Тариф Профи (план + AI-чат 30 дней + челлендж + канал)"
    elif amount == 14900:
        plan_name = "Внедрение под ключ (полная настройка воронки от продюсера)"
    else:
        plan_name = f"План за {amount} ₽"
    if amount == 490:
        old_price = 4900
        discount = 4410
    elif amount == 4900:
        old_price = 14900
        discount = 10000
    elif amount == 14900:
        old_price = 45000
        discount = 30100
    else:
        old_price = amount * 2
        discount = amount
    content = f'''
<div class="hero">
    <h1>💰 {plan_name} — {amount} ₽</h1>
    <p style="font-size: 18px;">«Спойлер: ты получишь не просто документ, а готовую дорожную карту. Бери и делай.»</p>
</div>
<div class="form-card">
    {error_message}
    <div id="timer" style="background: #ff3b30; color: white; text-align: center; padding: 12px; border-radius: 12px; margin-bottom: 20px; font-weight: 600;">
        <div>💰 Обычная цена: <span id="oldPrice">{old_price}</span> ₽</div>
        <div style="font-size: 20px; margin: 8px 0;">🔥 Сегодня: <span id="currentPrice">{amount}</span> ₽</div>
        <div>⏰ Скидка <span id="discountAmount">{discount}</span> ₽ действует: <span id="timer-countdown">10:00</span></div>
    </div>
    <form action="/create_yookassa_payment" method="post" style="margin-top: 30px;" id="paymentForm">
        <input type="hidden" name="user_id" value="{user_id}">
        <input type="hidden" name="amount" value="{amount}">
        <div class="form-group"><label>📞 Телефон (нужен для чека по закону)</label><input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required style="text-align: center; font-size: 18px;"><p style="font-size: 12px; color: #8e8e93; margin-top: 6px;">Чек придёт на этот номер. Звонков и рекламы не будет.</p></div>
        <div class="form-group">
            <label style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" name="consent" required style="width: 20px; height: 20px;">
                <span>Я принимаю условия публичной оферты и даю согласие на обработку персональных данных</span>
            </label>
        </div>
        <p style="font-size: 12px; text-align: center; margin-bottom: 16px;">Ты уже ответил на вопросы. Я знаю, куда тебе двигаться. Сейчас ты оплачиваешь план — и через пару минут получишь готовый маршрут. Останется только внедрять.</p>
        <div style="text-align:center;margin:20px 0"><button type="submit" class="btn-main" style="width: 100%;" onclick="ym(108348240,'reachGoal','pay_click'); return true;">💳 Оплатить {amount} ₽</button></div>
        <p style="font-size: 12px; text-align: center; margin-top: 12px;">✅ Безопасная оплата через ЮKassa — твои деньги под защитой. Не подойдёт? Верну деньги в течение 3 дней — без вопросов.</p>
    </form>
</div>
<script>
    let timeLeft = 600;
    var timerEl = document.getElementById('timer-countdown');
    var timerDiv = document.getElementById('timer');
    var interval = setInterval(function() {{
        if (timeLeft <= 0) {{
            clearInterval(interval);
            timerDiv.style.background = '#8e8e93';
            timerDiv.innerHTML = '⏰ Скидка закончилась. Цена вернётся к обычной через 24 часа.';
            return;
        }}
        timeLeft--;
        var minutes = Math.floor(timeLeft / 60);
        var seconds = timeLeft % 60;
        timerEl.innerText = minutes.toString().padStart(2, '0') + ':' + seconds.toString().padStart(2, '0');
    }}, 1000);
    window.addEventListener('beforeunload', function(e) {{
        var message = "Подожди! Ты не завершил оплату.\\n\\nПосле оплаты тебя ждёт:\\n- Готовый план продаж с анализом конкурентов\\n- Бесплатный 30-минутный разбор этого плана\\n- Доступ к закрытому MAX-каналу с кейсами\\n\\nВернись и заверши оплату — это займёт 2 минуты.";
        e.preventDefault();
        e.returnValue = message;
        return message;
    }});
</script>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/create_yookassa_payment")
async def create_yookassa_payment(
    request: Request,
    user_id: str = Form(...),
    phone: str = Form(...),
    amount: int = Form(...),
    consent: str = Form(...)
):
    phone = format_phone(phone)
    logger.info(f"Creating YooKassa payment for user {user_id}, phone {phone}, amount={amount}")
    save_user(user_id, phone, None)
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    save_consent(user_id, 'payment_and_offer', client_ip, user_agent)
    base_url = str(request.base_url).rstrip('/')
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error("YooKassa credentials missing!")
        save_payment_request(user_id, phone, amount=amount)
        return RedirectResponse(url=f"/payment?user_id={user_id}&amount={amount}", status_code=303)
    if not phone:
        logger.error("Phone is required")
        save_payment_request(user_id, phone, amount=amount)
        return RedirectResponse(url=f"/payment?user_id={user_id}&amp;amount={amount}&error=phone_required", status_code=303)
    if amount == 490:
        description = "Профессиональный маркетинговый план"
    elif amount == 4900:
        description = "Тариф Профи: Маркетинговый план + AI-чат 30 дней + Челлендж + канал"
    elif amount == 14900:
        description = "Внедрение под ключ: персональная настройка воронки от продюсера"
    else:
        description = f"План продаж за {amount} ₽"
    payment_data = {
        "amount": {"value": f"{amount}.00", "currency": "RUB"},
        "confirmation": {"type": "redirect", "return_url": f"{base_url}/payment/confirm?user_id={user_id}"},
        "capture": True,
        "description": description,
        "metadata": {"user_id": user_id, "phone": phone, "amount": amount},
        "receipt": {
            "customer": {"phone": phone},
            "items": [{"description": description, "quantity": "1.00", "amount": {"value": f"{amount}.00", "currency": "RUB"}, "vat_code": "6", "payment_mode": "full_payment", "payment_subject": "service"}]
        }
    }
    auth = base64.b64encode(f"{YOOKASSA_SHOP_ID}:{YOOKASSA_SECRET_KEY}".encode()).decode()
    try:
        response = requests.post(
            "https://api.yookassa.ru/v3/payments",
            json=payment_data,
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json", "Idempotence-Key": str(uuid.uuid4())},
            timeout=30
        )
        logger.info(f"YooKassa API response status: {response.status_code}")
        if response.status_code in (200, 201):
            payment = response.json()
            payment_id = payment.get("id")
            confirmation_url = payment.get("confirmation", {}).get("confirmation_url")
            if not confirmation_url:
                logger.error(f"No confirmation URL in response")
                save_payment_request(user_id, phone, amount=amount)
                return RedirectResponse(url=f"/payment?user_id={user_id}&amount={amount}", status_code=303)
            save_payment_request(user_id, phone, payment_id, amount, "pending")
            return RedirectResponse(url=confirmation_url, status_code=303)
        else:
            logger.error(f"YooKassa error: {response.status_code} - {response.text}")
            save_payment_request(user_id, phone, amount=amount)
            return RedirectResponse(url=f"/payment?user_id={user_id}&amount={amount}", status_code=303)
    except Exception as e:
        logger.error(f"YooKassa exception: {e}")
        save_payment_request(user_id, phone, amount=amount)
        return RedirectResponse(url=f"/payment?user_id={user_id}&amount={amount}", status_code=303)

@app.post("/payment/webhook")
async def payment_webhook(request: Request):
    try:
        body = await request.json()
        logger.info(f"Webhook received")
        event = body.get("event")
        payment = body.get("object", {})
        payment_id = payment.get("id")
        status = payment.get("status")
        metadata = payment.get("metadata", {})
        user_id = metadata.get("user_id")
        amount = metadata.get("amount")
        if amount is not None:
            try:
                amount = int(amount)
            except:
                amount = 490
        else:
            amount = 490
        logger.info(f"Webhook parsed: event={event}, payment_id={payment_id}, status={status}, user_id={user_id}, amount={amount}")
        if event == "payment.succeeded" and status == "succeeded":
            update_payment_status(payment_id, "succeeded")
            if user_id:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE reports SET paid_at = CURRENT_TIMESTAMP WHERE user_id = ? AND report_type = 'premium' AND status = 'ready'", (user_id,))
                conn.commit()
                conn.close()
                logger.info(f"Updated paid_at for user {user_id} after payment")
                
                biz = get_business_data(user_id)
                answers = get_form_data(user_id)
                if biz and answers and DEEPSEEK_API_KEY:
                    existing = get_report(user_id, "premium")
                    if not existing or existing["status"] != "ready":
                        conn = sqlite3.connect(DB_PATH)
                        cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'premium', 'generating')", (user_id,))
                        report_id = cursor.lastrowid
                        conn.commit()
                        conn.close()
                        asyncio.create_task(generate_premium_report_background(user_id, biz["name"], biz["description"], answers, report_id))
                        logger.info(f"Started premium report generation for user {user_id} after payment")
        return JSONResponse(content={"status": "ok"})
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return JSONResponse(content={"status": "error"}, status_code=500)

@app.get("/payment/confirm")
async def payment_confirm(request: Request):
    params = dict(request.query_params)
    logger.info(f"Payment confirm called with params: {params}")
    payment_id = params.get("paymentId") or params.get("payment_id")
    user_id = params.get("user_id")
    if payment_id:
        payment_info = get_payment_by_yookassa_id(payment_id)
        if payment_info:
            user_id = payment_info["user_id"]
            amount = payment_info["amount"] if payment_info["amount"] is not None else 490
            logger.info(f"Payment confirm: redirect via payment_id for user {user_id} amount {amount}")
            return RedirectResponse(url=f"/payment/success?user_id={user_id}&amount={amount}", status_code=303)
    if user_id:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT amount FROM payments WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        conn.close()
        if row:
            amount = row[0] if row[0] is not None else 490
            logger.info(f"Payment confirm: redirecting to success for user {user_id} with amount {amount}")
            return RedirectResponse(url=f"/payment/success?user_id={user_id}&amount={amount}", status_code=303)
        else:
            logger.warning(f"Payment confirm: no payments found for user {user_id}")
    else:
        logger.warning("Payment confirm: neither payment_id nor user_id provided")
    return HTMLResponse(content="""<!DOCTYPE html><html><head><title>Подтверждение оплаты</title><style>body{font-family:sans-serif;text-align:center;padding:50px}.btn{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;border-radius:12px}</style></head><body><h1>✅ Оплата прошла успешно!</h1><p>Вернись на сайт, чтобы получить план</p><a href="/" class="btn">На главную</a></body></html>""", status_code=200)

@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str, amount: int = 490):
    logger.info(f"Payment success page for user {user_id}, amount={amount}")
    conn = sqlite3.connect(DB_PATH)
    payment_row = conn.execute("SELECT status, amount FROM payments WHERE user_id = ? AND status = 'succeeded' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not payment_row:
        return RedirectResponse(url="/", status_code=303)
    if payment_row[1] and payment_row[1] != amount:
        amount = payment_row[1]
        logger.info(f"Fixed amount from payment: {amount} for user {user_id}")
    
    user_phone = ""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row and row[0]:
        user_phone = row[0]
    conn.close()
    
    biz = get_business_data(user_id)
    answers = get_form_data(user_id)
    existing_report = get_report(user_id, "premium")
    
    if not existing_report or existing_report["status"] == "generating":
        if not existing_report:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'premium', 'generating')", (user_id,))
            conn.commit()
            conn.close()
            if biz and answers and DEEPSEEK_API_KEY:
                report_id = cursor.lastrowid
                asyncio.create_task(generate_premium_report_background(user_id, biz["name"], biz["description"], answers, report_id))
        return HTMLResponse(content=render_premium_waiting_page(user_id, amount))
    
    report_text_full = None
    if existing_report.get("file_path"):
        file_path = existing_report["file_path"]
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    report_text_full = f.read()
            except Exception as e:
                logger.error(f"Failed to read report file: {e}")
    if not report_text_full:
        report_text_full = existing_report.get("text") or "Текст плана продаж временно недоступен. Обратись в поддержку."
    report_text_html = report_text_full.replace("\n", "<br>")
    
    if amount in (4900, 14900):
        if amount == 4900:
            content = f'''
<div class="hero">
    <h1>🎉 Доступ к пакету «Профи» активирован!</h1>
    <p style="font-size: 18px;">«Вот он — твой билет к системным продажам. Бери и делай. AI-чат ответит 24/7.»</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    <hr style="margin: 32px 0;">
    <div style="background: #e8f0fe; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left;">
        <p style="font-size: 14px; margin: 0;">📌 Твой маркетинговый план уже сгенерирован. Чтобы начать внедрять, перейди в чат-бот и напиши <strong>/start</strong>.</p>
    </div>
    <div class="bot-link-block">
        <div class="bot-icon">🤖</div>
        <div class="bot-text">
            <h4>Перейди в MAX-чат</h4>
            <p>Задавай вопросы AI-ассистенту по плану и участвуй в челлендже</p>
        </div>
        <a href="https://max.ru/id781407988795_bot" target="_blank" class="btn-main" style="margin-top: 10px;" onclick="ym(108348240,'reachGoal','premium_purchase_success'); return true;">🔥 Перейти в MAX-чат</a>
    </div>
    <hr style="margin: 32px 0;">
    <div style="background: linear-gradient(135deg, #f8f8fa 0%, #fff 0%); border-radius: 24px; padding: 28px; margin: 32px 0; text-align: center; border: 1px solid #e5e5ea;">
        <div style="font-size: 48px; margin-bottom: 16px;">🎁</div>
        <h3 style="font-size: 22px; margin-bottom: 12px;">Бонус: 30 минут со мной</h3>
        <p style="font-size: 16px; color: #6e6e73; margin-bottom: 20px;">«Я посмотрю твой план, бизнес и скажу честно: что работает, а что нет. Без воды. Без «всё хорошо». Только факты и следующая точка входа.»</p>
        <div style="background: #f5f5f7; border-radius: 16px; padding: 20px; text-align: left; margin: 20px 0;">
            <p style="font-weight: 600; margin-bottom: 12px;">Что вынесешь за 30 минут:</p>
            <ul style="list-style: none; padding: 0;">
                <li style="margin-bottom: 10px;">✅ Чёткий план первой продажи, которую можно сделать завтра</li>
                <li style="margin-bottom: 10px;">✅ Ответ, на каком этапе воронки ты теряешь деньги</li>
                <li style="margin-bottom: 10px;">✅ Честный разбор — где ты сливаешь время и бюджет впустую</li>
            </ul>
        </div>
        <div style="text-align: center; margin: 32px 0;">
            <a href="/consultation?user_id={user_id}" class="btn-main" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">🔥 Забрать 30 минут</a>
            <p style="font-size: 12px; color: #6e6e73; margin-top: 12px;">Без подписок, без обязательств. Просто созвон и польза.</p>
        </div>
    </div>
    <p style="margin-top: 20px;">Клиенты приходят к тебе. Система работает автоматически. Если понадобится помощь — AI-чат внутри MAX ответит в любое время.</p>
</div>
<script> ym(108348240,'reachGoal','premium_purchase_success'); </script>'''
        else:
            content = f'''
<div class="hero">
    <h1>🎉 Внедрение под ключ активировано!</h1>
    <p style="font-size: 18px;">«Ты выбрал полный пакет. Я свяжусь с тобой в течение часа, чтобы начать настройку воронки.»</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    <hr style="margin: 32px 0;">
    <div style="background: #e8f0fe; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left;">
        <p style="font-size: 14px; margin: 0;">📌 Твой маркетинговый план уже сгенерирован. Я напишу тебе в ближайшее время, чтобы согласовать детали внедрения.</p>
    </div>
    <p style="margin-top: 20px;">Клиенты приходят к тебе. Система работает автоматически.</p>
</div>
<script> ym(108348240,'reachGoal','producer_purchase_success'); </script>'''
        return HTMLResponse(content=render_page(content))
    else:
        # amount == 490
        content = f'''
<div class="hero">
    <h1>🎉 Спасибо за покупку!</h1>
    <p style="font-size: 18px;">«Вот твой маркетинговый план. Дальше всё зависит от тебя.»</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    <hr style="margin: 32px 0;">
    <div class="bot-link-block">
        <div class="bot-icon">🚀</div>
        <div class="bot-text">
            <h4>План есть. Теперь вопрос: будешь ты его внедрять один или с поддержкой?</h4>
            <p>Доплати 4000 ₽ — и получишь AI-чат 24/7, челлендж с моей проверкой и закрытый канал, где я делюсь тем, что реально работает. Результат придёт в 3 раза быстрее. Проверено на сотнях клиентов.</p>
        </div>
        <form action="/create_yookassa_payment" method="post" style="display: inline; margin: 0;">
            <input type="hidden" name="user_id" value="{user_id}">
            <input type="hidden" name="phone" value="{user_phone}">
            <input type="hidden" name="amount" value="4900">
            <input type="hidden" name="consent" value="on">
            <button type="submit" class="btn-main" style="margin-top: 10px;" onclick="ym(108348240,'reachGoal','upsell_click'); return true;">🔥 Доплатить 4000 ₽ и пройти путь с поддержкой</button>
        </form>
        <p style="font-size: 12px; margin-top: 8px;">* Вместо 4900 ₽ ты платишь только 4000 ₽, потому что 490 ₽ уже оплачены.</p>
        <hr style="margin: 20px 0;">
        <p style="font-size: 14px;">👉 Оставить план и идти самому — просто закрой это окно.</p>
    </div>
    <hr style="margin: 32px 0;">
    <div style="background: linear-gradient(135deg, #f8f8fa 0%, #fff 0%); border-radius: 24px; padding: 28px; margin: 32px 0; text-align: center; border: 1px solid #e5e5ea;">
        <div style="font-size: 48px; margin-bottom: 16px;">🎁</div>
        <h3 style="font-size: 22px; margin-bottom: 12px;">Бонус: 30 минут со мной</h3>
        <p style="font-size: 16px; color: #6e6e73; margin-bottom: 20px;">«Я посмотрю твой план, бизнес и скажу честно: что работает, а что нет. Без воды. Без «всё хорошо». Только факты и следующая точка входа.»</p>
        <div style="background: #f5f5f7; border-radius: 16px; padding: 20px; text-align: left; margin: 20px 0;">
            <p style="font-weight: 600; margin-bottom: 12px;">Что вынесешь за 30 минут:</p>
            <ul style="list-style: none; padding: 0;">
                <li style="margin-bottom: 10px;">✅ Чёткий план первой продажи, которую можно сделать завтра</li>
                <li style="margin-bottom: 10px;">✅ Ответ, на каком этапе воронки ты теряешь деньги</li>
                <li style="margin-bottom: 10px;">✅ Честный разбор — где ты сливаешь время и бюджет впустую</li>
            </ul>
        </div>
        <div style="text-align: center; margin: 32px 0;">
            <a href="/consultation?user_id={user_id}" class="btn-main" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">🔥 Забрать 30 минут</a>
            <p style="font-size: 12px; color: #6e6e73; margin-top: 12px;">Без подписок, без обязательств. Просто созвон и польза.</p>
        </div>
    </div>
</div>
<script> ym(108348240,'reachGoal','basic_purchase_success'); </script>'''
        return HTMLResponse(content=render_page(content))

# ========================
# КОНСУЛЬТАЦИЯ И ПОДПИСКА (с чекбоксом без ссылок)
# ========================
@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str = None):
    if not user_id:
        user_id = str(uuid.uuid4())
        save_user(user_id, None, None)
    content = f'''
<div class="hero" style="margin-bottom: 30px;">
    <h1 style="font-size: 36px;">🔥 Бесплатная 30-минутная консультация</h1>
    <p style="font-size: 18px;">«Не люблю гадать. Давай созвонимся на 30 минут. Ты расскажешь — я скажу, где у тебя дыра и как её заткнуть.»</p>
</div>
<div class="form-card" style="text-align: center;">
    <form action="/consultation/submit" method="post" id="consultationForm">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group"><label>📞 Твой телефон</label><input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required><p style="font-size: 12px; color: #6e6e73;">Только для связи. Спама не будет.</p></div>
        <div class="form-group"><label>🕐 Удобное время для звонка (по Москве)</label><input type="text" name="time" placeholder="например: завтра в 15:00" required></div>
        <div class="form-group"><label>✏️ Твой вопрос (кратко)</label><textarea name="question" rows="3"></textarea></div>
        <div class="form-group">
            <label style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" name="consent" required style="width: 20px; height: 20px;">
                <span>Я принимаю условия публичной оферты и даю согласие на обработку персональных данных</span>
            </label>
        </div>
        <button type="submit" class="btn-main" style="width: 100%; margin-top: 16px;" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">📅 Отправить заявку</button>
    </form>
</div>
<script>
    document.getElementById('consultationForm').addEventListener('submit', function(e) {{
        const btn = this.querySelector('button[type="submit"]');
        btn.disabled = true;
        btn.textContent = '⏳ Отправляю...';
    }});
</script>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/consultation/submit")
async def consultation_submit(
    request: Request,
    user_id: str = Form(...),
    phone: str = Form(...),
    time: str = Form(...),
    question: str = Form(None),
    consent: str = Form(...)
):
    save_consultation_request(user_id, phone, time, question)
    save_user(user_id, phone, None)
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    save_consent(user_id, 'consultation', client_ip, user_agent)
    await send_notification_to_channel(
        f"📞 НОВАЯ ЗАЯВКА НА КОНСУЛЬТАЦИЮ\n\n"
        f"Пользователь: {user_id}\nТелефон: {phone}\nВремя: {time}\nВопрос: {question}\n⏰ {format_moscow_time()}"
    )
    return RedirectResponse(url=f"/subscribe?user_id={user_id}", status_code=303)

@app.get("/subscribe", response_class=HTMLResponse)
async def subscribe_page(user_id: str):
    content = f'''
<div class="hero" style="margin-bottom: 30px;">
    <h1 style="font-size: 36px;">🤝 Осталось одно движение</h1>
    <p style="font-size: 18px;">Подпишись на мой канал в MAX — там я показываю, как реально делаю воронки и запуски. После подписки я увижу тебя и напишу, чтобы согласовать звонок.</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="margin: 30px 0;"><a href="https://max.ru/id781407988795_biz" target="_blank" class="btn-main" style="width: 80%; padding: 16px;">📢 Подписаться на канал</a></div>
    <p>После подписки я проверю и напишу тебе в MAX для согласования времени.</p>
    <div style="margin-top: 30px;"><a href="/" class="btn-main" style="background: transparent; color: #007aff; box-shadow: none;">На главную</a></div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# ========================
# СТРАНИЦЫ ОФЕРТЫ И ПОЛИТИКИ (полные тексты из документов)
# ========================
@app.get("/oferta", response_class=HTMLResponse)
async def oferta_page():
    content = """
<div class="hero" style="margin-bottom: 20px;">
    <h1>Публичная оферта</h1>
    <p style="font-size: 14px; color: #6e6e73;">о заключении договора купли-продажи цифрового товара</p>
</div>
<div class="form-card" style="text-align: left; max-width: 800px;">
    <p><strong>Индивидуальный предприниматель Макаревич Вероника Александровна,</strong><br>
    ИНН 781407988795, зарегистрированная в качестве налогоплательщика<br>
    налога на профессиональный доход (самозанятая),<br>
    размещая настоящий документ на сайте<br>
    realplanninig-oss-salesplan-web-7eb2.twc1.net (далее — «Сайт»),<br>
    предлагает неограниченному кругу лиц (далее — «Покупатель»)<br>
    заключить договор купли-продажи цифрового товара на условиях, изложенных ниже.</p>

    <h3>1. ТЕРМИНЫ И ОПРЕДЕЛЕНИЯ</h3>
    <p>1.1. Цифровой товар — профессиональный маркетинговый план продаж, сгенерированный с использованием искусственного интеллекта на основе данных, предоставленных Покупателем, предоставляемый в электронном виде в формате текстового файла (.txt) через Сайт.</p>
    <p>1.2. Сайт — интернет-страница, расположенная по адресу: realplanninig-oss-salesplan-web-7eb2.twc1.net</p>
    <p>1.3. Продавец — Индивидуальный предприниматель Макаревич Вероника Александровна, ИНН 781407988795, статус: ИП, применяет налог на профессиональный доход (самозанятая).</p>
    <p>1.4. Покупатель — любое физическое или юридическое лицо, акцептовавшее настоящую оферту.</p>

    <h3>2. ПРЕДМЕТ ДОГОВОРА</h3>
    <p>2.1. Продавец обязуется передать в собственность Покупателю Цифровой товар, а Покупатель обязуется оплатить его в порядке и на условиях, предусмотренных настоящей офертой.</p>
    <p>2.2. Цифровой товар передается Покупателю в момент получения доступа к файлу для скачивания после полной оплаты.</p>

    <h3>3. СТОИМОСТЬ И ПОРЯДОК ОПЛАТЫ</h3>
    <p>3.1. Стоимость Цифрового товара составляет 490 (Четыреста девяносто) рублей.</p>
    <p>3.2. Оплата производится через платежную систему ЮKassa (ООО «ЮMoney») с использованием банковской карты или иных доступных способов.</p>
    <p>3.3. Оплата считается произведенной в момент поступления денежных средств на счет Продавца.</p>
    <p>3.4. Продавец не является плательщиком НДС в силу применения налогового режима «Налог на профессиональный доход» (самозанятость).</p>

    <h3>4. ПОРЯДОК ПЕРЕДАЧИ ЦИФРОВОГО ТОВАРА</h3>
    <p>4.1. После успешной оплаты Покупателю автоматически открывается доступ к странице с Цифровым товаром для скачивания.</p>
    <p>4.2. Цифровой товар считается переданным надлежащим образом в момент предоставления доступа к файлу для скачивания.</p>
    <p>4.3. Продавец не несет ответственности за невозможность скачать Цифровой товар по техническим причинам на стороне Покупателя (отсутствие интернета, блокировка провайдером и т.п.).</p>

    <h3>5. ПОРЯДОК ВОЗВРАТА ДЕНЕЖНЫХ СРЕДСТВ</h3>
    <p>5.1. В соответствии со ст. 26.1 Закона РФ «О защите прав потребителей» цифровой товар надлежащего качества возврату не подлежит.</p>
    <p>5.2. Возврат денежных средств возможен в следующих исключительных случаях:<br>
    — Цифровой товар не может быть открыт / прочитан по техническим причинам;<br>
    — Цифровой товар не соответствует описанию (ошибка в предоставленном файле);<br>
    — Двойная оплата одного и того же заказа.</p>
    <p>5.3. Для возврата Покупатель должен обратиться к Продавцу по контактам, указанным в разделе 10, в течение 3 (трех) дней с момента оплаты.</p>
    <p>5.4. При подтверждении оснований для возврата Продавец обязуется вернуть денежные средства в течение 3 (трех) рабочих дней с момента получения заявления от Покупателя.</p>
    <p>5.5. Возврат осуществляется на ту же банковскую карту или счет, с которого производилась оплата.</p>

    <h3>6. ОТВЕТСТВЕННОСТЬ СТОРОН</h3>
    <p>6.1. Цифровой товар предоставляется «как есть» (as is). Продавец не гарантирует достижение Покупателем каких-либо финансовых или бизнес-результатов при использовании Цифрового товара.</p>
    <p>6.2. Продавец не несет ответственности за убытки Покупателя, возникшие в результате использования Цифрового товара.</p>

    <h3>7. ИНТЕЛЛЕКТУАЛЬНАЯ СОБСТВЕННОСТЬ</h3>
    <p>7.1. Цифровой товар является результатом интеллектуальной деятельности Продавца (с использованием нейросетей). Все исключительные права на Цифровой товар принадлежат Продавцу.</p>
    <p>7.2. Покупатель получает право личного некоммерческого использования Цифрового товара. Запрещается:<br>
    — перепродажа Цифрового товара;<br>
    — распространение в открытом доступе;<br>
    — копирование и тиражирование в коммерческих целях;<br>
    — выдача Цифрового товара за свой собственный.</p>

    <h3>8. ПЕРСОНАЛЬНЫЕ ДАННЫЕ И КОНФИДЕНЦИАЛЬНОСТЬ</h3>
    <p>8.1. Вопросы обработки персональных данных регулируются Политикой обработки персональных данных, размещенной на Сайте по адресу: realplanninig-oss-salesplan-web-7eb2.twc1.net/privacy</p>
    <p>8.2. Направляя данные через формы на Сайте, Покупатель дает согласие на их обработку в соответствии с указанной Политикой.</p>

    <h3>9. ФОРС-МАЖОР</h3>
    <p>9.1. Стороны освобождаются от ответственности за полное или частичное неисполнение обязательств, если это явилось следствием обстоятельств непреодолимой силы (стихийные бедствия, военные действия, решения органов власти, блокировки интернет-ресурсов и т.п.).</p>

    <h3>10. КОНТАКТЫ ПРОДАВЦА</h3>
    <p>— Индивидуальный предприниматель: Макаревич Вероника Александровна<br>
    — ИНН: 781407988795<br>
    — Email: veranikamakarevich@yandex.ru<br>
    — MAX-канал: https://max.ru/id781407988795_biz</p>

    <h3>11. ЗАКЛЮЧИТЕЛЬНЫЕ ПОЛОЖЕНИЯ</h3>
    <p>11.1. Акцептом настоящей оферты является совершение Покупателем действий по оплате Цифрового товара и/или проставление галочки в чекбоксе «Я принимаю условия публичной оферты».</p>
    <p>11.2. Продавец вправе изменять условия оферты в одностороннем порядке. Изменения вступают в силу с момента их опубликования на Сайте.</p>
    <p>Дата публикации: «05» мая 2026 г.</p>
</div>
"""
    return HTMLResponse(content=render_page(content))

@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    content = """
<div class="hero" style="margin-bottom: 20px;">
    <h1>Политика обработки персональных данных</h1>
    <p style="font-size: 14px; color: #6e6e73;">Индивидуального предпринимателя Макаревич Вероники Александровны</p>
</div>
<div class="form-card" style="text-align: left; max-width: 800px;">
    <h3>1. ОБЩИЕ ПОЛОЖЕНИЯ</h3>
    <p>1.1. Настоящая Политика определяет порядок обработки и защиты персональных данных лиц, использующих сайт realplanninig-oss-salesplan-web-7eb2.twc1.net (далее — «Сайт»).</p>
    <p>1.2. Оператор персональных данных: Индивидуальный предприниматель Макаревич Вероника Александровна, ИНН 781407988795.</p>
    <p>1.3. Настоящая Политика составлена во исполнение требований Федерального закона от 27.07.2006 № 152-ФЗ «О персональных данных» (с изменениями на 2026 год).</p>
    <p>1.4. Используя Сайт и заполняя формы, Пользователь выражает согласие с условиями настоящей Политики.</p>

    <h3>2. КАКИЕ ДАННЫЕ СОБИРАЮТСЯ</h3>
    <p>2.1. Оператор собирает следующие персональные данные:<br>
    — Номер телефона (обязательно)<br>
    — Имя (опционально)<br>
    — Название бизнеса и описание бизнеса<br>
    — Ответы на вопросы анкеты (7 вопросов о бизнесе)</p>
    <p>2.2. Технические данные, собираемые автоматически:<br>
    — IP-адрес<br>
    — User-Agent (тип браузера и устройства)<br>
    — Дата и время посещения<br>
    — Страница, с которой совершен переход (Referrer)</p>

    <h3>3. ЦЕЛИ ОБРАБОТКИ ПЕРСОНАЛЬНЫХ ДАННЫХ</h3>
    <p>3.1. Основные цели:<br>
    — Предоставление доступа к сервису маркетинговой диагностики<br>
    — Генерация индивидуального маркетингового плана на основе анкеты<br>
    — Обработка платежей через ЮKassa (ООО «ЮMoney»)<br>
    — Направление ссылки на скачивание отчета<br>
    — Направление информации о статусе заказа<br>
    — Улучшение работы Сайта и сервиса<br>
    — Ведение статистики посещений (Яндекс.Метрика)</p>
    <p>3.2. Второстепенные цели (с отдельным согласием Пользователя):<br>
    — Направление информационных и рекламных рассылок (если Пользователь подписался)</p>

    <h3>4. ПРАВОВЫЕ ОСНОВАНИЯ ОБРАБОТКИ</h3>
    <p>4.1. Оператор обрабатывает персональные данные на основании:<br>
    — Согласия субъекта персональных данных (отдельный чекбокс на Сайте)<br>
    — Договора (публичной оферты), стороной которого является субъект<br>
    — Исполнения обязательств, предусмотренных законодательством РФ</p>

    <h3>5. ПОРЯДОК И УСЛОВИЯ ОБРАБОТКИ</h3>
    <p>5.1. Обработка данных включает: сбор, запись, систематизацию, накопление, хранение, уточнение, извлечение, использование, передачу, блокирование, удаление, уничтожение.</p>
    <p>5.2. Срок хранения персональных данных: 3 (три) года с момента последнего взаимодействия с Пользователем либо до момента отзыва согласия, если отзыв не противоречит законодательству.</p>
    <p>5.3. Хранение данных осуществляется на серверах, расположенных на территории Российской Федерации.<br>
    — Хостинг-провайдер: ООО «ТаймВеб» (Timeweb), Россия, Санкт-Петербург<br>
    — Сайт хостинга: https://timeweb.cloud/</p>
    <p>5.4. Оператор не передает персональные данные третьим лицам, за исключением:<br>
    — Платежной системы ЮKassa (ООО «ЮMoney») — для проведения платежа<br>
    — Хостинг-провайдера ООО «ТаймВеб» — для обеспечения работы Сайта<br>
    — По запросу уполномоченных государственных органов (в рамках закона)</p>
    <p>5.5. Доступ к персональным данным имеет только Оператор (Макаревич Вероника Александровна). Иные лица к данным доступа не имеют.</p>

    <h3>6. ПРАВА ПОЛЬЗОВАТЕЛЯ</h3>
    <p>6.1. Пользователь имеет право:<br>
    — Получить информацию о своих персональных данных, обрабатываемых Оператором<br>
    — Требовать уточнения, блокирования или уничтожения своих данных<br>
    — Отозвать согласие на обработку персональных данных<br>
    — Обжаловать действия Оператора в уполномоченном органе (Роскомнадзор)</p>
    <p>6.2. Для реализации прав необходимо направить запрос на электронную почту: veranikamakarevich@yandex.ru</p>
    <p>6.3. Оператор обязуется рассмотреть запрос и дать ответ в течение 10 (десяти) рабочих дней.</p>

    <h3>7. ЗАЩИТА ПЕРСОНАЛЬНЫХ ДАННЫХ</h3>
    <p>7.1. Оператор принимает следующие меры защиты:<br>
    — Парольная защита доступа к базам данных (SQLite с паролем)<br>
    — Использование HTTPS-шифрования (через Timeweb)<br>
    — Регулярное резервное копирование<br>
    — Ограничение круга лиц, имеющих доступ к данным (только Оператор)<br>
    — Антивирусное ПО на рабочем компьютере</p>
    <p>7.2. В случае утечки персональных данных Оператор обязуется в течение 24 часов уведомить Роскомнадзор и пострадавших лиц в порядке, установленном законодательством.</p>

    <h3>8. ИСПОЛЬЗОВАНИЕ ФАЙЛОВ COOKIE И МЕТРИК</h3>
    <p>8.1. На Сайте используется Яндекс.Метрика для сбора статистики посещений. Данные собираются в обезличенном виде.</p>
    <p>8.2. Пользователь может отключить cookie в настройках браузера.</p>

    <h3>9. ПОРЯДОК ОТЗЫВА СОГЛАСИЯ</h3>
    <p>9.1. Пользователь может отозвать согласие на обработку персональных данных, направив письменное заявление на электронную почту Оператора.</p>
    <p>9.2. В случае отзыва согласия Оператор обязуется прекратить обработку и уничтожить персональные данные в течение 30 дней, если иное не предусмотрено законом.</p>

    <h3>10. КОНТАКТЫ ОПЕРАТОРА</h3>
    <p>— Индивидуальный предприниматель: Макаревич Вероника Александровна<br>
    — ИНН: 781407988795<br>
    — Email: veranikamakarevich@yandex.ru<br>
    — MAX-канал: https://max.ru/id781407988795_biz</p>

    <h3>11. ИЗМЕНЕНИЕ ПОЛИТИКИ</h3>
    <p>11.1. Оператор вправе изменять настоящую Политику. Новая редакция вступает в силу с момента ее публикации на Сайте.</p>
    <p>Дата публикации: «05» мая 2026 г.</p>
</div>
"""
    return HTMLResponse(content=render_page(content))

# ========================
# АДМИН-ДАШБОРД И ДОПОЛНИТЕЛЬНЫЕ ЭНДПОИНТЫ
# ========================
@app.get("/download/{user_id}/{report_type}")
async def download_report(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT file_path, report_text FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    if row and row[0] and os.path.exists(row[0]):
        with open(row[0], "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content=content, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={report_type}_{user_id}.txt"})
    if row and row[1]:
        return Response(content=row[1], media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={report_type}_{user_id}.txt"})
    raise HTTPException(status_code=404, detail="Report not found")

@app.get("/admin/logs")
async def admin_logs(auth: bool = Depends(verify_admin)):
    try:
        with open(LOGS_DIR / "salesplan.log", "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]
            return Response(content="".join(lines), media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========================
# АДМИН-ДАШБОРД (без изменений)
# ========================
@app.get("/admin/dashboard")
async def admin_dashboard(auth: bool = Depends(verify_admin)):
    dashboard_html = """<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Админ-дашборд | Salesplan</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>
        *{margin:0;padding:0;box-sizing:border-box} body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f7;padding:20px}
        .container{max-width:1400px;margin:0 auto} h1{font-size:28px;margin-bottom:20px}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
        .stat-card{background:#fff;border-radius:16px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
        .stat-card h3{font-size:14px;color:#6e6e73;margin-bottom:8px}
        .stat-card .value{font-size:32px;font-weight:700;color:#1d1d1f}
        .stat-card .trend{font-size:12px;color:#34c759;margin-top:8px}
        .chart-container{background:#fff;border-radius:16px;padding:20px;margin-bottom:30px;box-shadow:0 2px 8px rgba(0,0,0,0.05)} canvas{max-height:350px}
        .funnel-container{background:#fff;border-radius:16px;padding:20px;margin-bottom:30px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
        .funnel-step{display:flex;align-items:center;margin:15px 0;padding:15px;background:#f8f8fa;border-radius:12px}
        .funnel-step .step-name{width:200px;font-weight:600}
        .funnel-step .step-count{width:100px;font-size:24px;font-weight:700;color:#007aff}
        .funnel-step .step-bar{flex:1;height:30px;background:#e5e5ea;border-radius:15px;overflow:hidden}
        .funnel-step .step-fill{height:100%;background:#007aff;border-radius:15px;display:flex;align-items:center;justify-content:flex-end;padding-right:10px;color:#fff;font-size:12px}
        .tabs{display:flex;gap:10px;margin-bottom:20px;border-bottom:1px solid #e5e5e5;flex-wrap:wrap}
        .tab{padding:12px 24px;cursor:pointer;border:none;background:none;font-size:16px;transition:all 0.2s}
        .tab.active{border-bottom:2px solid #007aff;color:#007aff;font-weight:500}
        .table-container{background:#fff;border-radius:16px;padding:20px;overflow-x:auto} table{width:100%;border-collapse:collapse}
        th,td{padding:12px;text-align:left;border-bottom:1px solid #e5e5e5} th{background:#f8f8fa;font-weight:600}
        .badge{display:inline-block;padding:4px 8px;border-radius:12px;font-size:12px}
        .badge-success{background:#34c75920;color:#248a3d} .badge-pending{background:#ff9f0a20;color:#cc7b00}
        .report-link{color:#007aff;text-decoration:none} .expand-btn{cursor:pointer;color:#007aff;font-size:12px}
        .row-detail{display:none;background:#f8f8fa} .row-detail td{padding:20px}
        .detail-section{margin-bottom:15px} .detail-section strong{display:block;margin-bottom:5px}
        .detail-answers{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
        .answer-tag{background:#e5e5ea;padding:4px 12px;border-radius:20px;font-size:12px}
        @media (max-width:700px){.funnel-step{flex-wrap:wrap}.funnel-step .step-name{width:100%;margin-bottom:10px}.stats-grid{grid-template-columns:repeat(2,1fr)}}
    </style></head>
<body><div class="container">
<h1>📊 Воронка продаж — Salesplan</h1>
<div class="stats-grid" id="statsGrid">
    <div class="stat-card"><h3>👥 Уникальных посетителей</h3><div class="value" id="totalVisitors">-</div></div>
    <div class="stat-card"><h3>📝 Бесплатных диагностик</h3><div class="value" id="totalDiagnostics">-</div><div class="trend" id="convVisitToDiag">-</div></div>
    <div class="stat-card"><h3>💳 Оплатили план</h3><div class="value" id="totalPayments">-</div><div class="trend" id="convDiagToPayment">-</div></div>
    <div class="stat-card"><h3>📥 Скачали отчет</h3><div class="value" id="totalDownloads">-</div></div>
    <div class="stat-card"><h3>💰 Выручка</h3><div class="value" id="totalRevenue">-</div></div>
</div>
<div class="funnel-container"><h3>🎯 Воронка продаж (за 7 дней)</h3><div id="funnelSteps"></div></div>
<div class="chart-container"><canvas id="funnelChart"></canvas></div>
<div class="tabs"><button class="tab active" onclick="showTab('clients')">👥 Оплатившие клиенты</button><button class="tab" onclick="showTab('diagnostics')">📝 Бесплатные диагностики</button><button class="tab" onclick="showTab('consultations')">📞 Заявки на консультации</button></div>
<div id="clientsTab" class="table-container"><h3>💰 Клиенты, оплатившие премиум-план</h3><table id="clientsTable"><thead><tr><th>Дата</th><th>Телефон</th><th>Бизнес</th><th>Анкета</th><th>Отчет</th><th></th></tr></thead><tbody></tbody></table></div>
<div id="diagnosticsTab" class="table-container" style="display:none"><h3>📝 Бесплатные диагностики</h3><table id="diagnosticsTable"><thead><tr><th>Дата</th><th>Бизнес</th><th>Анкета</th><th>Статус</th><th></th></tr></thead><tbody></tbody></table></div>
<div id="consultationsTab" class="table-container" style="display:none"><h3>📞 Заявки на консультации</h3><table id="consultationsTable"><thead><tr><th>Дата</th><th>Телефон</th><th>Желаемое время</th></tr></thead><tbody></tbody></table></div>
</div>
<script>
let clientsData=[];
async function loadStats(){const res=await fetch('/admin/api/stats');const data=await res.json();
document.getElementById('totalVisitors').innerText=data.summary.visitors;
document.getElementById('totalDiagnostics').innerText=data.summary.diagnostics;
document.getElementById('totalPayments').innerText=data.summary.payments;
document.getElementById('totalDownloads').innerText=data.summary.downloads;
document.getElementById('totalRevenue').innerText=data.summary.total_revenue.toLocaleString()+' ₽';
document.getElementById('convVisitToDiag').innerHTML=`📈 Конверсия: ${data.summary.conv_visit_to_diag}%`;
document.getElementById('convDiagToPayment').innerHTML=`📈 Конверсия: ${data.summary.conv_diag_to_payment}%`;
const funnelDiv=document.getElementById('funnelSteps');
const steps=[[{name:'👥 Посетители сайта',key:'visitors',color:'#007aff'},{name:'📝 Бесплатная диагностика',key:'diagnostics',color:'#5856d6'},{name:'💳 Оплата плана (490₽)',key:'payments',color:'#ff9f0a'},{name:'📥 Скачивание отчета',key:'downloads',color:'#34c759'}]];
const maxCount=Math.max(data.summary.visitors,1);
funnelDiv.innerHTML=steps[0].map(step=>{const count=data.summary[step.key];const percent=(count/maxCount*100).toFixed(1);return `<div class="funnel-step"><div class="step-name">${step.name}</div><div class="step-count">${count}</div><div class="step-bar"><div class="step-fill" style="width:${percent}%;background:${step.color}">${percent}%</div></div></div>`;}).join('');
const ctx=document.getElementById('funnelChart').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:data.funnel.map(d=>d.date),datasets:[{label:'👥 Посетители',data:data.funnel.map(d=>d.visitors),borderColor:'#007aff',backgroundColor:'#007aff20',tension:0.3,fill:true},{label:'📝 Диагностики',data:data.funnel.map(d=>d.diagnostics),borderColor:'#5856d6',backgroundColor:'#5856d620',tension:0.3,fill:true},{label:'💳 Оплаты',data:data.funnel.map(d=>d.payments),borderColor:'#ff9f0a',backgroundColor:'#ff9f0a20',tension:0.3,fill:true},{label:'📥 Скачивания',data:data.funnel.map(d=>d.downloads),borderColor:'#34c759',backgroundColor:'#34c75920',tension:0.3,fill:true}]},options:{responsive:true,maintainAspectRatio:true}});}
async function loadClients(){const res=await fetch('/admin/api/clients');const data=await res.json();clientsData=data.clients;const tbody=document.querySelector('#clientsTable tbody');tbody.innerHTML='';
data.clients.forEach(client=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(client.payment_date).toLocaleDateString()}</td><td>${client.phone||'-'}</td><td><strong>${client.business_name||'-'}</strong><br><small>${(client.business_description||'').substring(0,50)}...</small></td><td><span class="expand-btn" onclick="showAnswers(${JSON.stringify(client).replace(/"/g,'&quot;')})">📋 Показать анкету</span></td><td>${client.report_path?'<a href="/download/'+client.user_id+'/premium" class="report-link">📥 Скачать отчет</a>':'<span class="badge badge-pending">генерация...</span>'}</td><td><span class="expand-btn" onclick="toggleDetail(this)">▶ Подробнее</span></td>`;const detailRow=tbody.insertRow();detailRow.className='row-detail';detailRow.style.display='none';detailRow.innerHTML=`<td colspan="6"><div class="detail-section"><strong>📝 Полная анкета:</strong><div class="detail-answers"><span class="answer-tag">Продаёт: ${client.q1||'-'}</span><span class="answer-tag">Чек: ${client.q2||'-'}</span><span class="answer-tag">Клиентов: ${client.q3||'-'}</span><span class="answer-tag">Цель: ${client.q4||'-'}</span><span class="answer-tag">Воронка: ${client.q5||'-'}</span></div></div><div class="detail-section"><strong>📄 Описание бизнеса:</strong><br>${client.business_description||'-'}</div>`;});}
async function loadDiagnostics(){const res=await fetch('/admin/api/diagnostics');const data=await res.json();const tbody=document.querySelector('#diagnosticsTable tbody');tbody.innerHTML='';data.diagnostics.forEach(d=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(d.date).toLocaleString()}</td><td><strong>${d.business_name||'-'}</strong><br><small>${(d.business_description||'').substring(0,50)}...</small></td><td><span class="expand-btn" onclick="showAnswersDialog('${d.q1}','${d.q2}','${d.q3}','${d.q4}','${d.q5}')">📋 Показать</span></td><td><span class="badge ${d.report_status==='ready'?'badge-success':'badge-pending'}">${d.report_status==='ready'?'✅ Готов':'⏳ Генерация'}</span></td><td>${d.report_status==='ready'?'<a href="/download/'+d.user_id+'/free" class="report-link">📥 Скачать</a>':'-'}</td>`;});}
async function loadConsultations(){const res=await fetch('/admin/api/consultations');const data=await res.json();const tbody=document.querySelector('#consultationsTable tbody');tbody.innerHTML='';data.consultations.forEach(c=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(c.created_at).toLocaleString()}</td><td>${c.phone||'-'}</td><td>${c.time||'-'}</td>`;});}
function toggleDetail(btn){const row=btn.closest('tr');const detailRow=row.nextElementSibling;if(detailRow&&detailRow.classList.contains('row-detail')){const isHidden=detailRow.style.display==='none';detailRow.style.display=isHidden?'table-row':'none';btn.innerText=isHidden?'▼ Скрыть':'▶ Подробнее';}}
function showAnswers(client){alert(`📋 АНКЕТА КЛИЕНТА\n\nПродаёт: ${client.q1||'-'}\nСредний чек: ${client.q2||'-'}\nКлиентов/мес: ${client.q3||'-'}\nЦель: ${client.q4||'-'}\nАвтоворонка: ${client.q5||'-'}`);}
function showAnswersDialog(q1,q2,q3,q4,q5){alert(`📋 АНКЕТА\n\nПродаёт: ${q1||'-'}\nСредний чек: ${q2||'-'}\nКлиентов/мес: ${q3||'-'}\nЦель: ${q4||'-'}\nАвтоворонка: ${q5||'-'}`);}
function showTab(tab){document.getElementById('clientsTab').style.display=tab==='clients'?'block':'none';document.getElementById('diagnosticsTab').style.display=tab==='diagnostics'?'block':'none';document.getElementById('consultationsTab').style.display=tab==='consultations'?'block':'none';document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));event.target.classList.add('active');}
loadStats();loadClients();loadDiagnostics();loadConsultations();setInterval(()=>{loadStats();loadClients();loadDiagnostics();},30000);
</script>
</body>
</html>"""
    return HTMLResponse(content=dashboard_html)

@app.get("/admin/api/stats")
async def admin_stats(auth: bool = Depends(verify_admin)):
    days = 7
    funnel = get_full_funnel(days)
    conn = sqlite3.connect(DB_PATH)
    total_revenue = conn.execute("SELECT SUM(amount) FROM payments WHERE status = 'succeeded'").fetchone()[0] or 0
    conn.close()
    total_visitors = sum(f['visitors'] for f in funnel)
    total_diagnostics = sum(f['diagnostics'] for f in funnel)
    total_payments = len([p for p in get_sales_funnel_stats(days) if p['payments'] > 0])
    return {"funnel": funnel, "summary": {"visitors": total_visitors, "diagnostics": total_diagnostics, "payments": total_payments, "downloads": sum(f['downloads'] for f in funnel), "conv_visit_to_diag": round(total_diagnostics / max(total_visitors,1)*100,1), "conv_diag_to_payment": round(total_payments / max(total_diagnostics,1)*100,1), "total_revenue": total_revenue}}

@app.get("/admin/api/clients")
async def admin_clients(auth: bool = Depends(verify_admin)):
    return {"clients": get_all_premium_clients()}

@app.get("/admin/api/diagnostics")
async def admin_diagnostics(auth: bool = Depends(verify_admin)):
    return {"diagnostics": get_all_free_diagnostics()}

@app.get("/admin/api/consultations")
async def admin_consultations(auth: bool = Depends(verify_admin)):
    return {"consultations": get_new_consultations()}

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
