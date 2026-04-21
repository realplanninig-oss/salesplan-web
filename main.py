# File: main.py — веб-приложение Salesplan с админ-дашбордом

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

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn

# Загружаем переменные окружения
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

# Проверка обязательных переменных
missing_vars = []
if not DEEPSEEK_API_KEY:
    missing_vars.append("DEEPSEEK_API_KEY")
if not YOOKASSA_SHOP_ID:
    missing_vars.append("YOOKASSA_SHOP_ID")
if not YOOKASSA_SECRET_KEY:
    missing_vars.append("YOOKASSA_SECRET_KEY")

if missing_vars:
    print(f"⚠️ WARNING: Missing environment variables: {missing_vars}")
    print("   Some features may not work correctly!")

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
    # Существующие таблицы
    conn.execute("CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, phone TEXT, name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS business_data (user_id TEXT PRIMARY KEY, business_name TEXT, business_description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS forms (user_id TEXT PRIMARY KEY, q1 TEXT, q2 TEXT, q3 TEXT, q4 TEXT, q5 TEXT, q6 TEXT, q7 TEXT, completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, report_type TEXT NOT NULL, report_text TEXT, file_path TEXT, status TEXT DEFAULT 'generating', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ready_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS consultations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, time TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, phone TEXT, yookassa_payment_id TEXT, amount TEXT, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    
    # Таблица для отслеживания посещений
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
    
    # Новая таблица для согласий на обработку персональных данных
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
    
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="Salesplan Web")

# === MIDDLEWARE ДЛЯ ЗАЩИТЫ И ОТСЛЕЖИВАНИЯ ===
BLOCKED_PATHS = [
    "/_next", "/api/route", "/app", "/wp-content", "/wp-admin", "/cgi-bin",
    "/.env", "/.git", "/robots.txt", "/api", "/_next/server"
]

@app.middleware("http")
async def track_and_block_requests(request: Request, call_next):
    path = request.url.path
    user_agent = request.headers.get("user-agent", "").lower()
    client_ip = request.client.host if request.client else "unknown"
    
    # Отслеживаем посещения основных страниц
    if path in ["/", "/survey", "/diagnostic", "/payment", "/payment/success"]:
        track_visit(ip=client_ip, user_agent=user_agent)
    
    # Блокировка вредоносных путей
    if path == "/favicon.ico":
        return await call_next(request)
    
    for blocked in BLOCKED_PATHS:
        if path.startswith(blocked):
            logger.warning(f"Blocked malicious path: {path} from {client_ip}")
            return Response(status_code=404)
    
    # Блокировка ботов
    bad_bots = ["bot", "crawler", "scanner", "nikto", "sqlmap", "wget", "curl", "python-requests", "java"]
    for bot in bad_bots:
        if bot in user_agent and "yandex" not in user_agent and "google" not in user_agent:
            logger.warning(f"Blocked bot: {user_agent} from {client_ip}")
            return Response(status_code=403)
    
    response = await call_next(request)
    return response

# === ФУНКЦИИ ДЛЯ ОТСЛЕЖИВАНИЯ ПОСЕЩЕНИЙ ===
def track_visit(user_id=None, ip=None, user_agent=None):
    """Отслеживание уникальных посетителей"""
    conn = sqlite3.connect(DB_PATH)
    today = datetime.now().strftime('%Y-%m-%d')
    
    if ip:
        cursor = conn.execute("""
            SELECT id FROM visits 
            WHERE ip = ? AND visit_date = ? 
            LIMIT 1
        """, (ip, today))
        
        if not cursor.fetchone():
            conn.execute("""
                INSERT INTO visits (visit_date, ip, user_agent)
                VALUES (?, ?, ?)
            """, (today, ip, user_agent[:500] if user_agent else None))
    
    conn.commit()
    conn.close()

def get_unique_visitors(days=7):
    """Уникальные посетители по дням"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT 
            visit_date,
            COUNT(DISTINCT ip) as unique_visitors,
            COUNT(*) as total_visits
        FROM visits
        WHERE visit_date >= date('now', ?)
        GROUP BY visit_date
        ORDER BY visit_date DESC
    """, (f'-{days} days',))
    
    results = [{"date": r[0], "visitors": r[1], "total_visits": r[2]} for r in cursor.fetchall()]
    conn.close()
    return results

def get_sales_funnel_stats(days=7):
    """Получить данные по оплатам за N дней"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT 
            date(created_at) as date,
            COUNT(DISTINCT CASE WHEN status = 'succeeded' THEN user_id END) as payments,
            SUM(CASE WHEN status = 'succeeded' THEN 490 ELSE 0 END) as revenue
        FROM payments
        WHERE created_at >= date('now', ?)
        GROUP BY date(created_at)
        ORDER BY date DESC
    """, (f'-{days} days',))
    
    results = [{"date": r[0], "payments": r[1], "revenue": r[2]} for r in cursor.fetchall()]
    conn.close()
    return results

def get_free_diagnostics_stats(days=7):
    """Статистика по бесплатной диагностике"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT 
            date(completed_at) as date,
            COUNT(*) as total
        FROM forms
        WHERE completed_at >= date('now', ?)
        GROUP BY date(completed_at)
        ORDER BY date DESC
    """, (f'-{days} days',))
    
    results = [{"date": r[0], "diagnostics": r[1]} for r in cursor.fetchall()]
    conn.close()
    return results

def get_report_downloads_stats(days=7):
    """Статистика скачиваний отчетов"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT 
            date(ready_at) as date,
            COUNT(*) as downloads
        FROM reports
        WHERE report_type = 'premium' 
            AND status = 'ready'
            AND ready_at >= date('now', ?)
        GROUP BY date(ready_at)
        ORDER BY date DESC
    """, (f'-{days} days',))
    
    results = [{"date": r[0], "downloads": r[1]} for r in cursor.fetchall()]
    conn.close()
    return results

def get_full_funnel(days=7):
    """Полная воронка по дням"""
    visitors = {v['date']: v['visitors'] for v in get_unique_visitors(days)}
    diagnostics = {d['date']: d['diagnostics'] for d in get_free_diagnostics_stats(days)}
    payments = {p['date']: p['payments'] for p in get_sales_funnel_stats(days)}
    downloads = {d['date']: d['downloads'] for d in get_report_downloads_stats(days)}
    
    all_dates = set(visitors.keys()) | set(diagnostics.keys()) | set(payments.keys()) | set(downloads.keys())
    all_dates = sorted(list(all_dates), reverse=True)[:days]
    
    funnel = []
    for date in all_dates:
        funnel.append({
            "date": date,
            "visitors": visitors.get(date, 0),
            "diagnostics": diagnostics.get(date, 0),
            "payments": payments.get(date, 0),
            "downloads": downloads.get(date, 0)
        })
    
    return funnel

def get_all_premium_clients():
    """Получить всех оплативших клиентов с анкетами и отчетами"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT 
            p.user_id,
            p.phone,
            p.created_at as payment_date,
            b.business_name,
            b.business_description,
            f.q1, f.q2, f.q3, f.q4, f.q5,
            r.file_path,
            r.status as report_status,
            r.ready_at
        FROM payments p
        LEFT JOIN business_data b ON p.user_id = b.user_id
        LEFT JOIN forms f ON p.user_id = f.user_id
        LEFT JOIN reports r ON p.user_id = r.user_id AND r.report_type = 'premium'
        WHERE p.status = 'succeeded'
        ORDER BY p.created_at DESC
    """)
    
    columns = ['user_id', 'phone', 'payment_date', 'business_name', 
               'business_description', 'q1', 'q2', 'q3', 'q4', 'q5',
               'report_path', 'report_status', 'report_ready_at']
    
    results = []
    for row in cursor.fetchall():
        results.append(dict(zip(columns, row)))
    
    conn.close()
    return results

def get_all_free_diagnostics():
    """Получить все бесплатные диагностики"""
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
        LEFT JOIN reports r ON f.user_id = r.user_id AND r.report_type = 'free'
        ORDER BY f.completed_at DESC
        LIMIT 100
    """)
    
    columns = ['user_id', 'date', 'business_name', 'business_description', 
               'q1', 'q2', 'q3', 'q4', 'q5', 'report_status', 'report_text']
    
    results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return results

def get_new_consultations():
    """Новые заявки на консультации"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("""
        SELECT c.*, u.phone, u.name
        FROM consultations c
        LEFT JOIN users u ON c.user_id = u.user_id
        ORDER BY c.created_at DESC
        LIMIT 50
    """)
    
    columns = ['id', 'user_id', 'time', 'created_at', 'phone', 'name']
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

def save_consent(user_id: str, consent_type: str, ip: str = None, user_agent: str = None):
    """Сохраняет согласие пользователя (оферта или персональные данные)"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO user_consents (user_id, consent_type, ip, user_agent)
        VALUES (?, ?, ?, ?)
    """, (user_id, consent_type, ip, user_agent[:500] if user_agent else None))
    conn.commit()
    conn.close()
    logger.info(f"Consent saved: user_id={user_id}, type={consent_type}")

def call_deepseek_diagnostic(name: str, description: str, answers: dict) -> str:
    if not DEEPSEEK_API_KEY:
        logger.error("DEEPSEEK_API_KEY not configured")
        return None
    
    q1_map = {"Услугу": "Услугу", "Инфопродукт": "Инфопродукт", "Консультацию": "Консультацию", "Пока не продаю": "Пока не продаю"}
    q2_map = {"до 5k": "до 5000 ₽", "5k-20k": "5000-20000 ₽", "20k-50k": "20000-50000 ₽", ">50k": "более 50000 ₽"}
    q3_map = {"<10": "менее 10", "10-50": "10-50", "50-200": "50-200", ">200": "более 200"}
    q4_map = {"300k/мес": "300 000 ₽/мес", "500k/мес": "500 000 ₽/мес", "1M/мес": "1 000 000 ₽/мес", "Масштаб": "масштабирование"}
    q5_map = {"Да": "да", "Нет": "нет", "В разработке": "в разработке"}
    
    survey_info = f"ДАННЫЕ О БИЗНЕСЕ:\n• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}\n• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}\n• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}\n• Цель на 2026: {q4_map.get(answers.get('q4'), 'не указано')}\n• Есть автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}"
    
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
        logger.error(f"DeepSeek API error: {response.status_code}")
        return None
    except Exception as e:
        logger.error(f"DeepSeek failed: {e}")
        return None

def generate_premium_report_sync(user_id: str, name: str, description: str, answers: dict, report_id: int):
    logger.info(f"Starting premium report generation for user {user_id}")
    if not DEEPSEEK_API_KEY:
        update_report_status(report_id, 'failed')
        logger.error("Cannot generate premium report: DEEPSEEK_API_KEY missing")
        return False
    
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
            logger.info(f"Premium report generated for user {user_id}")
            return True
        else:
            update_report_status(report_id, 'failed')
            logger.error(f"Premium report API error: {response.status_code}")
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

# === HEALTH CHECK ENDPOINT ===
@app.get("/health")
async def health():
    """Проверка состояния приложения и переменных окружения"""
    return {
        "status": "alive",
        "timestamp": datetime.now().isoformat(),
        "configuration": {
            "DEEPSEEK_API_KEY": "configured" if DEEPSEEK_API_KEY else "missing",
            "YOOKASSA_SHOP_ID": "configured" if YOOKASSA_SHOP_ID else "missing",
            "YOOKASSA_SECRET_KEY": "configured" if YOOKASSA_SECRET_KEY else "missing",
            "ADMIN_USERNAME": "configured",
            "ADMIN_PASSWORD": "configured" if ADMIN_PASSWORD else "missing",
        }
    }

# === HTML ШАБЛОНЫ ===
HTML_HEAD = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Salesplan</title>
    
    <!-- Яндекс.Метрика -->
    <script type="text/javascript">
        (function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};
        m[i].l=1*new Date();
        for (var j = 0; j < document.scripts.length; j++) {if (document.scripts[j].src === r) { return; }}
        k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)})
        (window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
        
        ym(108348240, "init", {
            clickmap:true,
            trackLinks:true,
            accurateTrackBounce:true,
            webvisor:true,
            ecommerce:"dataLayer"
        });
    </script>
    <noscript><div><img src="https://mc.yandex.ru/watch/108348240" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
    <!-- /Яндекс.Метрика -->
    
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
        .course-card{background:linear-gradient(135deg,#667eea10 0%,#764ba210 100%);border-radius:28px;padding:32px;margin:32px 0;text-align:left}
        @media (max-width:700px){
            .container{padding:20px 16px}
            .hero h1{font-size:32px}
            .hero p{font-size:16px}
            .form-card{padding:20px}
            input,textarea,.btn{font-size:16px}
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
                        setTimeout(() => {{
                            window.location.href = '{redirect_url}';
                        }}, 500);
                    }} else {{
                        attempts++;
                        updateProgress();
                        if (attempts < 120) {{
                            setTimeout(checkStatus, 3000);
                        }}
                    }}
                }})
                .catch(() => {{
                    setTimeout(checkStatus, 3000);
                }});
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
    <div class="progress-bar">
        <div class="progress-fill" id="progressFill"></div>
    </div>
    
    <div class="status-item" id="status1">
        <span class="status-icon pending">○</span>
        <span>🔍 Анализируем вашу нишу — кто ваши клиенты и где они тусуются</span>
    </div>
    <div class="status-item" id="status2">
        <span class="status-icon pending">○</span>
        <span>📊 Изучаем целевую аудиторию — что они хотят на самом деле</span>
    </div>
    <div class="status-item" id="status3">
        <span class="status-icon pending">○</span>
        <span>🎯 Ищем точки роста — где вы теряете деньги</span>
    </div>
    <div class="status-item" id="status4">
        <span class="status-icon pending">○</span>
        <span>📝 Формируем рекомендации — что делать прямо сейчас</span>
    </div>
    
    <p class="subtext">Пока нейросеть копается в вашей нише — я налью себе чай. Вы тоже можете. Это займёт 1-2 минуты. Страница обновится сама. Не обновляйте вручную — нейросеть обидится.</p>
</div>
</body>
</html>"""

def render_premium_waiting_page(user_id: str):
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
                        window.location.href = '/payment/success?user_id={user_id}';
                    }} else {{
                        attempts++;
                        step = Math.min(3, Math.floor(attempts / 20) + 1);
                        const step1 = document.getElementById('step1');
                        const step2 = document.getElementById('step2');
                        const step3 = document.getElementById('step3');
                        if(step1) step1.className = step >= 1 ? 'step active' : 'step';
                        if(step2) step2.className = step >= 2 ? 'step active' : 'step';
                        if(step3) step3.className = step >= 3 ? 'step active' : 'step';
                        if (attempts < 180) {{
                            setTimeout(checkStatus, 3000);
                        }}
                    }}
                }})
                .catch(() => {{
                    setTimeout(checkStatus, 3000);
                }});
        }}
        setTimeout(checkStatus, 3000);
    </script>
</head>
<body>
<div class="container">
    <div class="spinner"></div>
    <h1>📊 Анализируем рынок и конкурентов</h1>
    <p>Нейросеть уже пишет ваш план. Я пока схожу за печеньками. Вы тоже можете отвлечься — это займёт 3-5 минут.</p>
    
    <div style="margin: 30px 0;">
        <span id="step1" class="step active">1. Анализ конкурентов — кто платит и почему</span>
        <span id="step2" class="step">2. Сбор стратегии — собираем пазл</span>
        <span id="step3" class="step">3. Формирование плана — почти готово</span>
    </div>
    
    <p class="subtext">Страница обновится сама. Не нужно сидеть и сверлить экран взглядом.</p>
</div>
</body>
</html>"""

# === ОСНОВНЫЕ ЭНДПОИНТЫ ===
@app.get("/")
async def index():
    content = '''
<div class="hero">
    <h1>Вероника Макаревич | Продюсер в кармане</h1>
    <p style="font-size: 18px;">«Я не волшебник, я практик. За моими плечами 33 эксперта, которые перестали ныть и начали продавать. Услуги, онлайн-курсы — без разницы. Есть система — есть результат.»</p>
</div>

<div class="features">
    <div class="feature">
        <div class="feature-icon">⭐️</div>
        <h3>Бесплатный аудит — 2 минуты</h3>
        <p>Узнайте 3 конкретных шага, которые можно внедрить прямо сейчас</p>
    </div>
    <div class="feature">
        <div class="feature-icon">🔥</div>
        <h3>Готовая стратегия — 5 минут</h3>
        <p>План продаж с анализом конкурентов и разбором ЦА</p>
    </div>
    <div class="feature">
        <div class="feature-icon">⚡️</div>
        <h3>Первое действие — 15 минут</h3>
        <p>Внедрите работающее решение, которое запустит продажи</p>
    </div>
</div>

<div style="text-align:center">
    <a href="/survey" class="btn">Начать диагностику</a>
</div>

<div style="margin-top: 40px; padding: 20px; background: #f5f5f7; border-radius: 20px; text-align: center;">
    <p style="font-size: 14px; color: #6e6e73;">Помогла 33 экспертам запустить продажи услуг и онлайн-курсов</p>
</div>
'''
    return HTMLResponse(content=render_page(content))

@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<div class="hero">
    <h1>Шаг 1 из 2. Давайте знакомиться</h1>
    <p style="font-size: 18px;">«Чем честнее ответите — тем точнее будет разбор. Обещаю: никакой магии. Только маркетинг, который работает.»</p>
</div>

<div class="form-card">
    <form action="/survey/submit" method="post" id="surveyForm">
        <div class="form-group">
            <label>1. Название бизнеса</label>
            <input type="text" name="business_name" placeholder="например: Продюсирую экспертов" required>
        </div>
        <div class="form-group">
            <label>2. Короткое описание (чем занимаетесь, кому помогаете)</label>
            <textarea name="business_description" rows="3" placeholder="Пример: Воронка: бесплатная диагностика бизнеса → план запуска продаж за 490₽ → бесплатный разбор плана за подписку в MAX" required></textarea>
        </div>
        <div class="form-group">
            <label>3. Что вы продаёте?</label>
            <div class="radio-group">
                <label><input type="radio" name="q1" value="Услугу" required> Услугу</label>
                <label><input type="radio" name="q1" value="Инфопродукт"> Инфопродукт</label>
                <label><input type="radio" name="q1" value="Консультацию"> Консультацию</label>
                <label><input type="radio" name="q1" value="Пока не продаю"> Пока не продаю</label>
            </div>
        </div>
        <div class="form-group">
            <label>4. Средний чек (₽)</label>
            <div class="radio-group">
                <label><input type="radio" name="q2" value="до 5k" required> до 5k</label>
                <label><input type="radio" name="q2" value="5k-20k"> 5k-20k</label>
                <label><input type="radio" name="q2" value="20k-50k"> 20k-50k</label>
                <label><input type="radio" name="q2" value=">50k"> >50k</label>
            </div>
        </div>
        <div class="form-group">
            <label>5. Клиентов в месяц (примерно)</label>
            <div class="radio-group">
                <label><input type="radio" name="q3" value="<10" required> меньше 10</label>
                <label><input type="radio" name="q3" value="10-50"> 10-50</label>
                <label><input type="radio" name="q3" value="50-200"> 50-200</label>
                <label><input type="radio" name="q3" value=">200"> более 200</label>
            </div>
        </div>
        <div class="form-group">
            <label>6. Цель на 2026</label>
            <div class="radio-group">
                <label><input type="radio" name="q4" value="300k/мес" required> 300k/мес</label>
                <label><input type="radio" name="q4" value="500k/мес"> 500k/мес</label>
                <label><input type="radio" name="q4" value="1M/мес"> 1M/мес</label>
                <label><input type="radio" name="q4" value="Масштаб"> Масштаб</label>
            </div>
        </div>
        <div class="form-group">
            <label>7. Уже есть автоворонка?</label>
            <div class="radio-group">
                <label><input type="radio" name="q5" value="Да" required> Да</label>
                <label><input type="radio" name="q5" value="Нет"> Нет</label>
                <label><input type="radio" name="q5" value="В разработке"> В разработке</label>
            </div>
        </div>
        <div style="text-align:center">
            <p style="margin-bottom: 20px; font-size: 14px; color: #6e6e73;">Ответьте на 7 коротких вопросов → получите персональный разбор вашего бизнеса с конкретными шагами для роста продаж</p>
            <button type="submit" class="btn" id="submitBtn" onclick="ym(108348240,'reachGoal','survey_submit'); return true;">Получить диагностику</button>
        </div>
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
    logger.info(f"New survey submission: user_id={user_id}, business={business_name}")
    
    save_user(user_id, None, None)
    save_business_data(user_id, business_name, business_description)
    save_form(user_id, {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5})
    
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
        diagnostic_text = await loop.run_in_executor(
            None, 
            call_deepseek_diagnostic, 
            business_name, 
            business_description, 
            answers
        )
        conn = sqlite3.connect(DB_PATH)
        if diagnostic_text:
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (diagnostic_text, report_id))
            logger.info(f"Free report {report_id} generated successfully")
        else:
            fallback_text = f"Диагностика для бизнеса \"{business_name}\"\n\nОписание: {business_description}\n\nРекомендации:\n- Проанализируйте целевую аудиторию\n- Настройте воронку продаж\n- Добавьте призывы к действию"
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (fallback_text, report_id))
            logger.warning(f"Free report {report_id} using fallback text")
        conn.commit()
        conn.close()
    
    asyncio.create_task(generate_and_save())
    
    return HTMLResponse(content=render_waiting_page(user_id, "free", f"/diagnostic?user_id={user_id}"))

@app.get("/check_status")
async def check_status(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type))
    row = cursor.fetchone()
    conn.close()
    ready = row and row[0] == 'ready'
    return {"ready": ready}

@app.get("/diagnostic", response_class=HTMLResponse)
async def diagnostic(user_id: str):
    logger.info(f"Diagnostic page requested for user {user_id}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT report_text FROM reports WHERE user_id = ? AND report_type = 'free' ORDER BY id DESC LIMIT 1", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row or not row[0]:
        logger.warning(f"Diagnostic not ready for user {user_id}, showing waiting page")
        return HTMLResponse(content=render_waiting_page(user_id, "free", f"/diagnostic?user_id={user_id}"))
    
    report_text_full = row[0]
    report_text_html = report_text_full.replace("\n", "<br>")
    
    content = f'''
<div class="hero">
    <h1>✨ Ваша персональная диагностика готова</h1>
    <p style="font-size: 18px;">«Держите. Это не просто текст — это карта вашего ближайшего пути к деньгам. Я подсветила слабые места и точки роста. Теперь выбор за вами.»</p>
</div>

<div class="form-card" style="text-align: center;">
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="margin: 32px 0; text-align: center;">
        <h2 style="font-size: 28px; margin-bottom: 16px;">🚀 Что дальше?</h2>
        <p style="font-size: 17px; color: #6e6e73; margin-bottom: 32px;">«Диагностика — это как сходить к терапевту. А теперь нужен спортивный тренер, который доведёт до результата.»</p>
    </div>
    
    <div style="background: linear-gradient(135deg, #007aff10 0%, #005fc510 100%); border-radius: 28px; padding: 32px; margin: 32px 0;">
        <h3 style="font-size: 24px; margin-bottom: 20px;">📋 В профессиональном маркетинговом плане запуска продаж:</h3>
        <div style="display: flex; flex-wrap: wrap; gap: 12px; justify-content: center;">
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">🎯 Разбор ЦА — кто платит и почему</span>
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">🔍 Разбор 5 конкурентов — чем они лучше и как это обойти</span>
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">⚡ Готовая воронка продаж — от подписки до чека</span>
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">📅 Контент план на месяц + 1 действие, которое запустит продажи</span>
        </div>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="margin: 32px 0;">
        <div class="price-old">4 900 ₽</div>
        <div class="price-new">490 ₽</div>
        <p style="margin-top: 8px;">«Да, я могла бы взять 4900. Но я хочу, чтобы вы сделали первый шаг. Следующие будут дороже.»</p>
        <p style="margin-top: 8px; color: #ff3b30; font-weight: 600;">🔥 Предложение действует, пока вы находитесь на этой странице. Закроете страницу — цена вернётся к 4 900 ₽.</p>
    </div>
    
    <form action="/payment/create" method="post" style="margin-top: 24px;">
        <input type="hidden" name="user_id" value="{user_id}">
        <button type="submit" class="btn" style="width: 100%; padding: 16px; font-size: 18px;" onclick="ym(108348240,'reachGoal','payment_start'); return true;">🔥 Забрать план за 490 ₽</button>
        <p style="font-size: 13px; color: #8e8e93; margin-top: 16px;">Без телефона, без смс, только польза</p>
    </form>
    
    <hr style="margin: 32px 0;">
    
    <div style="background: #f5f5f7; border-radius: 28px; padding: 28px; margin: 32px 0; text-align: left;">
        <p style="font-size: 18px; font-weight: 600; margin-bottom: 20px;">🎯 Я Вероника, продюсер экспертов</p>
        <p>За 8 лет помогла десяткам специалистов выйти на стабильные продажи. Вот несколько примеров успешных кейсов:</p>
    </div>
    
    <div style="display: flex; flex-wrap: wrap; gap: 16px; margin: 32px 0; text-align: left;">
        <div style="flex: 1; min-width: 200px; background: #ffffff; border-radius: 20px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
            <div style="font-size: 32px; margin-bottom: 12px;">🇨🇳</div>
            <p><strong>Эксперт по китайскому</strong><br>без блога, только таргет и бот<br>📈 +120 000 ₽ за 2 недели</p>
        </div>
        <div style="flex: 1; min-width: 200px; background: #ffffff; border-radius: 20px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
            <div style="font-size: 32px; margin-bottom: 12px;">🧠</div>
            <p><strong>Психолог Елена</strong><br>7 клиентов за 2 недели<br>📈 доход с 0 до 180 000 ₽</p>
        </div>
        <div style="flex: 1; min-width: 200px; background: #ffffff; border-radius: 20px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
            <div style="font-size: 32px; margin-bottom: 12px;">🌊</div>
            <p><strong>Мастер Фен Шуй</strong><br>первый запуск при рекламе 30 000 ₽<br>📈 +195 000 ₽</p>
        </div>
        <div style="flex: 1; min-width: 200px; background: #ffffff; border-radius: 20px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
            <div style="font-size: 32px; margin-bottom: 12px;">🏫</div>
            <p><strong>Онлайн-школа</strong><br>марафон в ВК за 2 недели<br>📈 +2 000 000 ₽</p>
        </div>
    </div>
    
    <div style="margin: 32px 0;">
        <a href="https://vk.ru/topic-164421538_39653658" target="_blank" class="btn btn-outline" style="margin: 10px;">📸 Реальные отзывы моих клиентов (ВКонтакте)</a>
    </div>
</div>

<script>
    ym(108348240,'reachGoal','diagnostic_got');
</script>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/payment/create")
async def payment_create(user_id: str = Form(...)):
    logger.info(f"Payment create for user {user_id}")
    return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)

@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str, status: str = None):
    error_message = ""
    if status == "cancelled":
        error_message = '<p style="color: red; margin-bottom: 20px;">❌ Платеж был отменен. Попробуйте снова.</p>'
    
    existing_report = get_report(user_id, "premium")
    if existing_report and existing_report["status"] == "ready":
        return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)
    
    content = f'''
<div class="hero">
    <h1>💰 План продаж — 490 ₽</h1>
    <p style="font-size: 18px;">«Спойлер: вы получите не просто документ, а готовую дорожную карту. Бери и делай.»</p>
</div>

<div class="form-card">
    {error_message}
    
    <h3>Что внутри:</h3>
    <ul style="margin-bottom: 20px;">
        <li>🎯 Разбор ЦА — кто платит и почему</li>
        <li>🔍 Разбор 5 конкурентов — чем они лучше и как это обойти</li>
        <li>⚡ Готовая воронка продаж — от подписки до чека</li>
        <li>📅 Контент план на месяц + 1 действие, которое запустит продажи</li>
    </ul>
    
    <div class="price-old" style="text-align:center">4 900 ₽</div>
    <div class="price-new" style="text-align:center">490 ₽</div>
    <p style="text-align:center; margin-top:8px">«Я снизила цену, чтобы вы перестали думать и начали действовать.»</p>
    
    <form action="/create_yookassa_payment" method="post" style="margin-top: 30px;" id="paymentForm">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group">
            <label>📞 Куда прислать план?</label>
            <input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required style="text-align: center; font-size: 18px;">
        </div>
        
        <!-- Чекбоксы с согласиями -->
        <div style="margin: 20px 0;">
            <label style="display: flex; align-items: flex-start; gap: 10px; background: #f5f5f7; padding: 12px; border-radius: 12px; margin-bottom: 10px; cursor: pointer;">
                <input type="checkbox" name="agree_oferta" required style="width: 18px; margin-top: 2px;">
                <span style="font-size: 13px; line-height: 1.4;">
                    Я принимаю условия 
                    <a href="/oferta" target="_blank" style="color: #007aff;">публичной оферты</a>
                </span>
            </label>
            
            <label style="display: flex; align-items: flex-start; gap: 10px; background: #f5f5f7; padding: 12px; border-radius: 12px; cursor: pointer;">
                <input type="checkbox" name="agree_personal" required style="width: 18px; margin-top: 2px;">
                <span style="font-size: 13px; line-height: 1.4;">
                    Я даю согласие на обработку моих персональных данных в соответствии с 
                    <a href="/privacy" target="_blank" style="color: #007aff;">Политикой обработки персональных данных</a>
                </span>
            </label>
        </div>
        
        <div style="text-align:center;margin:20px 0">
            <button type="submit" class="btn" style="width: 100%;" onclick="ym(108348240,'reachGoal','pay_490'); return true;">💳 Оплатить 490 ₽</button>
        </div>
    </form>
    
    <hr style="margin: 20px 0;">
    
    <div style="text-align: center; margin-top: 20px;">
        <p style="font-size: 14px; color: #6e6e73;">✅ Безопасная оплата через ЮKassa — ваши деньги под защитой</p>
        <p style="font-size: 14px; color: #6e6e73; margin-top: 10px;">❓ Не подойдёт? Вернём деньги в течение 3 дней — без вопросов и танцев с бубном</p>
    </div>
</div>

<script>
    window.addEventListener('beforeunload', function(e) {{
        const message = "Подождите! Вы не завершили оплату.\\n\\nПосле оплаты вас ждёт:\\n- Готовый план продаж с анализом конкурентов\\n- Бесплатный 30-минутный разбор этого плана\\n- Доступ к закрытому MAX-каналу с кейсами\\n\\nВернитесь и завершите оплату — это займёт 2 минуты.";
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
    agree_oferta: bool = Form(False),
    agree_personal: bool = Form(False)
):
    # Проверка согласий
    if not agree_oferta:
        return HTMLResponse("Для оплаты необходимо принять условия публичной оферты", status_code=400)
    if not agree_personal:
        return HTMLResponse("Для оплаты необходимо дать согласие на обработку персональных данных", status_code=400)
    
    phone = format_phone(phone)
    logger.info(f"Creating YooKassa payment for user {user_id}, phone {phone}")
    save_user(user_id, phone, None)
    
    # Сохраняем согласия в БД
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    save_consent(user_id, 'oferta', client_ip, user_agent)
    save_consent(user_id, 'personal', client_ip, user_agent)
    
    base_url = str(request.base_url).rstrip('/')
    
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error("YooKassa credentials missing!")
        save_payment_request(user_id, phone)
        return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)
    
    if not phone:
        logger.error("Phone is required")
        save_payment_request(user_id, phone)
        return RedirectResponse(url=f"/payment?user_id={user_id}&error=phone_required", status_code=303)
    
    # Для самозанятого НДС не нужен, блок receipt не передаём
    payment_data = {
        "amount": {"value": "490.00", "currency": "RUB"},
        "confirmation": {"type": "redirect", "return_url": f"{base_url}/payment/confirm"},
        "capture": True,
        "description": f"План продаж для пользователя {user_id}",
        "metadata": {"user_id": user_id, "phone": phone}
    }
    
    auth = base64.b64encode(f"{YOOKASSA_SHOP_ID}:{YOOKASSA_SECRET_KEY}".encode()).decode()
    
    try:
        response = requests.post(
            "https://api.yookassa.ru/v3/payments",
            json=payment_data,
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json",
                "Idempotence-Key": str(uuid.uuid4())
            },
            timeout=30
        )
        
        logger.info(f"YooKassa API response status: {response.status_code}")
        
        if response.status_code in (200, 201):
            payment = response.json()
            payment_id = payment.get("id")
            confirmation_url = payment.get("confirmation", {}).get("confirmation_url")
            
            if not confirmation_url:
                logger.error(f"No confirmation URL in response")
                save_payment_request(user_id, phone)
                return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)
            
            save_payment_request(user_id, phone, payment_id, "490.00", "pending")
            return RedirectResponse(url=confirmation_url, status_code=303)
        else:
            logger.error(f"YooKassa error: {response.status_code} - {response.text}")
            save_payment_request(user_id, phone)
            return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)
    except Exception as e:
        logger.error(f"YooKassa exception: {e}")
        save_payment_request(user_id, phone)
        return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)

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
        
        if event == "payment.succeeded" and status == "succeeded":
            update_payment_status(payment_id, "succeeded")
            
            if user_id:
                biz = get_business_data(user_id)
                answers = get_form_data(user_id)
                
                if biz and answers and DEEPSEEK_API_KEY:
                    existing_report = get_report(user_id, "premium")
                    if not existing_report or existing_report["status"] != "ready":
                        conn = sqlite3.connect(DB_PATH)
                        cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'premium', 'generating')", (user_id,))
                        report_id = cursor.lastrowid
                        conn.commit()
                        conn.close()
                        
                        asyncio.create_task(generate_premium_report_background(
                            user_id, biz["name"], biz["description"], answers, report_id
                        ))
        
        return JSONResponse(content={"status": "ok"})
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return JSONResponse(content={"status": "error"}, status_code=500)

@app.get("/payment/confirm")
async def payment_confirm(request: Request):
    params = dict(request.query_params)
    logger.info(f"Payment confirm called with params: {params}")
    
    payment_id = params.get("paymentId") or params.get("payment_id")
    
    if payment_id:
        payment_info = get_payment_by_yookassa_id(payment_id)
        if payment_info:
            user_id = payment_info["user_id"]
            return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)
    
    user_id = get_last_succeeded_payment()
    if user_id:
        return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)
    
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Подтверждение оплаты</title>
        <meta charset="UTF-8">
        <style>
            body{font-family:sans-serif;text-align:center;padding:50px}
            .btn{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;border-radius:12px}
        </style>
    </head>
    <body>
        <h1>✅ Оплата прошла успешно!</h1>
        <p>Вернитесь на сайт, чтобы получить план</p>
        <a href="/" class="btn">На главную</a>
    </body>
    </html>
    """, status_code=200)

@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str):
    logger.info(f"Payment success page for user {user_id}")
    
    biz = get_business_data(user_id)
    answers = get_form_data(user_id)
    
    existing_report = get_report(user_id, "premium")
    
    if existing_report and existing_report["status"] == "ready":
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
            report_text_full = existing_report.get("text")
        
        if not report_text_full:
            report_text_full = "Текст плана продаж временно недоступен. Пожалуйста, обратитесь в поддержку."
        
        report_text_html = report_text_full.replace("\n", "<br>")
        
        content = f'''
<div class="hero">
    <h1>🎉 План готов!</h1>
    <p style="font-size: 18px;">«Вот он — ваш персональный маршрут к стабильным продажам. Берите и делайте. Если что-то непонятно — я здесь.»</p>
</div>

<div class="form-card" style="text-align: center;">
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; text-align: left;">
        <p style="font-size: 18px; font-weight: 600;">«Хотите, чтобы я лично разобрала ваш план и сказала: "здесь ты всё правильно написал, а здесь — провалишься"?»</p>
        <div style="text-align:center;margin-top:20px">
            <a href="/consultation?user_id={user_id}" class="btn" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">→ Записаться на бесплатный разбор</a>
        </div>
    </div>
    
    <div style="margin: 32px 0;">
        <a href="https://vk.ru/topic-164421538_39653658" target="_blank" class="btn btn-outline" style="margin: 10px;">📸 Реальные отзывы моих клиентов (ВКонтакте)</a>
    </div>
</div>
'''
        return HTMLResponse(content=render_page(content))
    
    if not biz:
        biz = {"name": "Тестовый бизнес", "description": "Тестовое описание"}
    if not answers:
        answers = {"q1": "Услугу", "q2": "до 5k", "q3": "<10", "q4": "500k/мес", "q5": "Нет"}
    
    if DEEPSEEK_API_KEY:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'premium', 'generating')", (user_id,))
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        asyncio.create_task(generate_premium_report_background(user_id, biz["name"], biz["description"], answers, report_id))
        return HTMLResponse(content=render_premium_waiting_page(user_id))
    else:
        premium_text = f"""ПРОФЕССИОНАЛЬНЫЙ МАРКЕТИНГОВЫЙ ПЛАН

Данные о бизнесе:
Название: {biz['name']}
Описание: {biz['description']}

Рекомендации для увеличения продаж:
1. Проанализируйте целевую аудиторию
2. Настройте автоворонку
3. Добавьте триггерные сообщения
"""
        save_report(user_id, "premium", premium_text)
        report_text_html = premium_text.replace("\n", "<br>")
        
        content = f'''
<div class="hero">
    <h1>🎉 Спасибо за покупку!</h1>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
</div>
'''
        return HTMLResponse(content=render_page(content))

@app.get("/check_premium_status")
async def check_premium_status(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = 'premium' ORDER BY id DESC LIMIT 1", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return {"ready": row and row[0] == 'ready'}

@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    phone = row[0] if row else ""
    
    content = f'''
<div class="hero" style="margin-bottom: 30px;">
    <h1 style="font-size: 36px;">🔥 Бесплатная консультация</h1>
    <p style="font-size: 18px;">«Да, я серьёзно. Бесплатно. Но только для первых 100 подписчиков. Осталось 97 мест.»</p>
</div>

<div class="form-card" style="text-align: center; background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);">
    <div style="background: #007aff10; border-radius: 20px; padding: 24px; margin-bottom: 24px;">
        <div style="font-size: 48px; font-weight: 700; color: #007aff;">Осталось мест: <span id="counter">97</span></div>
        <p style="color: #6e6e73;">Только для первых 100 подписчиков</p>
    </div>
    
    <div style="text-align: left; margin-bottom: 24px;">
        <p style="font-weight: 600;">Что вы получите:</p>
        <ul style="margin-top: 10px;">
            <li>3 точки утечки клиентов, о которых вы не знали</li>
            <li>1 точный первый шаг к продажам</li>
            <li>Честный фидбек по вашему бизнесу</li>
        </ul>
    </div>
    
    <hr style="margin: 24px 0;">
    
    <div style="text-align: left; margin-bottom: 24px;">
        <p style="font-weight: 600;">После отправки заявки:</p>
        <p style="margin-top: 10px;">1. ✅ Я проверю подписку в MAX (1 минута)</p>
        <p>2. 📝 Напишу вам для согласования времени (15 минут)</p>
        <p>3. 🎯 Отвечу на ваши вопросы по плану запуска продаж (30 минут)</p>
    </div>
    
    <hr style="margin: 24px 0;">
    
    <form action="/consultation/submit" method="post">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group">
            <label>📞 Ваш телефон</label>
            <input type="tel" name="phone" value="{phone}" placeholder="+7 (___) ___-__-__" required style="text-align: center; font-size: 18px; border-radius: 16px;">
        </div>
        <div class="form-group">
            <label>🕐 Удобное время для звонка (по Москве)</label>
            <input type="text" name="time" placeholder="например: завтра в 15:00" required style="border-radius: 16px;">
        </div>
        <button type="submit" class="btn" style="width: 100%; margin-top: 16px; background: #007aff; border-radius: 16px;" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">📅 Записаться</button>
    </form>
    
    <hr style="margin: 32px 0;">
    
    <p style="font-size: 14px; color: #8e8e93;">«Никакой воды. Только польза. Только конкретика. Только честно.»</p>
</div>

<script>
    let counter = 97;
    const counterElement = document.getElementById('counter');
    const form = document.querySelector('form');
    if (form) {{
        form.addEventListener('submit', function() {{
            if (counter > 0) {{
                counter--;
                if(counterElement) counterElement.textContent = counter;
            }}
        }});
    }}
</script>
'''
    return HTMLResponse(content=render_page(content))

@app.post("/consultation/submit")
async def consultation_submit(user_id: str = Form(...), time: str = Form(...), phone: str = Form(None), username: str = Form(None)):
    save_consultation(user_id, time, phone, username)
    logger.info(f"Consultation request: user_id={user_id}, time={time}, phone={phone}")
    return RedirectResponse(url=f"/subscribe?user_id={user_id}", status_code=303)

@app.get("/subscribe", response_class=HTMLResponse)
async def subscribe_page(user_id: str):
    content = f'''
<div class="hero" style="margin-bottom: 30px;">
    <h1 style="font-size: 36px;">🤝 Остался последний шаг</h1>
    <p style="font-size: 18px;">Вы почти у цели. Честное слово, это самый сложный этап — нажать на кнопку.</p>
</div>

<div class="form-card" style="text-align: center; background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);">
    <div style="margin: 20px 0;">
        <a href="https://max.ru/id781407988795_biz" target="_blank" class="btn" style="width: 80%; padding: 16px; background: #007aff; border-radius: 16px;">📢 Подписаться на канал в MAX</a>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="text-align: left;">
        <p style="font-size: 16px; font-weight: 600;">✅ А дальше:</p>
        <p style="font-size: 14px; color: #6e6e73; margin-top: 10px;">
            1. Я проверю подписку (1 минута, честно)<br>
            2. Напишу вам в MAX — договоримся о времени (15 минут)<br>
            3. Проведу консультацию — отвечу на все вопросы (30 минут)
        </p>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="background: #007aff10; border-radius: 16px; padding: 16px; margin: 20px 0;">
        <p style="font-size: 14px; color: #6e6e73;">✅ После подписки я свяжусь с вами в MAX для согласования времени консультации</p>
    </div>
    
    <div style="margin: 24px 0;">
        <a href="/" class="btn-outline" style="display: inline-block; padding: 12px 24px; border: 1px solid #007aff; border-radius: 16px; color: #007aff; text-decoration: none;">→ На главную</a>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(content))

@app.get("/download/{user_id}/{report_type}")
async def download_report(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT file_path, report_text FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type))
    row = cursor.fetchone()
    conn.close()
    
    if row and row[0]:
        file_path = row[0]
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return Response(
                content=content,
                media_type="text/plain",
                headers={"Content-Disposition": f"attachment; filename={report_type}_{user_id}.txt"}
            )
    
    if row and row[1]:
        return Response(
            content=row[1],
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={report_type}_{user_id}.txt"}
        )
    
    raise HTTPException(status_code=404, detail="Report not found")

@app.get("/admin/logs")
async def admin_logs(auth: bool = Depends(verify_admin)):
    try:
        with open(LOGS_DIR / "salesplan.log", "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]
            return Response(content="".join(lines), media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === СТРАНИЦЫ ДОКУМЕНТОВ ===
@app.get("/oferta", response_class=HTMLResponse)
async def oferta_page():
    oferta_text = """ПУБЛИЧНАЯ ОФЕРТА 
о заключении договора купли-продажи цифрового товара

Индивидуальный предприниматель Макаревич Вероника Александровна,
ИНН 781407988795, зарегистрированная в качестве налогоплательщика 
налога на профессиональный доход (самозанятая), 
размещая настоящий документ на сайте 
realplanninig-oss-salesplan-web-7eb2.twc1.net (далее — «Сайт»), 
предлагает неограниченному кругу лиц (далее — «Покупатель») 
заключить договор купли-продажи цифрового товара на условиях, изложенных ниже.

1. ТЕРМИНЫ И ОПРЕДЕЛЕНИЯ
1.1. Цифровой товар — профессиональный маркетинговый план продаж, 
сгенерированный с использованием искусственного интеллекта на основе 
данных, предоставленных Покупателем, предоставляемый в электронном виде 
в формате текстового файла (.txt) через Сайт.

1.2. Сайт — интернет-страница, расположенная по адресу: 
realplanninig-oss-salesplan-web-7eb2.twc1.net

1.3. Продавец — Индивидуальный предприниматель Макаревич Вероника Александровна, 
ИНН 781407988795, статус: ИП, применяет налог на профессиональный доход 
(самозанятая).

1.4. Покупатель — любое физическое или юридическое лицо, 
акцептовавшее настоящую оферту.

2. ПРЕДМЕТ ДОГОВОРА
2.1. Продавец обязуется передать в собственность Покупателю Цифровой товар, 
а Покупатель обязуется оплатить его в порядке и на условиях, 
предусмотренных настоящей офертой.

2.2. Цифровой товар передается Покупателю в момент получения доступа 
к файлу для скачивания после полной оплаты.

3. СТОИМОСТЬ И ПОРЯДОК ОПЛАТЫ
3.1. Стоимость Цифрового товара составляет 490 (Четыреста девяносто) рублей.

3.2. Оплата производится через платежную систему ЮKassa (ООО «ЮMoney») 
с использованием банковской карты или иных доступных способов.

3.3. Оплата считается произведенной в момент поступления денежных средств 
на счет Продавца.

3.4. Продавец не является плательщиком НДС в силу применения 
налогового режима «Налог на профессиональный доход» (самозанятость).

4. ПОРЯДОК ПЕРЕДАЧИ ЦИФРОВОГО ТОВАРА
4.1. После успешной оплаты Покупателю автоматически открывается доступ 
к странице с Цифровым товаром для скачивания.

4.2. Цифровой товар считается переданным надлежащим образом в момент 
предоставления доступа к файлу для скачивания.

4.3. Продавец не несет ответственности за невозможность скачать 
Цифровой товар по техническим причинам на стороне Покупателя 
(отсутствие интернета, блокировка провайдером и т.п.).

5. ПОРЯДОК ВОЗВРАТА ДЕНЕЖНЫХ СРЕДСТВ
5.1. В соответствии со ст. 26.1 Закона РФ «О защите прав потребителей» 
цифровой товар надлежащего качества возврату не подлежит.

5.2. Возврат денежных средств возможен в следующих исключительных случаях:
— Цифровой товар не может быть открыт / прочитан по техническим причинам;
— Цифровой товар не соответствует описанию (ошибка в предоставленном файле);
— Двойная оплата одного и того же заказа.

5.3. Для возврата Покупатель должен обратиться к Продавцу по контактам, 
указанным в разделе 10, в течение 3 (трех) дней с момента оплаты.

5.4. При подтверждении оснований для возврата Продавец обязуется 
вернуть денежные средства в течение 3 (трех) рабочих дней с момента 
получения заявления от Покупателя.

5.5. Возврат осуществляется на ту же банковскую карту или счет, 
с которого производилась оплата.

6. ОТВЕТСТВЕННОСТЬ СТОРОН
6.1. Цифровой товар предоставляется «как есть» (as is). 
Продавец не гарантирует достижение Покупателем каких-либо финансовых 
или бизнес-результатов при использовании Цифрового товара.

6.2. Продавец не несет ответственности за убытки Покупателя, 
возникшие в результате использования Цифрового товара.

7. ИНТЕЛЛЕКТУАЛЬНАЯ СОБСТВЕННОСТЬ
7.1. Цифровой товар является результатом интеллектуальной деятельности 
Продавца (с использованием нейросетей). Все исключительные права 
на Цифровой товар принадлежат Продавцу.

7.2. Покупатель получает право личного некоммерческого использования 
Цифрового товара. Запрещается:
— перепродажа Цифрового товара;
— распространение в открытом доступе;
— копирование и тиражирование в коммерческих целях;
— выдача Цифрового товара за свой собственный.

8. ПЕРСОНАЛЬНЫЕ ДАННЫЕ И КОНФИДЕНЦИАЛЬНОСТЬ
8.1. Вопросы обработки персональных данных регулируются 
Политикой обработки персональных данных, размещенной на Сайте 
по адресу: realplanninig-oss-salesplan-web-7eb2.twc1.net/privacy

8.2. Направляя данные через формы на Сайте, Покупатель дает 
согласие на их обработку в соответствии с указанной Политикой.

9. ФОРС-МАЖОР
9.1. Стороны освобождаются от ответственности за полное или частичное 
неисполнение обязательств, если это явилось следствием обстоятельств 
непреодолимой силы (стихийные бедствия, военные действия, 
решения органов власти, блокировки интернет-ресурсов и т.п.).

10. КОНТАКТЫ ПРОДАВЦА
— Индивидуальный предприниматель: Макаревич Вероника Александровна
— ИНН: 781407988795
— Email: veranikamakarevich@yandex.ru
— MAX-канал: https://max.ru/id781407988795_biz

11. ЗАКЛЮЧИТЕЛЬНЫЕ ПОЛОЖЕНИЯ
11.1. Акцептом настоящей оферты является совершение Покупателем 
действий по оплате Цифрового товара и/или проставление галочки 
в чекбоксе «Я принимаю условия публичной оферты».

11.2. Продавец вправе изменять условия оферты в одностороннем порядке. 
Изменения вступают в силу с момента их опубликования на Сайте.

Дата публикации: «21» апреля 2026 г."""
    
    oferta_html = f"""
<div class="container">
    <h1>Публичная оферта</h1>
    <div style="white-space: pre-wrap; font-family: monospace; background: #f5f5f7; padding: 20px; border-radius: 16px; font-size: 13px; line-height: 1.5;">
        {oferta_text.replace(chr(10), "<br>")}
    </div>
</div>
"""
    return HTMLResponse(content=render_page(oferta_html))

@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    privacy_text = """ПОЛИТИКА ОБРАБОТКИ ПЕРСОНАЛЬНЫХ ДАННЫХ

Индивидуального предпринимателя Макаревич Вероники Александровны

1. ОБЩИЕ ПОЛОЖЕНИЯ
1.1. Настоящая Политика определяет порядок обработки и защиты 
персональных данных лиц, использующих сайт 
realplanninig-oss-salesplan-web-7eb2.twc1.net (далее — «Сайт»).

1.2. Оператор персональных данных: 
Индивидуальный предприниматель Макаревич Вероника Александровна,
ИНН 781407988795.

1.3. Настоящая Политика составлена во исполнение требований 
Федерального закона от 27.07.2006 № 152-ФЗ «О персональных данных» 
(с изменениями на 2026 год).

1.4. Используя Сайт и заполняя формы, Пользователь выражает 
согласие с условиями настоящей Политики.

2. КАКИЕ ДАННЫЕ СОБИРАЮТСЯ
2.1. Оператор собирает следующие персональные данные:
— Номер телефона (обязательно)
— Имя (опционально)
— Название бизнеса и описание бизнеса
— Ответы на вопросы анкеты (7 вопросов о бизнесе)

2.2. Технические данные, собираемые автоматически:
— IP-адрес
— User-Agent (тип браузера и устройства)
— Дата и время посещения
— Страница, с которой совершен переход (Referrer)

3. ЦЕЛИ ОБРАБОТКИ ПЕРСОНАЛЬНЫХ ДАННЫХ
3.1. Основные цели:
— Предоставление доступа к сервису маркетинговой диагностики
— Генерация индивидуального маркетингового плана на основе анкеты
— Обработка платежей через ЮKassa (ООО «ЮMoney»)
— Направление ссылки на скачивание отчета
— Направление информации о статусе заказа
— Улучшение работы Сайта и сервиса
— Ведение статистики посещений (Яндекс.Метрика)

3.2. Второстепенные цели (с отдельным согласием Пользователя):
— Направление информационных и рекламных рассылок (если Пользователь подписался)

4. ПРАВОВЫЕ ОСНОВАНИЯ ОБРАБОТКИ
4.1. Оператор обрабатывает персональные данные на основании:
— Согласия субъекта персональных данных (отдельный чекбокс на Сайте)
— Договора (публичной оферты), стороной которого является субъект
— Исполнения обязательств, предусмотренных законодательством РФ

5. ПОРЯДОК И УСЛОВИЯ ОБРАБОТКИ
5.1. Обработка данных включает: сбор, запись, систематизацию, 
накопление, хранение, уточнение, извлечение, использование, 
передачу, блокирование, удаление, уничтожение.

5.2. Срок хранения персональных данных: 3 (три) года с момента 
последнего взаимодействия с Пользователем либо до момента отзыва 
согласия, если отзыв не противоречит законодательству.

5.3. Хранение данных осуществляется на серверах, расположенных 
на территории Российской Федерации.
— Хостинг-провайдер: ООО «ТаймВеб» (Timeweb), Россия, Санкт-Петербург
— Сайт хостинга: https://timeweb.cloud/

5.4. Оператор не передает персональные данные третьим лицам, 
за исключением:
— Платежной системы ЮKassa (ООО «ЮMoney») — для проведения платежа
— Хостинг-провайдера ООО «ТаймВеб» — для обеспечения работы Сайта
— По запросу уполномоченных государственных органов (в рамках закона)

5.5. Доступ к персональным данным имеет только Оператор 
(Макаревич Вероника Александровна). Иные лица к данным доступа не имеют.

6. ПРАВА ПОЛЬЗОВАТЕЛЯ
6.1. Пользователь имеет право:
— Получить информацию о своих персональных данных, обрабатываемых Оператором
— Требовать уточнения, блокирования или уничтожения своих данных
— Отозвать согласие на обработку персональных данных
— Обжаловать действия Оператора в уполномоченном органе (Роскомнадзор)

6.2. Для реализации прав необходимо направить запрос 
на электронную почту: veranikamakarevich@yandex.ru

6.3. Оператор обязуется рассмотреть запрос и дать ответ 
в течение 10 (десяти) рабочих дней.

7. ЗАЩИТА ПЕРСОНАЛЬНЫХ ДАННЫХ
7.1. Оператор принимает следующие меры защиты:
— Парольная защита доступа к базам данных (SQLite с паролем)
— Использование HTTPS-шифрования (через Timeweb)
— Регулярное резервное копирование
— Ограничение круга лиц, имеющих доступ к данным (только Оператор)
— Антивирусное ПО на рабочем компьютере

7.2. В случае утечки персональных данных Оператор обязуется 
в течение 24 часов уведомить Роскомнадзор и пострадавших лиц 
в порядке, установленном законодательством.

8. ИСПОЛЬЗОВАНИЕ ФАЙЛОВ COOKIE И МЕТРИК
8.1. На Сайте используется Яндекс.Метрика для сбора статистики 
посещений. Данные собираются в обезличенном виде.

8.2. Пользователь может отключить cookie в настройках браузера.

9. ПОРЯДОК ОТЗЫВА СОГЛАСИЯ
9.1. Пользователь может отозвать согласие на обработку 
персональных данных, направив письменное заявление 
на электронную почту Оператора.

9.2. В случае отзыва согласия Оператор обязуется прекратить 
обработку и уничтожить персональные данные в течение 30 дней, 
если иное не предусмотрено законом.

10. КОНТАКТЫ ОПЕРАТОРА
— Индивидуальный предприниматель: Макаревич Вероника Александровна
— ИНН: 781407988795
— Email: veranikamakarevich@yandex.ru
— MAX-канал: https://max.ru/id781407988795_biz

11. ИЗМЕНЕНИЕ ПОЛИТИКИ
11.1. Оператор вправе изменять настоящую Политику. 
Новая редакция вступает в силу с момента ее публикации на Сайте.

Дата публикации: «21» апреля 2026 г."""
    
    privacy_html = f"""
<div class="container">
    <h1>Политика обработки персональных данных</h1>
    <div style="white-space: pre-wrap; font-family: monospace; background: #f5f5f7; padding: 20px; border-radius: 16px; font-size: 13px; line-height: 1.5;">
        {privacy_text.replace(chr(10), "<br>")}
    </div>
</div>
"""
    return HTMLResponse(content=render_page(privacy_html))

# === АДМИН-ДАШБОРД ===
@app.get("/admin/dashboard")
async def admin_dashboard(auth: bool = Depends(verify_admin)):
    """Страница админ-дашборда с полной воронкой"""
    
    dashboard_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Админ-дашборд | Salesplan</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f7;padding:20px}
        .container{max-width:1400px;margin:0 auto}
        h1{font-size:28px;margin-bottom:20px}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
        .stat-card{background:#fff;border-radius:16px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
        .stat-card h3{font-size:14px;color:#6e6e73;margin-bottom:8px}
        .stat-card .value{font-size:32px;font-weight:700;color:#1d1d1f}
        .stat-card .trend{font-size:12px;color:#34c759;margin-top:8px}
        .stat-card .small{font-size:14px;color:#6e6e73}
        .chart-container{background:#fff;border-radius:16px;padding:20px;margin-bottom:30px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
        canvas{max-height:350px}
        .funnel-container{background:#fff;border-radius:16px;padding:20px;margin-bottom:30px;box-shadow:0 2px 8px rgba(0,0,0,0.05)}
        .funnel-step{display:flex;align-items:center;margin:15px 0;padding:15px;background:#f8f8fa;border-radius:12px}
        .funnel-step .step-name{width:200px;font-weight:600}
        .funnel-step .step-count{width:100px;font-size:24px;font-weight:700;color:#007aff}
        .funnel-step .step-bar{flex:1;height:30px;background:#e5e5ea;border-radius:15px;overflow:hidden}
        .funnel-step .step-fill{height:100%;background:#007aff;border-radius:15px;display:flex;align-items:center;justify-content:flex-end;padding-right:10px;color:#fff;font-size:12px}
        .tabs{display:flex;gap:10px;margin-bottom:20px;border-bottom:1px solid #e5e5e5;flex-wrap:wrap}
        .tab{padding:12px 24px;cursor:pointer;border:none;background:none;font-size:16px;transition:all 0.2s}
        .tab.active{border-bottom:2px solid #007aff;color:#007aff;font-weight:500}
        .table-container{background:#fff;border-radius:16px;padding:20px;overflow-x:auto}
        table{width:100%;border-collapse:collapse}
        th,td{padding:12px;text-align:left;border-bottom:1px solid #e5e5e5}
        th{background:#f8f8fa;font-weight:600}
        .badge{display:inline-block;padding:4px 8px;border-radius:12px;font-size:12px}
        .badge-success{background:#34c75920;color:#248a3d}
        .badge-pending{background:#ff9f0a20;color:#cc7b00}
        .report-link{color:#007aff;text-decoration:none}
        .report-link:hover{text-decoration:underline}
        .expand-btn{cursor:pointer;color:#007aff;font-size:12px}
        .row-detail{display:none;background:#f8f8fa}
        .row-detail td{padding:20px}
        .detail-section{margin-bottom:15px}
        .detail-section strong{display:block;margin-bottom:5px}
        .detail-answers{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
        .answer-tag{background:#e5e5ea;padding:4px 12px;border-radius:20px;font-size:12px}
        @media (max-width:700px){
            .funnel-step{flex-wrap:wrap}
            .funnel-step .step-name{width:100%;margin-bottom:10px}
            .stats-grid{grid-template-columns:repeat(2,1fr)}
        }
    </style>
</head>
<body>
<div class="container">
    <h1>📊 Воронка продаж — Salesplan</h1>
    
    <div class="stats-grid" id="statsGrid">
        <div class="stat-card"><h3>👥 Уникальных посетителей</h3><div class="value" id="totalVisitors">-</div></div>
        <div class="stat-card"><h3>📝 Бесплатных диагностик</h3><div class="value" id="totalDiagnostics">-</div><div class="trend" id="convVisitToDiag">-</div></div>
        <div class="stat-card"><h3>💳 Оплатили план</h3><div class="value" id="totalPayments">-</div><div class="trend" id="convDiagToPayment">-</div></div>
        <div class="stat-card"><h3>📥 Скачали отчет</h3><div class="value" id="totalDownloads">-</div></div>
        <div class="stat-card"><h3>💰 Выручка</h3><div class="value" id="totalRevenue">-</div></div>
    </div>
    
    <div class="funnel-container">
        <h3 style="margin-bottom:20px">🎯 Воронка продаж (за 7 дней)</h3>
        <div id="funnelSteps"></div>
    </div>
    
    <div class="chart-container">
        <canvas id="funnelChart"></canvas>
    </div>
    
    <div class="tabs">
        <button class="tab active" onclick="showTab('clients')">👥 Оплатившие клиенты</button>
        <button class="tab" onclick="showTab('diagnostics')">📝 Бесплатные диагностики</button>
        <button class="tab" onclick="showTab('consultations')">📞 Заявки на консультации</button>
    </div>
    
    <div id="clientsTab" class="table-container">
        <h3 style="margin-bottom:15px">💰 Клиенты, оплатившие премиум-план</h3>
        <table id="clientsTable">
            <thead>
                <tr><th>Дата</th><th>Телефон</th><th>Бизнес</th><th>Анкета</th><th>Отчет</th><th></th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    
    <div id="diagnosticsTab" class="table-container" style="display:none">
        <h3 style="margin-bottom:15px">📝 Бесплатные диагностики</h3>
        <table id="diagnosticsTable">
            <thead>
                <tr><th>Дата</th><th>Бизнес</th><th>Анкета</th><th>Статус</th><th></th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    
    <div id="consultationsTab" class="table-container" style="display:none">
        <h3 style="margin-bottom:15px">📞 Заявки на консультации</h3>
        <table id="consultationsTable">
            <thead>
                <tr><th>Дата</th><th>Телефон</th><th>Желаемое время</th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>

<script>
    let clientsData = [];
    
    async function loadStats() {
        const res = await fetch('/admin/api/stats');
        const data = await res.json();
        
        document.getElementById('totalVisitors').innerText = data.summary.visitors;
        document.getElementById('totalDiagnostics').innerText = data.summary.diagnostics;
        document.getElementById('totalPayments').innerText = data.summary.payments;
        document.getElementById('totalDownloads').innerText = data.summary.downloads;
        document.getElementById('totalRevenue').innerText = data.summary.total_revenue.toLocaleString() + ' ₽';
        document.getElementById('convVisitToDiag').innerHTML = `📈 Конверсия: ${data.summary.conv_visit_to_diag}%`;
        document.getElementById('convDiagToPayment').innerHTML = `📈 Конверсия: ${data.summary.conv_diag_to_payment}%`;
        
        // Воронка
        const funnelDiv = document.getElementById('funnelSteps');
        const steps = [
            {name: '👥 Посетители сайта', key: 'visitors', color: '#007aff'},
            {name: '📝 Бесплатная диагностика', key: 'diagnostics', color: '#5856d6'},
            {name: '💳 Оплата плана (490₽)', key: 'payments', color: '#ff9f0a'},
            {name: '📥 Скачивание отчета', key: 'downloads', color: '#34c759'}
        ];
        
        const maxCount = Math.max(data.summary.visitors, 1);
        funnelDiv.innerHTML = steps.map(step => {
            const count = data.summary[step.key];
            const percent = (count / maxCount * 100).toFixed(1);
            return `
                <div class="funnel-step">
                    <div class="step-name">${step.name}</div>
                    <div class="step-count">${count}</div>
                    <div class="step-bar">
                        <div class="step-fill" style="width: ${percent}%; background: ${step.color}">${percent}%</div>
                    </div>
                </div>
            `;
        }).join('');
        
        // График по дням
        const ctx = document.getElementById('funnelChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.funnel.map(d => d.date),
                datasets: [
                    {label: '👥 Посетители', data: data.funnel.map(d => d.visitors), borderColor: '#007aff', backgroundColor: '#007aff20', tension: 0.3, fill: true},
                    {label: '📝 Диагностики', data: data.funnel.map(d => d.diagnostics), borderColor: '#5856d6', backgroundColor: '#5856d620', tension: 0.3, fill: true},
                    {label: '💳 Оплаты', data: data.funnel.map(d => d.payments), borderColor: '#ff9f0a', backgroundColor: '#ff9f0a20', tension: 0.3, fill: true},
                    {label: '📥 Скачивания', data: data.funnel.map(d => d.downloads), borderColor: '#34c759', backgroundColor: '#34c75920', tension: 0.3, fill: true}
                ]
            },
            options: {responsive: true, maintainAspectRatio: true}
        });
    }
    
    async function loadClients() {
        const res = await fetch('/admin/api/clients');
        const data = await res.json();
        clientsData = data.clients;
        
        const tbody = document.querySelector('#clientsTable tbody');
        tbody.innerHTML = '';
        
        data.clients.forEach(client => {
            const row = tbody.insertRow();
            row.innerHTML = `
                <td>${new Date(client.payment_date).toLocaleDateString()}</td>
                <td>${client.phone || '-'}</td>
                <td><strong>${client.business_name || '-'}</strong><br><small>${(client.business_description || '').substring(0, 50)}...</small></td>
                <td><span class="expand-btn" onclick="showAnswers(${JSON.stringify(client).replace(/"/g, '&quot;')})">📋 Показать анкету</span></td>
                <td>${client.report_path ? '<a href="/download/' + client.user_id + '/premium" class="report-link">📥 Скачать отчет</a>' : '<span class="badge badge-pending">генерация...</span>'}</td>
                <td><span class="expand-btn" onclick="toggleDetail(this)">▶ Подробнее</span></td>
            `;
            
            const detailRow = tbody.insertRow();
            detailRow.className = 'row-detail';
            detailRow.style.display = 'none';
            detailRow.innerHTML = `<td colspan="6"><div class="detail-section"><strong>📝 Полная анкета:</strong><div class="detail-answers">
                <span class="answer-tag">Продаёт: ${client.q1 || '-'}</span>
                <span class="answer-tag">Чек: ${client.q2 || '-'}</span>
                <span class="answer-tag">Клиентов: ${client.q3 || '-'}</span>
                <span class="answer-tag">Цель: ${client.q4 || '-'}</span>
                <span class="answer-tag">Воронка: ${client.q5 || '-'}</span>
            </div></div><div class="detail-section"><strong>📄 Описание бизнеса:</strong><br>${client.business_description || '-'}</div></td>`;
        });
    }
    
    async function loadDiagnostics() {
        const res = await fetch('/admin/api/diagnostics');
        const data = await res.json();
        
        const tbody = document.querySelector('#diagnosticsTable tbody');
        tbody.innerHTML = '';
        
        data.diagnostics.forEach(d => {
            const row = tbody.insertRow();
            row.innerHTML = `
                <td>${new Date(d.date).toLocaleString()}</td>
                <td><strong>${d.business_name || '-'}</strong><br><small>${(d.business_description || '').substring(0, 50)}...</small></td>
                <td><span class="expand-btn" onclick="showAnswersDialog('${d.q1}', '${d.q2}', '${d.q3}', '${d.q4}', '${d.q5}')">📋 Показать</span></td>
                <td><span class="badge ${d.report_status === 'ready' ? 'badge-success' : 'badge-pending'}">${d.report_status === 'ready' ? '✅ Готов' : '⏳ Генерация'}</span></td>
                <td>${d.report_status === 'ready' ? '<a href="/download/' + d.user_id + '/free" class="report-link">📥 Скачать</a>' : '-'}</td>
            `;
        });
    }
    
    async function loadConsultations() {
        const res = await fetch('/admin/api/consultations');
        const data = await res.json();
        
        const tbody = document.querySelector('#consultationsTable tbody');
        tbody.innerHTML = '';
        
        data.consultations.forEach(c => {
            const row = tbody.insertRow();
            row.innerHTML = `
                <td>${new Date(c.created_at).toLocaleString()}</td>
                <td>${c.phone || '-'}</td>
                <td>${c.time || '-'}</td>
            `;
        });
    }
    
    function toggleDetail(btn) {
        const row = btn.closest('tr');
        const detailRow = row.nextElementSibling;
        if (detailRow && detailRow.classList.contains('row-detail')) {
            const isHidden = detailRow.style.display === 'none';
            detailRow.style.display = isHidden ? 'table-row' : 'none';
            btn.innerText = isHidden ? '▼ Скрыть' : '▶ Подробнее';
        }
    }
    
    function showAnswers(client) {
        alert(`📋 АНКЕТА КЛИЕНТА\n\nПродаёт: ${client.q1 || '-'}\nСредний чек: ${client.q2 || '-'}\nКлиентов/мес: ${client.q3 || '-'}\nЦель: ${client.q4 || '-'}\nАвтоворонка: ${client.q5 || '-'}`);
    }
    
    function showAnswersDialog(q1, q2, q3, q4, q5) {
        alert(`📋 АНКЕТА\n\nПродаёт: ${q1 || '-'}\nСредний чек: ${q2 || '-'}\nКлиентов/мес: ${q3 || '-'}\nЦель: ${q4 || '-'}\nАвтоворонка: ${q5 || '-'}`);
    }
    
    function showTab(tab) {
        document.getElementById('clientsTab').style.display = tab === 'clients' ? 'block' : 'none';
        document.getElementById('diagnosticsTab').style.display = tab === 'diagnostics' ? 'block' : 'none';
        document.getElementById('consultationsTab').style.display = tab === 'consultations' ? 'block' : 'none';
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
    }
    
    loadStats();
    loadClients();
    loadDiagnostics();
    loadConsultations();
    
    setInterval(() => { loadStats(); loadClients(); loadDiagnostics(); }, 30000);
</script>
</body>
</html>
    """
    return HTMLResponse(content=dashboard_html)

@app.get("/admin/api/stats")
async def admin_stats(auth: bool = Depends(verify_admin)):
    """API для полной статистики воронки"""
    days = 7
    funnel = get_full_funnel(days)
    
    total_visitors = sum(f['visitors'] for f in funnel)
    total_diagnostics = sum(f['diagnostics'] for f in funnel)
    total_payments = sum(f['payments'] for f in funnel)
    total_downloads = sum(f['downloads'] for f in funnel)
    
    return {
        "funnel": funnel,
        "summary": {
            "visitors": total_visitors,
            "diagnostics": total_diagnostics,
            "payments": total_payments,
            "downloads": total_downloads,
            "conv_visit_to_diag": round(total_diagnostics / max(total_visitors, 1) * 100, 1),
            "conv_diag_to_payment": round(total_payments / max(total_diagnostics, 1) * 100, 1),
            "total_revenue": total_payments * 490
        }
    }

@app.get("/admin/api/clients")
async def admin_clients(auth: bool = Depends(verify_admin)):
    """API для списка оплативших клиентов"""
    clients = get_all_premium_clients()
    return {"clients": clients}

@app.get("/admin/api/diagnostics")
async def admin_diagnostics(auth: bool = Depends(verify_admin)):
    """API для списка бесплатных диагностик"""
    diagnostics = get_all_free_diagnostics()
    return {"diagnostics": diagnostics}

@app.get("/admin/api/consultations")
async def admin_consultations(auth: bool = Depends(verify_admin)):
    """API для заявок на консультации"""
    consultations = get_new_consultations()
    return {"consultations": consultations}

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
