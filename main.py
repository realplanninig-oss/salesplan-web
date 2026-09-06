# File: main.py — веб-приложение Salesplan (с SEO-оптимизацией)

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
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse, PlainTextResponse
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
BASE_URL = os.getenv("BASE_URL", "https://realplanninig-oss-salesplan-web-7eb2.twc1.net")

missing_vars = []
if not DEEPSEEK_API_KEY:
    missing_vars.append("DEEPSEEK_API_KEY")
if not YOOKASSA_SHOP_ID:
    missing_vars.append("YOOKASSA_SHOP_ID")
if not YOOKASSA_SECRET_KEY:
    missing_vars.append("YOOKASSA_SECRET_KEY")

if missing_vars:
    print(f"WARNING: Missing environment variables: {missing_vars}")

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
    if path in ["/", "/survey", "/payment", "/payment/success", "/thank-you", "/choose-plan", "/consultation", "/implementation", "/oferta", "/privacy"]:
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
            r.report_text,
            u.phone
        FROM forms f
        LEFT JOIN business_data b ON f.user_id = b.user_id
        LEFT JOIN users u ON f.user_id = u.user_id
        LEFT JOIN (
            SELECT user_id, report_type, status, report_text, id
            FROM reports 
            WHERE report_type = 'free'
            AND id IN (SELECT MAX(id) FROM reports WHERE report_type = 'free' GROUP BY user_id)
        ) r ON f.user_id = r.user_id
        ORDER BY f.completed_at DESC LIMIT 100
    """)
    columns = ['user_id','date','business_name','business_description','q1','q2','q3','q4','q5','report_status','report_text','phone']
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

# === DEEPSEEK (бесплатная диагностика) ===
def call_deepseek_diagnostic(name: str, description: str, answers: dict) -> str:
    if not DEEPSEEK_API_KEY:
        logger.error("DEEPSEEK_API_KEY not configured")
        return None
    q1_map = {"до 5k": "до 5000 ₽", "5k-20k": "5000-20000 ₽", "20k-50k": "20000-50000 ₽", ">50k": "более 50000 ₽"}
    q2_map = {"<10": "менее 10", "10-50": "10-50", "50-200": "50-200", ">200": "более 200"}
    q3_map = {"300k/мес": "300 000 ₽/мес", "500k/мес": "500 000 ₽/мес", "1M/мес": "1 000 000 ₽/мес", "Масштаб": "масштабирование"}
    q4 = answers.get('q4') or 'не указано'
    q5 = answers.get('q5') or 'не указано'
    survey_info = f"""
ДАННЫЕ О БИЗНЕСЕ:
• Название: {name}
• Описание: {description}
• Средний чек: {q1_map.get(answers.get('q1'), 'не указано')}
• Клиентов/мес: {q2_map.get(answers.get('q2'), 'не указано')}
• Цель на 2026: {q3_map.get(answers.get('q3'), 'не указано')}
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
3. ПЕРВЫЙ ШАГ (3 конкретных действия прямо сейчас, обязательно включая тестирование рекламных каналов, например Яндекс Директ)"""
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

# === DEEPSEEK (расширенный план) ===
def generate_premium_report_sync(user_id: str, name: str, description: str, answers: dict, report_id: int):
    logger.info(f"Starting premium report generation for user {user_id}")
    if not DEEPSEEK_API_KEY:
        update_report_status(report_id, 'failed')
        return False
    prompt = f"""Сделай расширенный маркетинговый план для бизнеса.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
Средний чек: {answers.get('q1', 'не указано')}
Клиентов/мес: {answers.get('q2', 'не указано')}
Цель: {answers.get('q3', 'не указано')}

Требования:
1. Все разделы должны содержать конкретные числа, примеры и готовые формулировки.
2. В конце плана – чек-лист из 50 пунктов и 5 главных действий на первую неделю.
3. Пиши деловым, прямым стилем. Без воды. Обращайся на «ты».
4. НЕ используй символы форматирования (*, #, _, `, ~). Для списков используй дефис.
5. Структура строго по разделам ниже.

СТРУКТУРА ПЛАНА:

1. АНАЛИЗ НИШИ
   - Объём рынка (примерно, в деньгах)
   - Тренды (что сейчас работает в этой нише)
   - 3 главных конкурента: их УТП, сильные и слабые стороны

2. ЦЕЛЕВАЯ АУДИТОРИЯ (3 портрета)
   - Кто они (должность, возраст, доход)
   - Их главная боль (одним предложением)
   - Их главное возражение при покупке

3. ОФФЕР (3 варианта)
   - Вариант А – для новичков (низкая цена, быстрый вход)
   - Вариант Б – для средних (основной продукт)
   - Вариант В – для премиум-клиентов (дорого, с гарантией)
   - Для каждого варианта – готовый заголовок и подзаголовок (как в рекламе)

4. ВОРОНКА ПРОДАЖ (по шагам)
   - Шаг 1: Привлечение (какой канал)
   - Шаг 2: Лид-магнит (что даём бесплатно)
   - Шаг 3: Прогрев (серия писем/сообщений)
   - Шаг 4: Продажа (как закрываем)
   - Шаг 5: Доведение до результата
   - Для каждого шага – готовый текст для касания (пример сообщения)

5. РЕКЛАМНЫЕ КАНАЛЫ (5 каналов) – обязательно включи Яндекс Директ как один из основных каналов
   - Для каждого канала: примерный бюджет в месяц, ожидаемый CPC (или CPM), прогноз по лидам.
   - Укажи, какие каналы дадут быстрый результат, а какие – долгосрочный.

6. КОНТЕНТ-ПЛАН НА МЕСЯЦ (по дням)
   - Разбей на недели.
   - Для каждой недели – темы для постов в соцсетях, сторис, рассылок.
   - Укажи формат (текст, видео, опрос и т.п.)

7. СКРИПТЫ ПРОДАЖ (для 5 возражений)
   - Возражение 1: «Дорого» – готовый ответ
   - Возражение 2: «Подумаю» – готовый ответ
   - Возражение 3: «Сравню с другими» – готовый ответ
   - Возражение 4: «Нет времени» – готовый ответ
   - Возражение 5: «У меня уже есть специалист» – готовый ответ

8. ЧЕК-ЛИСТ ЗАПУСКА (50 пунктов)
   - От регистрации домена до настройки автоворонки.
   - Разбей по этапам: подготовка, настройка, запуск, анализ.

9. 5 ГЛАВНЫХ ДЕЙСТВИЙ НА ПЕРВУЮ НЕДЕЛЮ
   - Конкретные шаги, которые можно сделать завтра.

В конце – краткое резюме: какие 3 ошибки вы совершаете сейчас и как их исправить."""
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {"model": "deepseek-chat", "messages": [{"role": "system", "content": "Ты — профессиональный бизнес-консультант в мудром, прямом стиле. Без воды."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 8000}
    try:
        response = requests.post(url, headers=headers, json=data, timeout=300)
        if response.status_code == 200:
            report_text = response.json()["choices"][0]["message"]["content"]
            
            # Добавляем призыв в конец отчёта (ЗАПУСК)
            launch_text = f"""


---
🚀 В этом плане вы увидели канал в соцсетях. Хотите узнать, как запустить его за 3 дня без бюджета?

Напишите слово «ЗАПУСК» в личный чат MAX – и я пришлю видео.
Ссылка на чат: https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8
"""
            report_text += launch_text
            
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

# === SEO: robots.txt ===
@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return """User-agent: *
Allow: /
Disallow: /admin/
Disallow: /payment/confirm
Disallow: /thank-you
Disallow: /payment/success
Disallow: /check_status
Disallow: /check-premium-status
Sitemap: {}/sitemap.xml
""".format(BASE_URL)

# === SEO: sitemap.xml ===
@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap():
    now = datetime.now().strftime("%Y-%m-%d")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{BASE_URL}/</loc>
    <lastmod>{now}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>{BASE_URL}/survey</loc>
    <lastmod>{now}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>{BASE_URL}/payment</loc>
    <lastmod>{now}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>{BASE_URL}/oferta</loc>
    <lastmod>{now}</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.4</priority>
  </url>
  <url>
    <loc>{BASE_URL}/privacy</loc>
    <lastmod>{now}</lastmod>
    <changefreq>yearly</changefreq>
    <priority>0.4</priority>
  </url>
  <url>
    <loc>{BASE_URL}/consultation</loc>
    <lastmod>{now}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>{BASE_URL}/implementation</loc>
    <lastmod>{now}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
</urlset>
"""

# === ГЛОБАЛЬНЫЕ HTML ШАБЛОНЫ И CSS (дизайн-система) ===
# Основной цвет – неон-лайм #B5FF47, дополнительный – #5AD1FF

def render_page(content: str, title: str = "Привлечение клиентов для экспертов | Вероника Макаревич", description: str = "Получите план привлечения клиентов под ваш бизнес. AI-аналитика + личное продюсирование. Реальные кейсы: +120 000, +187 000, +2 000 000 ₽.", noindex: bool = False):
    """Генерирует полную HTML-страницу с мета-тегами и Open Graph."""
    robots_meta = '<meta name="robots" content="noindex, nofollow">' if noindex else ''
    og_image = f"{BASE_URL}/static/og-image.png"  # если есть, иначе можно использовать картинку-заглушку
    html_head = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>{title}</title>
    <meta name="description" content="{description}">
    {robots_meta}
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{description}">
    <meta property="og:type" content="website">
    <meta property="og:url" content="{BASE_URL}/">
    <meta property="og:image" content="{og_image}">
    <meta name="twitter:card" content="summary_large_image">
    <link href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@500;600;700;800&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <script type="text/javascript">
        (function(m,e,t,r,i,k,a){{m[i]=m[i]||function(){{(m[i].a=m[i].a||[]).push(arguments)}};
        m[i].l=1*new Date();
        for (var j = 0; j < document.scripts.length; j++) {{if (document.scripts[j].src === r) {{ return; }}}}
        k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)}})
        (window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
        ym(108348240, "init", {{ clickmap:true, trackLinks:true, accurateTrackBounce:true, webvisor:true, ecommerce:"dataLayer" }});
    </script>
    <noscript><div><img src="https://mc.yandex.ru/watch/108348240" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
    <style>
        /* === ДИЗАЙН-СИСТЕМА === */
        :root {{
            --color-bg: #0F1115;
            --color-bg-secondary: #1A1D23;
            --color-text-primary: #FFFFFF;
            --color-text-secondary: #AAB2C0;
            --color-accent: #B5FF47;          /* неон-лайм */
            --color-accent-secondary: #5AD1FF;
            --color-glass: rgba(255,255,255,0.04);
            --color-glass-border: rgba(255,255,255,0.08);
            --font-heading: 'Inter Tight', sans-serif;
            --font-body: 'Manrope', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            --shadow-glass: 0 8px 32px rgba(0,0,0,0.4);
            --shadow-glow: 0 0 30px rgba(181,255,71,0.3);
            --radius-card: 16px;
            --radius-button: 60px;
        }}
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{
            font-family: var(--font-body);
            background: var(--color-bg);
            color: var(--color-text-primary);
            line-height: 1.6;
            font-weight: 400;
            padding-top: 80px;
        }}
        .container{{max-width:1200px;margin:0 auto;padding:40px 20px}}
        .hero{{text-align:center;margin-bottom:60px}}
        .hero h1{{
            font-size:clamp(2.2rem, 5vw, 4.5rem);
            font-weight:700;
            margin-bottom:20px;
            letter-spacing:-0.02em;
            color:var(--color-accent);
            text-shadow:0 0 30px rgba(181,255,71,0.2);
            font-family: var(--font-heading);
        }}
        .hero p{{font-size:clamp(1rem, 1.5vw, 1.25rem);color:var(--color-text-secondary);max-width:700px;margin-left:auto;margin-right:auto;font-family:var(--font-body);}}
        h1, h2, h3, .heading {{
            color: var(--color-accent);
            font-family: var(--font-heading);
            font-weight: 700;
        }}
        h2 {{ font-size: clamp(1.8rem, 3vw, 3rem); font-weight: 700; margin-bottom: 16px; text-shadow: 0 0 20px rgba(181,255,71,0.15); }}
        h3 {{ font-size: clamp(1.3rem, 1.8vw, 1.8rem); font-weight: 600; margin-bottom: 12px; }}
        .btn-main{{
            display:inline-block;
            background:var(--color-accent);
            color:#0F1115;
            text-decoration:none;
            padding:16px 48px;
            font-size:clamp(1rem, 1.2vw, 1.125rem);
            font-weight:600;
            border-radius:var(--radius-button);
            box-shadow:var(--shadow-glow);
            transition:all 0.2s ease;
            border:none;
            cursor:pointer;
            font-family: var(--font-body);
        }}
        .btn-main:hover{{
            transform:translateY(-2px);
            box-shadow:0 0 40px rgba(181,255,71,0.6);
        }}
        .btn-secondary{{
            background:transparent;
            border:1px solid var(--color-accent);
            color:var(--color-accent);
        }}
        .btn-secondary:hover{{
            background:rgba(181,255,71,0.1);
            box-shadow:0 0 20px rgba(181,255,71,0.1);
        }}
        .glass-card{{
            background:var(--color-glass);
            backdrop-filter:blur(12px);
            -webkit-backdrop-filter:blur(12px);
            border:1px solid var(--color-glass-border);
            border-radius:var(--radius-card);
            padding:32px;
            transition:all 0.3s ease;
            font-family: var(--font-body);
            box-shadow:var(--shadow-glass);
        }}
        .glass-card:hover{{
            border-color:rgba(181,255,71,0.3);
            box-shadow:0 0 30px rgba(181,255,71,0.05);
        }}
        .glass-card.gold{{border-color:rgba(90,209,255,0.3)}}
        .glass-card.gold:hover{{border-color:var(--color-accent-secondary);box-shadow:0 0 30px rgba(90,209,255,0.1)}}
        .footer{{text-align:center;margin-top:60px;padding-top:24px;border-top:1px solid var(--color-glass-border);font-size:12px;color:var(--color-text-secondary);font-family:var(--font-body);}}
        .social-links{{margin-top:8px;display:flex;flex-wrap:wrap;justify-content:center;gap:16px}}
        .social-links a{{color:var(--color-accent);text-decoration:none;font-size:12px}}
        hr{{margin:30px 0;border:none;border-top:1px solid var(--color-glass-border)}}
        .form-card{{
            background:var(--color-glass);
            backdrop-filter:blur(12px);
            -webkit-backdrop-filter:blur(12px);
            border:1px solid var(--color-glass-border);
            border-radius:var(--radius-card);
            padding:32px;
            max-width:600px;
            margin:0 auto;
            font-family: var(--font-body);
            box-shadow:var(--shadow-glass);
        }}
        .form-group{{margin-bottom:24px}}
        label{{font-size:0.9rem;font-weight:500;display:block;margin-bottom:8px;color:var(--color-text-secondary)}}
        input,textarea{{
            width:100%;padding:12px;font-size:1rem;
            border:1px solid rgba(255,255,255,0.1);border-radius:10px;
            font-family:var(--font-body);
            background:rgba(255,255,255,0.06);
            color:var(--color-text-primary);
            transition:border-color 0.3s,box-shadow 0.3s;
        }}
        input:focus,textarea:focus{{outline:none;border-color:var(--color-accent);box-shadow:0 0 10px rgba(181,255,71,0.2)}}
        .radio-group{{display:flex;flex-direction:column;gap:12px;margin-top:8px}}
        .radio-group label{{
            display:flex;align-items:center;gap:8px;
            font-weight:normal;cursor:pointer;padding:8px 12px;
            background:rgba(255,255,255,0.04);
            border-radius:12px;
            transition:all 0.2s;border:1px solid var(--color-glass-border);
            color:var(--color-text-primary);
            font-family:var(--font-body);
        }}
        .radio-group label:hover{{background:rgba(181,255,71,0.08);border-color:rgba(181,255,71,0.3)}}
        .radio-group input[type="radio"]{{width:20px;height:20px;margin:0;cursor:pointer;accent-color:var(--color-accent)}}
        .mono-number {{
            font-family: var(--font-mono);
            font-weight: 600;
        }}
        .step-card{{
            text-align:center;padding:24px;
            background:var(--color-glass);
            backdrop-filter:blur(8px);
            -webkit-backdrop-filter:blur(8px);
            border:1px solid var(--color-glass-border);
            border-radius:var(--radius-card);
            transition:all 0.3s ease;
            font-family:var(--font-body);
        }}
        .step-card:hover{{transform:translateY(-4px);border-color:rgba(181,255,71,0.3);box-shadow:0 8px 25px rgba(181,255,71,0.05)}}
        .step-icon{{font-size:40px;display:block;margin-bottom:12px}}
        .step-title{{font-size:1.125rem;font-weight:600;color:var(--color-accent);margin-bottom:8px;font-family:var(--font-heading);}}
        .step-desc{{font-size:0.875rem;color:var(--color-text-secondary)}}
        .timeline{{display:flex;justify-content:space-between;position:relative;padding:20px 0;margin-top:20px}}
        .timeline::before{{content:'';position:absolute;top:50%;left:0;right:0;height:2px;background:var(--color-glass-border);transform:translateY(-50%)}}
        .timeline-point{{display:flex;flex-direction:column;align-items:center;gap:8px;z-index:1}}
        .timeline-point .dot{{width:12px;height:12px;border-radius:50%;background:var(--color-accent);border:2px solid var(--color-bg);box-shadow:0 0 10px rgba(181,255,71,0.3)}}
        .timeline-point .dot.done{{background:var(--color-accent-secondary);box-shadow:0 0 10px rgba(90,209,255,0.3)}}
        .timeline-point .label{{font-size:0.75rem;color:var(--color-text-secondary);text-align:center;font-family:var(--font-body);}}
        .faq-item{{border-bottom:1px solid var(--color-glass-border);padding:16px 0}}
        .faq-question{{display:flex;justify-content:space-between;align-items:center;cursor:pointer;font-weight:500;color:var(--color-text-primary);transition:color 0.3s;font-family:var(--font-body);}}
        .faq-question:hover{{color:var(--color-accent)}}
        .faq-question .arrow{{transition:transform 0.3s;font-size:20px;color:var(--color-text-secondary)}}
        .faq-answer{{max-height:0;overflow:hidden;transition:max-height 0.4s ease, padding 0.3s;color:var(--color-text-secondary);padding:0;font-family:var(--font-body);}}
        .faq-answer.open{{max-height:300px;padding:12px 0 0 0}}

        /* ФИКСИРОВАННАЯ ШАПКА */
        .navbar {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
            background: rgba(15,17,21,0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--color-glass-border);
            padding: 0 20px;
            height: 70px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .navbar .logo {{
            font-family: var(--font-heading);
            font-weight: 800;
            font-size: 1.8rem;
            color: var(--color-accent);
            text-decoration: none;
            text-shadow: 0 0 15px rgba(181,255,71,0.2);
            letter-spacing:-0.02em;
        }}
        .navbar .nav-links {{
            display: flex;
            gap: 24px;
            align-items: center;
        }}
        .navbar .nav-links a {{
            color: var(--color-text-secondary);
            text-decoration: none;
            font-size: 1rem;
            font-weight: 500;
            transition: color 0.2s;
            font-family: var(--font-body);
        }}
        .navbar .nav-links a:hover {{
            color: var(--color-accent);
        }}
        .navbar .nav-links .btn-nav {{
            background: var(--color-accent);
            color: #0F1115;
            padding: 8px 20px;
            border-radius: 30px;
            font-weight: 600;
            font-size: 0.9rem;
            transition: all 0.2s;
        }}
        .navbar .nav-links .btn-nav:hover {{
            transform:translateY(-2px);
            box-shadow:0 0 20px rgba(181,255,71,0.4);
        }}
        @media (max-width: 700px) {{
            .navbar .nav-links {{ gap: 12px; }}
            .navbar .nav-links a {{ font-size: 0.8rem; }}
            .navbar .nav-links .btn-nav {{ padding: 6px 14px; font-size: 0.8rem; }}
        }}
        /* Дополнительные стили для главной */
        .apple-hero, .apple-text-block, .apple-list li, .apple-footer-link {{
            font-family: var(--font-body);
        }}
        .apple-hero h1, .apple-hero .subtitle, .steps-grid .step-title {{
            font-family: var(--font-heading);
        }}
        .timeline-section h3, .timeline-label {{
            font-family: var(--font-heading);
        }}
        .cases-block .case-item .label, .case-detail {{
            font-family: var(--font-body);
        }}
        .apple-list li {{
            background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>') left center no-repeat;
            background-size: 20px;
        }}
        .apple-footer-link a {{ color: var(--color-accent); }}
        /* Стили для графика внедрения */
        .implementation-graph {{
            background: rgba(255,255,255,0.04);
            border-radius: 16px;
            padding: 24px 20px;
            border: 1px solid rgba(255,255,255,0.08);
            margin-top: 20px;
        }}
        .graph-step {{
            display: flex;
            align-items: center;
            margin: 12px 0;
            gap: 12px;
        }}
        .graph-step .step-label {{
            width: 120px;
            font-size: 0.9rem;
            color: #FFFFFF;
            font-family: var(--font-body);
            text-align: right;
        }}
        .graph-step .step-bar {{
            flex: 1;
            height: 8px;
            background: rgba(255,255,255,0.08);
            border-radius: 4px;
            overflow: hidden;
        }}
        .graph-step .step-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 1s;
        }}
        .graph-step .step-fill.done {{ background: var(--color-accent); width: 100%; }}
        .graph-step .step-fill.partial {{ background: var(--color-accent-secondary); width: 50%; }}
        .graph-step .step-fill.empty {{ background: rgba(255,255,255,0.2); width: 0%; }}
        .graph-step .step-status {{
            width: 80px;
            font-size: 0.8rem;
            color: var(--color-text-secondary);
            font-family: var(--font-body);
        }}
        .graph-step .step-status.done {{ color: var(--color-accent); }}
        .graph-step .step-status.partial {{ color: var(--color-accent-secondary); }}
        @media (max-width: 700px) {{
            .graph-step .step-label {{ width: 80px; font-size: 0.8rem; }}
            .graph-step .step-status {{ width: 60px; font-size: 0.7rem; }}
        }}
        /* Дополнительные стили для SEO-текста */
        .seo-text {{
            font-size: 0.95rem;
            color: var(--color-text-secondary);
            line-height: 1.7;
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid var(--color-glass-border);
        }}
        .seo-text h3 {{
            font-size: 1.3rem;
            margin-bottom: 12px;
            color: var(--color-accent);
        }}
        .seo-text p {{
            margin-bottom: 14px;
        }}
        .seo-text ul {{
            list-style: none;
            padding: 0;
            font-family: var(--font-body);
            color: var(--color-text-secondary);
        }}
        .seo-text ul li {{
            padding: 4px 0 4px 24px;
            background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') left center no-repeat;
            background-size: 16px;
            margin-bottom: 2px;
        }}
    </style>
</head>
<body>

<!-- ШАПКА -->
<nav class="navbar">
    <a href="/" class="logo">Вероника Макаревич</a>
    <div class="nav-links">
        <a href="/#how-it-works">Как работает</a>
        <a href="/#cases">Кейсы</a>
        <a href="/#pricing">Тарифы</a>
        <a href="/survey" class="btn-nav">Получить план</a>
    </div>
</nav>

<div class="container">
"""
    html_foot = """
    <div class="footer">
        <p>Вероника Макаревич | Продюсер экспертов</p>
        <div class="social-links">
            <a href="https://max.ru/id781407988795_biz" target="_blank">Мой канал в MAX</a>
            <a href="https://vk.ru/makarevichveronika">ВКонтакте</a>
        </div>
        <div style="margin-top: 8px;">
            <a href="/oferta" style="color:var(--color-accent);text-decoration:none;">Публичная оферта</a> | <a href="/privacy" style="color:var(--color-accent);text-decoration:none;">Политика персональных данных</a>
        </div>
        <p>© 2026 Все права защищены</p>
    </div>
</div>
</body>
</html>"""
    return html_head + content + html_foot

# === ВСПОМОГАТЕЛЬНЫЕ СТРАНИЦЫ ОЖИДАНИЯ ===
def render_waiting_page(user_id: str, report_type: str, redirect_url: str):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Генерируем план</title>
<meta name="robots" content="noindex, nofollow">
<link href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@500;600;700;800&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>body{{font-family:'Manrope',sans-serif;text-align:center;padding:60px 20px;background:#0F1115;color:#FFFFFF}}.spinner{{width:50px;height:50px;border:4px solid rgba(255,255,255,0.1);border-top-color:#B5FF47;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
<script>
let attempts=0; let isRedirected=false;
function checkStatus(){{
    if(isRedirected) return;
    fetch('/check_status?user_id={user_id}&report_type={report_type}')
        .then(res=>res.json())
        .then(data=>{{
            if(data.ready){{
                isRedirected=true;
                window.location.href='{redirect_url}';
            }} else {{
                attempts++;
                if(attempts<60) setTimeout(checkStatus,3000);
            }}
        }})
        .catch(()=>setTimeout(checkStatus,3000));
}}
setTimeout(checkStatus,1000);
</script>
</head>
<body><div class="spinner"></div><h1 style="color:#B5FF47;font-family:'Inter Tight',sans-serif;font-weight:700;">Генерируем ваш план...</h1><p style="color:#AAB2C0;">Это займёт 1-2 минуты. Страница обновится сама.</p></body>
</html>"""

# ========================================
# ГЛАВНАЯ СТРАНИЦА (ОБНОВЛЁННАЯ) – ИСПРАВЛЕННАЯ ВЕРСИЯ
# ========================================
@app.get("/")
async def index():
    content = '''
<style>
    /* Дополнительные стили для главной */
    .apple-hero {
        text-align: center;
        max-width: 820px;
        margin: 0 auto;
        padding: 40px 20px;
    }
    .apple-hero h1 {
        font-size: clamp(1.6rem, 3.8vw, 2.8rem);
        font-weight: 700;
        letter-spacing: -0.02em;
        line-height: 1.2;
        margin-bottom: 12px;
        color: #B5FF47;
        text-shadow: 0 0 30px rgba(181,255,71,0.2);
        font-family: 'Inter Tight', sans-serif;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    @media (max-width: 480px) {
        .apple-hero h1 {
            font-size: 1.4rem;
            white-space: normal;
        }
    }
    .apple-hero .subtitle {
        font-size: clamp(1rem, 1.5vw, 1.25rem);
        font-weight: 400;
        color: #AAB2C0;
        max-width: 700px;
        margin: 0 auto 24px;
        line-height: 1.5;
        font-family: 'Manrope', sans-serif;
    }
    .apple-text-block {
        background: rgba(255,255,255,0.04);
        backdrop-filter: blur(12px);
        border-radius: 16px;
        padding: 40px 48px;
        margin: 32px auto;
        text-align: left;
        font-size: 1.125rem;
        line-height: 1.6;
        color: #FFFFFF;
        border: 1px solid rgba(255,255,255,0.08);
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        font-family: 'Manrope', sans-serif;
    }
    .apple-text-block p { margin-bottom: 16px; }
    .apple-text-block strong { font-weight: 600; color: #B5FF47; font-family: 'Inter Tight', sans-serif; }
    .apple-list {
        list-style: none;
        padding: 0;
        margin: 20px 0 24px;
    }
    .apple-list li {
        padding: 8px 0 8px 36px;
        background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>') left center no-repeat;
        background-size: 20px;
        margin-bottom: 4px;
        font-size: 1.05rem;
        color: #FFFFFF;
        font-family: 'Manrope', sans-serif;
    }
    .cases-block {
        display: flex;
        justify-content: center;
        gap: 20px;
        flex-wrap: wrap;
        margin: 20px 0 30px;
        background: rgba(255,255,255,0.04);
        backdrop-filter: blur(12px);
        border-radius: 16px;
        padding: 20px 16px;
        border: 1px solid rgba(255,255,255,0.08);
    }
    .cases-block .case-item {
        text-align: center;
        flex: 1;
        min-width: 120px;
    }
    .cases-block .case-item .number {
        font-size: clamp(1.2rem, 1.8vw, 1.8rem);
        font-weight: 600;
        color: #B5FF47;
        text-shadow: 0 0 15px rgba(181,255,71,0.15);
        font-family: 'JetBrains Mono', monospace;
        white-space: nowrap;
    }
    .cases-block .case-item .label {
        font-size: 0.9rem;
        color: #FFFFFF;
        line-height: 1.3;
        margin: 4px auto 0;
        font-family: 'Manrope', sans-serif;
    }
    .case-detail {
        font-size: 0.8rem;
        color: #AAB2C0;
        margin-top: 2px;
    }
    .steps-grid {
        display: grid;
        grid-template-columns: repeat(3,1fr);
        gap: 24px;
        margin: 40px 0;
    }
    .step-card {
        text-align: center;
        padding: 24px;
        background: rgba(255,255,255,0.04);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        transition: all 0.3s ease;
        font-family: 'Manrope', sans-serif;
    }
    .step-card:hover {
        transform: translateY(-4px);
        border-color: rgba(181,255,71,0.3);
        box-shadow: 0 8px 25px rgba(181,255,71,0.05);
    }
    .step-icon { font-size: 40px; display: block; margin-bottom: 12px; }
    .step-title {
        font-size: 1.125rem;
        font-weight: 600;
        color: #B5FF47;
        margin-bottom: 8px;
        font-family: 'Inter Tight', sans-serif;
    }
    .step-desc {
        font-size: 0.875rem;
        color: #AAB2C0;
    }
    .faq-item {
        border-bottom: 1px solid rgba(255,255,255,0.08);
        padding: 16px 0;
    }
    .faq-question {
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
        font-weight: 500;
        color: #FFFFFF;
        transition: color 0.3s;
        font-family: 'Manrope', sans-serif;
    }
    .faq-question:hover { color: #B5FF47; }
    .faq-answer {
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.4s ease, padding 0.3s;
        color: #AAB2C0;
        padding: 0;
        font-family: 'Manrope', sans-serif;
    }
    .faq-answer.open {
        max-height: 300px;
        padding: 12px 0 0 0;
    }
    .seo-text {
        margin-top: 60px;
        padding-top: 40px;
        border-top: 1px solid rgba(255,255,255,0.08);
        font-size: 0.95rem;
        color: #AAB2C0;
        line-height: 1.7;
    }
    .seo-text h3 {
        color: #B5FF47;
        font-family: 'Inter Tight', sans-serif;
        font-size: 1.4rem;
        margin-bottom: 16px;
    }
    .seo-text p { margin-bottom: 14px; }
    .seo-text ul {
        list-style: none;
        padding: 0;
        font-family: 'Manrope', sans-serif;
        color: #AAB2C0;
    }
    .seo-text ul li {
        padding: 4px 0 4px 24px;
        background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') left center no-repeat;
        background-size: 16px;
        margin-bottom: 2px;
    }
    @media (max-width: 700px) {
        .apple-hero h1 { font-size: 1.8rem; white-space: normal; }
        .apple-hero .subtitle { font-size: 1rem; }
        .apple-text-block { padding: 24px 20px; }
        .apple-list li { font-size: 0.95rem; padding-left: 30px; }
        .steps-grid { grid-template-columns: 1fr; gap: 16px; }
        .cases-block { flex-direction: column; gap: 12px; padding: 12px; }
        .cases-block .case-item .number { font-size: 1.4rem; }
        .seo-text { margin-top: 40px; padding-top: 30px; }
    }
    @media (max-width: 480px) {
        .apple-hero h1 {
            font-size: 1.4rem;
            white-space: normal;
        }
    }
</style>

<div class="apple-hero">
    <h1>Ты теряешь клиентов? Я покажу где — за 2 минуты.</h1>
    <p class="subtitle">
        AI просканирует твою нишу, конкурентов и воронку. Ты получишь отчёт, который уже принёс моим клиентам от 120 000 ₽ за первый месяц.
    </p>
    <div style="margin: 24px 0 32px;">
        <a href="/survey" class="btn-main" onclick="ym(108348240,'reachGoal','click_lead_magnet'); return true;">Получить бесплатный план</a>
    </div>
</div>

<!-- Блок: Что ты получишь -->
<div class="apple-text-block">
    <p><strong>Что ты получишь прямо сейчас:</strong></p>
    <ul class="apple-list">
        <li><strong>Карту утечек</strong> — увидишь, на каком этапе клиенты уходят и как это закрыть.</li>
        <li><strong>Три готовых оффера</strong> под твою аудиторию — бери и тестируй завтра.</li>
        <li><strong>Чек-лист первых действий</strong> — что сделать за 3 дня, чтобы получить заявки.</li>
    </ul>
    <p style="font-size:1rem; color:#AAB2C0;">Всё это — <strong style="color:#B5FF47;">бесплатно</strong>. Без подписок и скрытых платежей.</p>
</div>

<!-- Блок: Как это работает -->
<div style="text-align:center; margin: 60px 0;" id="how-it-works">
    <h2 style="color:#B5FF47; font-family:'Inter Tight',sans-serif; text-shadow: 0 0 20px rgba(181,255,71,0.15);">Как это работает</h2>
    <div class="steps-grid">
        <div class="step-card">
            <span class="step-icon">📝</span>
            <div class="step-title">Отвечаешь на 5 вопросов</div>
            <div class="step-desc">2 минуты — без лишней воды.</div>
        </div>
        <div class="step-card">
            <span class="step-icon">🤖</span>
            <div class="step-title">AI анализирует</div>
            <div class="step-desc">Сверяет с данными по нише и находит скрытые возможности.</div>
        </div>
        <div class="step-card">
            <span class="step-icon">📥</span>
            <div class="step-title">Скачиваешь отчёт от AI</div>
            <div class="step-desc">Чёткий план: где сливаешь деньги, как остановить и с чего начать.</div>
        </div>
    </div>
</div>

<!-- Блок: Почему это работает (кейсы) -->
<div style="margin: 40px 0;" id="cases">
    <h2 style="text-align:center; color:#B5FF47; font-family:'Inter Tight',sans-serif; text-shadow: 0 0 20px rgba(181,255,71,0.15);">Почему это работает</h2>
    <p style="text-align:center; color:#AAB2C0; max-width:600px; margin:0 auto 20px; font-family:'Manrope',sans-serif;">
        Я обучила AI на реальных кейсах экспертов в <strong style="color:#B5FF47;">50+ нишах</strong> и получила впечатляющие результаты:
    </p>
    <div class="cases-block">
        <div class="case-item">
            <div class="number">+120 000 ₽</div>
            <div class="label">Специалист по китайскому</div>
            <div class="case-detail">без блога, с нуля</div>
        </div>
        <div class="case-item">
            <div class="number">+187 000 ₽</div>
            <div class="label">Психолог</div>
            <div class="case-detail">первый онлайн-курс</div>
        </div>
        <div class="case-item">
            <div class="number">+2 000 000 ₽</div>
            <div class="label">Онлайн-школа коучинга</div>
            <div class="case-detail">за 2 недели в VK</div>
        </div>
    </div>
    <p style="text-align:center; color:#AAB2C0; font-family:'Manrope',sans-serif; font-size:1rem;">
        Твой план будет <strong style="color:#B5FF47;">под твою нишу</strong>. Не шаблон, а личная карта.
    </p>
</div>

<!-- Блок: Кому это нужно -->
<div class="glass-card" style="max-width:700px; margin:40px auto; text-align:left;">
    <h3 style="color:#B5FF47; font-family:'Inter Tight',sans-serif;">Кому это нужно</h3>
    <ul style="list-style:none; padding:0; color:#FFFFFF; font-family:'Manrope',sans-serif;">
        <li style="padding:6px 0 6px 28px; background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') left center no-repeat; background-size:16px;">Ты эксперт, коуч, психолог или владелец онлайн-школы.</li>
        <li style="padding:6px 0 6px 28px; background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') left center no-repeat; background-size:16px;">У тебя уже есть клиенты, но хочешь больше и стабильнее.</li>
        <li style="padding:6px 0 6px 28px; background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') left center no-repeat; background-size:16px;">Ты только начинаешь и не знаешь, куда бить.</li>
        <li style="padding:6px 0 6px 28px; background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="%23B5FF47" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>') left center no-repeat; background-size:16px;">Ты сливаешь бюджет на рекламу, а она не окупается.</li>
    </ul>
    <p style="color:#AAB2C0; margin-top:12px; font-size:0.95rem;">Хотя бы один пункт — мой план для тебя.</p>
</div>

<!-- Блок: Развею ваши сомнения (заголовок заменён) -->
<div style="margin: 40px 0; max-width:700px; margin-left:auto; margin-right:auto;">
    <h3 style="text-align:center; color:#B5FF47; font-family:'Inter Tight',sans-serif; margin-bottom:20px;">Развею ваши сомнения</h3>
    <div class="faq-item">
        <div class="faq-question" onclick="this.nextElementSibling.classList.toggle('open')">
            <span>❓ Это правда бесплатно?</span>
            <span class="arrow">▼</span>
        </div>
        <div class="faq-answer">Да. Диагностика — мой способ показать ценность, чтобы ты захотел(а) работать дальше.</div>
    </div>
    <div class="faq-item">
        <div class="faq-question" onclick="this.nextElementSibling.classList.toggle('open')">
            <span>❓ Что я получу?</span>
            <span class="arrow">▼</span>
        </div>
        <div class="faq-answer">Отчёт от AI с анализом твоей ситуации, тремя точками роста и конкретными шагами на неделю.</div>
    </div>
    <div class="faq-item">
        <div class="faq-question" onclick="this.nextElementSibling.classList.toggle('open')">
            <span>❓ А если я новичок?</span>
            <span class="arrow">▼</span>
        </div>
        <div class="faq-answer">Тем более. План содержит пошаговые инструкции даже для тех, кто никогда не занимался маркетингом.</div>
    </div>
    <div class="faq-item">
        <div class="faq-question" onclick="this.nextElementSibling.classList.toggle('open')">
            <span>❓ Когда увижу результат?</span>
            <span class="arrow">▼</span>
        </div>
        <div class="faq-answer">Рекомендации можно внедрить за 3 дня. Первые изменения заметишь уже на следующей неделе.</div>
    </div>
</div>

<!-- Призыв к действию (CTA) -->
<div style="text-align:center; margin: 40px 0;" id="pricing">
    <h2 style="color:#B5FF47; font-family:'Inter Tight',sans-serif; text-shadow: 0 0 20px rgba(181,255,71,0.15);">Получить бесплатный план привлечения клиентов</h2>
    <ul style="list-style:none; padding:0; color:#AAB2C0; font-family:'Manrope',sans-serif; margin:16px 0 24px;">
        <li style="display:inline-block; margin:0 16px;">✅ Заполни анкету — 2 минуты</li>
        <li style="display:inline-block; margin:0 16px;">✅ Получи персональный AI-разбор</li>
        <li style="display:inline-block; margin:0 16px;">✅ Начни привлекать клиентов завтра</li>
    </ul>
    <a href="/survey" class="btn-main" onclick="ym(108348240,'reachGoal','click_lead_magnet'); return true;">Пройти диагностику</a>
</div>

<!-- Финальный блок — моё слово -->
<div class="glass-card" style="max-width:700px; margin:40px auto; text-align:center; border-color:rgba(181,255,71,0.2);">
    <p style="font-size:1.2rem; color:#FFFFFF; font-family:'Manrope',sans-serif; font-style:italic;">
        «Я не даю общих советов. Я даю план, который работает лично для тебя. А если нет — я доработаю его бесплатно.»
    </p>
    <p style="margin-top:8px; color:#B5FF47; font-family:'Inter Tight',sans-serif; font-weight:600;">
        Вероника Макаревич<br>
        <span style="font-weight:400; font-size:0.9rem; color:#AAB2C0;">Продюсер экспертов, автор AI-методики</span>
    </p>
</div>

<!-- SEO-текст (исправлен список) -->
<div class="seo-text">
    <h3>Привлечение клиентов для экспертов: как работает система</h3>
    <p>Вы эксперт, коуч, психолог или владелец онлайн-школы? Тогда вы знаете, как сложно привлекать клиентов в условиях высокой конкуренции. Моя система, основанная на AI-аналитике и реальных кейсах, помогает экспертам получать стабильный поток заявок уже через 14 дней после внедрения.</p>
    <p>Я — Вероника Макаревич, продюсер экспертов. Моя специализация — настройка воронок продаж, разработка офферов и скриптов, а также запуск рекламных кампаний. Я работаю с экспертами из разных ниш: коучинг, психология, обучение, наставничество, и помогаю им выходить на новый уровень дохода.</p>
    <p><strong>Как я привлекаю клиентов для экспертов?</strong> Я использую AI-аналитику для сканирования ниши, конкурентов и аудитории. На основе данных я создаю персональный план действий, который включает в себя:</p>
    <ul>
        <li>Проверку текущей воронки продаж и выявление точек утечки клиентов</li>
        <li>Разработку оффера, который цепляет целевую аудиторию</li>
        <li>Настройку рекламных каналов (Яндекс Директ, VK, Telegram)</li>
        <li>Готовые скрипты продаж и возражений</li>
    </ul>
    <p>В результатах моих клиентов — первые заявки уже через 14 дней, а средний чек увеличивается в 2-3 раза. Я не просто даю план — я внедряю его вместе с вами, контролируя ключевые метрики и корректируя стратегию по ходу.</p>
    <p>Хотите узнать, как привлечь клиентов в вашу нишу? Заполните анкету из 5 вопросов, и AI-аналитик подготовит персональный разбор бесплатно. А после этого мы с вами обсудим, какой тариф подходит именно вам — от бесплатного разбора до полного внедрения под ключ с гарантией первых заявок за 14 дней.</p>
</div>
'''
    return HTMLResponse(content=render_page(content,
        title="Привлечение клиентов для экспертов, коучей и психологов | Вероника Макаревич",
        description="Помогаю экспертам, коучам и психологам привлекать клиентов. Получите персональный план привлечения клиентов за 14 дней. Бесплатная AI-диагностика."
    ))

# ========================================
# ОСТАЛЬНЫЕ СТРАНИЦЫ (без изменений)
# ========================================
# Здесь находятся все остальные маршруты:
# /survey, /survey/submit, /thank-you, /payment, /create_yookassa_payment,
# /payment/webhook, /payment/confirm, /payment/success, /consultation,
# /implementation, /admin/dashboard, /admin/api/*, /oferta, /privacy,
# /check_status, /check-premium-status и т.д.
# Их код идентичен вашему исходному файлу и не был изменён.
# Для краткости они не дублируются, но должны быть в вашем файле.

# === ЗАПУСК ===
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
