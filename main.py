# File: main.py — веб-приложение Salesplan (версия с УТП для психологов, фокус на воронку)

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
    if path in ["/", "/survey", "/payment", "/payment/success", "/thank-you", "/choose-plan", "/lead-magnet", "/consultation", "/generate-premium-report", "/implementation"]:
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
    # q4, q5 могут быть None, поэтому используем get с запасными значениями
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
    prompt = f"""Сделай профессиональную диагностику воронки для психолога.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши отчёт в деловом, мудром стиле. Без лишних слов. Обращайся на "ты".

Структура:
1. ЧТО СЕЙЧАС?
   - Оценка текущей воронки (0-100)
   - 3 признака, что конверсия падает из-за системных ошибок
   - Честная оценка: где вы теряете деньги прямо сейчас

2. 3 ТОЧКИ УТЕЧКИ (конкретно по вашему случаю)
   - Утечка 1: что происходит на этапе привлечения/прогрева
   - Утечка 2: что происходит на вебинаре (оффер, структура, призыв)
   - Утечка 3: что происходит после вебинара (касания, скрипты продаж)

3. ПЛАН НА 14 ДНЕЙ
   - День 1-3: что править в оффере и прогреве прямо сейчас
   - День 4-7: какие касания добавить после вебинара
   - День 8-14: как тестировать и масштабировать

4. ПРОГНОЗ
   - Сколько клиентов вы могли бы получить при конверсии 12-18%
   - Сколько денег вы теряете на каждой точке утечки
   - Что изменится через 14 дней после внедрения правок"""
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
    prompt = f"""Сделай расширенный маркетинговый план для психолога.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
Средний чек: {answers.get('q1', 'не указано')}
Клиентов/мес: {answers.get('q2', 'не указано')}
Цель: {answers.get('q3', 'не указано')}

Требования:
1. Все разделы должны содержать конкретные числа, примеры и готовые формулировки.
2. В конце плана – чек-лист из 50 пунктов и 5 главных действий на первую неделю.
3. Пиши деловым, прямым стилем. Без воды.
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

# === ГЛОБАЛЬНЫЕ HTML ШАБЛОНЫ И CSS ===
HTML_HEAD = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>AI-диагностика воронки для психологов | Вероника Макаревич</title>
    <meta name="description" content="Психологам: вебинар не продаёт? AI-диагностика всей воронки за 2 минуты. 14 дней до первых заявок. Или работаю бесплатно.">
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
        body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#0F1331;color:#FFFFFF;line-height:1.5}
        .container{max-width:1200px;margin:0 auto;padding:0 20px}
        h1,h2,h3,.logo{font-family:'Manrope',-apple-system,sans-serif;font-weight:700;letter-spacing:-0.02em}
        .mono{font-family:'JetBrains Mono',monospace}
        .text-white{color:#FFFFFF}
        .text-cyan{color:#28E0C6}
        .text-coral{color:#FF6B6B}
        .bg-cyan{background:#28E0C6}
        .bg-dark{background:#0F1331}
        .bg-card{background:rgba(26,29,58,0.7);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(40,224,198,0.15);border-radius:12px}
        .btn{display:inline-block;padding:14px 36px;border-radius:48px;font-weight:600;font-size:16px;border:none;cursor:pointer;transition:all 0.2s;text-decoration:none;font-family:'Inter',sans-serif}
        .btn-primary{background:#28E0C6;color:#0F1331;box-shadow:0 4px 20px rgba(40,224,198,0.3)}
        .btn-primary:hover{background:#1fb8a2;transform:translateY(-2px);box-shadow:0 8px 30px rgba(40,224,198,0.4)}
        .btn-outline{background:transparent;color:#28E0C6;border:1px solid #28E0C6}
        .btn-outline:hover{background:rgba(40,224,198,0.1)}
        .btn-ghost{background:transparent;color:#FFFFFF;border:1px solid rgba(255,255,255,0.2)}
        .btn-ghost:hover{background:rgba(255,255,255,0.05)}
        .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:40px}
        .grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:30px}
        @media(max-width:768px){.grid-2,.grid-3{grid-template-columns:1fr;gap:24px}}
        .glass{background:rgba(26,29,58,0.6);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(40,224,198,0.1);border-radius:12px;padding:24px;transition:all 0.3s}
        .glass:hover{transform:translateY(-4px);border-color:rgba(40,224,198,0.3);box-shadow:0 12px 40px rgba(0,0,0,0.3)}
        .navbar{position:fixed;top:0;left:0;right:0;z-index:1000;padding:16px 0;background:rgba(15,19,49,0.7);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid rgba(40,224,198,0.1)}
        .navbar .container{display:flex;justify-content:space-between;align-items:center}
        .nav-links{display:flex;gap:32px;align-items:center}
        .nav-links a{color:#FFFFFF;text-decoration:none;font-size:14px;transition:color 0.2s}
        .nav-links a:hover{color:#28E0C6}
        .burger{display:none;flex-direction:column;gap:5px;cursor:pointer}
        .burger span{width:28px;height:2px;background:#FFFFFF;transition:0.3s}
        @media(max-width:768px){.nav-links{display:none;flex-direction:column;position:absolute;top:70px;left:0;right:0;background:#0F1331;padding:24px;gap:20px;border-bottom:1px solid rgba(40,224,198,0.1)}.nav-links.open{display:flex}.burger{display:flex}}
        .hero{min-height:100vh;display:flex;align-items:center;position:relative;overflow:hidden;padding:120px 0 80px}
        .hero-bg{position:absolute;inset:0;background:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><rect fill="%230F1331" width="1200" height="800"/><path d="M0 400 Q300 200 600 400 T1200 400" stroke="%2328E0C6" stroke-width="1" fill="none" opacity="0.1"/><circle cx="200" cy="300" r="150" fill="%2328E0C6" opacity="0.03"/><circle cx="900" cy="500" r="200" fill="%23FF6B6B" opacity="0.02"/></svg>') center/cover no-repeat;z-index:0}
        .hero-content{position:relative;z-index:1;max-width:720px}
        .hero h1{font-size:52px;line-height:1.1;margin-bottom:16px}
        .hero .subtitle{font-size:20px;color:#a0aec0;margin-bottom:32px}
        .hero .badge{display:inline-block;background:rgba(40,224,198,0.15);color:#28E0C6;padding:6px 16px;border-radius:20px;font-size:14px;margin-bottom:20px}
        .hero .micro-proofs{display:flex;gap:24px;margin-top:32px;flex-wrap:wrap}
        .hero .micro-proofs .item{display:flex;align-items:center;gap:8px;font-size:14px;color:#a0aec0}
        .hero .micro-proofs .item .num{color:#28E0C6;font-weight:700}
        @media(max-width:768px){.hero h1{font-size:32px}.hero .subtitle{font-size:18px}}
        section{padding:80px 0}
        section h2{font-size:36px;margin-bottom:16px}
        section .section-sub{font-size:18px;color:#a0aec0;margin-bottom:40px}
        .text-center{text-align:center}
        .mt-16{margin-top:16px}
        .mt-32{margin-top:32px}
        .mb-16{margin-bottom:16px}
        .mb-32{margin-bottom:32px}
        .flex-center{display:flex;justify-content:center;align-items:center}
        .gap-16{gap:16px}
        .gap-24{gap:24px}
        .flex-wrap{flex-wrap:wrap}
        @media(max-width:768px){section{padding:48px 0}section h2{font-size:28px}.hero{padding:100px 0 48px}}
        .footer{padding:40px 0;border-top:1px solid rgba(40,224,198,0.1);margin-top:40px}
        .footer .container{display:flex;justify-content:space-between;flex-wrap:wrap;gap:20px}
        .footer a{color:#a0aec0;text-decoration:none;font-size:14px}
        .footer a:hover{color:#28E0C6}
        .faq-item{border-bottom:1px solid rgba(40,224,198,0.1);padding:16px 0}
        .faq-item .question{display:flex;justify-content:space-between;cursor:pointer;font-weight:600;font-size:18px}
        .faq-item .answer{max-height:0;overflow:hidden;transition:max-height 0.3s;color:#a0aec0;padding-top:0}
        .faq-item.open .answer{max-height:300px;padding-top:12px}
        .faq-item .question .icon{transition:transform 0.3s}
        .faq-item.open .question .icon{transform:rotate(180deg)}
        .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(8px);z-index:2000;justify-content:center;align-items:center}
        .modal-overlay.active{display:flex}
        .modal{background:#0F1331;border:1px solid rgba(40,224,198,0.2);border-radius:16px;padding:40px;max-width:480px;width:90%;position:relative}
        .modal .close{position:absolute;top:16px;right:20px;font-size:24px;cursor:pointer;color:#a0aec0}
        .modal h3{font-size:24px;margin-bottom:8px}
        .modal p{color:#a0aec0;margin-bottom:24px}
        .modal input,.modal textarea{width:100%;padding:12px 16px;border-radius:8px;border:1px solid rgba(40,224,198,0.2);background:rgba(255,255,255,0.05);color:#FFFFFF;font-size:16px;margin-bottom:16px;font-family:'Inter',sans-serif}
        .modal input:focus,.modal textarea:focus{outline:none;border-color:#28E0C6}
        .modal .btn{width:100%;justify-content:center}
        .btn-main{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:16px 48px;font-size:20px;font-weight:600;border-radius:48px;box-shadow:0 2px 8px rgba(0,122,255,0.3);transition:transform 0.2s,box-shadow 0.2s;border:none;cursor:pointer}
        .btn-main:hover{background:#005fc5;transform:scale(1.02);box-shadow:0 4px 12px rgba(0,122,255,0.4)}
    </style>
</head>
<body>
<div class="container">
"""

HTML_FOOT = """
    </div>
    <div class="footer">
        <div class="container">
            <div>
                <div class="logo" style="font-size:18px;font-weight:700;color:#28E0C6;">Вероника Макаревич</div>
                <div style="font-size:12px;color:#a0aec0;margin-top:4px;">Продюсер экспертов</div>
                <div style="font-size:12px;color:#a0aec0;margin-top:8px;">© 2026</div>
            </div>
            <div>
                <a href="/oferta">Публичная оферта</a> | <a href="/privacy">Политика конфиденциальности</a>
            </div>
            <div>
                <a href="mailto:veranikamakarevich@yandex.ru">veranikamakarevich@yandex.ru</a><br>
                <a href="https://t.me/veronika_makarevich" target="_blank">Telegram</a> | 
                <a href="https://vk.com/makarevichveronika" target="_blank">VK</a> |
                <a href="https://max.ru/id781407988795_biz" target="_blank">MAX</a>
            </div>
        </div>
    </div>
    <div class="modal-overlay" id="popup">
        <div class="modal">
            <span class="close" onclick="closePopup()">&times;</span>
            <h3>Проверьте свою воронку</h3>
            <p>AI за 2 минуты найдёт 3 утечки и даст план на 14 дней. Заполните форму – я пришлю диагностику и свяжусь с вами.</p>
            <form action="/survey/submit" method="post" onsubmit="closePopup();">
                <input type="text" name="business_name" placeholder="Ваше имя" required>
                <input type="text" name="phone" placeholder="Телефон или Telegram" required>
                <textarea name="business_description" rows="3" placeholder="Кратко опишите свою нишу, сколько было на вебинаре и сколько дошли до оплаты" required></textarea>
                <input type="hidden" name="q1" value="до 5k">
                <input type="hidden" name="q2" value="<10">
                <input type="hidden" name="q3" value="Масштаб">
                <input type="hidden" name="consent" value="on">
                <button type="submit" class="btn btn-primary">Запустить диагностику</button>
            </form>
        </div>
    </div>
    <script>
        function openPopup(){document.getElementById('popup').classList.add('active');}
        function closePopup(){document.getElementById('popup').classList.remove('active');}
        document.querySelectorAll('.faq-item .question').forEach(q => {
            q.addEventListener('click', function(){this.parentElement.classList.toggle('open');});
        });
        document.querySelector('.burger')?.addEventListener('click', function(){
            document.querySelector('.nav-links').classList.toggle('open');
        });
    </script>
</body>
</html>"""

def render_page(content: str):
    return HTML_HEAD + content + HTML_FOOT

# === ВСПОМОГАТЕЛЬНЫЕ СТРАНИЦЫ ОЖИДАНИЯ ===
def render_waiting_page(user_id: str, report_type: str, redirect_url: str):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Генерируем план</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;text-align:center;padding:60px 20px;background:#0F1331;color:#fff}}.spinner{{width:50px;height:50px;border:4px solid rgba(40,224,198,0.2);border-top-color:#28E0C6;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
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
<body><div class="spinner"></div><h1>Анализируем вашу воронку</h1><p>AI ищет точки утечки. Это займёт 1-2 минуты.</p></body>
</html>"""

# ============================================================
# ГЛАВНАЯ СТРАНИЦА — НОВОЕ УТП (психологи, воронка, гарантия)
# ============================================================
@app.get("/")
async def index():
    content = '''
<style>
    .apple-hero {
        text-align: center;
        max-width: 820px;
        margin: 0 auto;
        padding: 40px 20px;
    }
    .apple-hero h1 {
        font-size: 56px;
        font-weight: 700;
        letter-spacing: -0.03em;
        line-height: 1.1;
        margin-bottom: 16px;
        color: #fff;
    }
    .apple-hero .subtitle {
        font-size: 24px;
        font-weight: 400;
        color: #a0aec0;
        max-width: 700px;
        margin: 0 auto 32px;
        line-height: 1.4;
    }
    .cases-block {
        display: flex;
        justify-content: center;
        gap: 40px;
        flex-wrap: wrap;
        margin: 20px 0 30px;
        background: rgba(26,29,58,0.4);
        border-radius: 24px;
        padding: 24px 20px;
        border: 1px solid rgba(40,224,198,0.1);
    }
    .cases-block .case-item {
        text-align: center;
        flex: 1;
        min-width: 100px;
    }
    .cases-block .case-item .number {
        font-size: 28px;
        font-weight: 700;
        color: #28E0C6;
    }
    .cases-block .case-item .label {
        font-size: 14px;
        color: #a0aec0;
    }
    .apple-text-block {
        background: rgba(26,29,58,0.5);
        border-radius: 28px;
        padding: 40px 48px;
        margin: 32px auto;
        text-align: left;
        font-size: 18px;
        line-height: 1.6;
        color: #fff;
        box-shadow: 0 2px 12px rgba(0,0,0,0.04);
        border: 1px solid rgba(40,224,198,0.05);
    }
    .apple-text-block p {
        margin-bottom: 16px;
    }
    .apple-text-block strong {
        font-weight: 600;
        color: #28E0C6;
    }
    .apple-list {
        list-style: none;
        padding: 0;
        margin: 20px 0 24px;
    }
    .apple-list li {
        padding: 8px 0 8px 36px;
        background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="%2328E0C6" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>') left center no-repeat;
        background-size: 20px;
        margin-bottom: 4px;
        font-size: 17px;
        color: #fff;
    }
    .apple-divider {
        border: none;
        border-top: 1px solid rgba(40,224,198,0.2);
        margin: 28px 0;
    }
    .apple-cta {
        margin: 40px 0 24px;
    }
    .apple-footer-link {
        font-size: 15px;
        color: #a0aec0;
        margin-top: 32px;
    }
    .apple-footer-link a {
        color: #28E0C6;
        text-decoration: none;
        font-weight: 500;
    }
    .apple-footer-link a:hover {
        text-decoration: underline;
    }
    @media (max-width: 700px) {
        .apple-hero h1 { font-size: 36px; }
        .apple-hero .subtitle { font-size: 20px; }
        .apple-text-block { padding: 24px 20px; }
        .apple-list li { font-size: 16px; padding-left: 30px; }
        .cases-block { gap: 20px; padding: 16px; }
        .cases-block .case-item .number { font-size: 22px; }
    }
</style>

<div class="apple-hero">
    <h1>Психологам: вебинар не продаёт? AI-диагностика всей воронки за 2 минуты найдёт 3 утечки. План на 14 дней — и заявки возвращаются. Или я работаю бесплатно.</h1>
    <p class="subtitle">Вероника Макаревич, продюсер экспертов. Я обучила AI на 50+ нишах — теперь он анализирует не только вебинар, а всю воронку: привлечение, прогрев, касания, скрипты продаж. Вы получите готовый план, который уже привёл клиентов психологам.</p>

    <!-- Блок кейсов -->
    <div class="cases-block">
        <div class="case-item">
            <div class="number">+120 000 ₽</div>
            <div class="label">эксперту по китайскому без блога</div>
        </div>
        <div class="case-item">
            <div class="number">+187 000 ₽</div>
            <div class="label">психологу с одного вебинара</div>
        </div>
        <div class="case-item">
            <div class="number">+2 000 000 ₽</div>
            <div class="label">онлайн-школе за марафон</div>
        </div>
    </div>

    <div class="apple-text-block">
        <p><strong>Как это работает:</strong> мой AI-аналитик обучен на 50+ нишах. Он сканирует всю вашу воронку — откуда приходят люди, как их прогревают, что происходит на вебинаре, какие касания после и как закрывают продажи. За 2 минуты выявляет 3 точки утечки.</p>
        <ul class="apple-list">
            <li>Выявим 3 утечки во всей воронке — не только в вебинаре</li>
            <li>Рассчитаем бюджет, который окупится за 14 дней</li>
            <li>Дадим готовые скрипты, касания и воронку, которые работают без вас</li>
        </ul>
        <hr class="apple-divider">
        <p style="font-size: 19px; font-weight: 500;">План и скрипты вы получите сразу после ответов на 5 вопросов.</p>
    </div>

    <div class="apple-cta">
        <a href="/survey" class="btn-primary" style="padding:16px 48px;font-size:20px;border-radius:48px;display:inline-block;" onclick="ym(108348240,'reachGoal','click_lead_magnet'); return true;">Проверить воронку бесплатно</a>
    </div>

    <div class="apple-footer-link">
        Есть вопросы? <a href="https://max.ru/id781407988795_biz" target="_blank">Напишите мне в MAX</a>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# ============================================================
# ОСТАЛЬНЫЕ СТРАНИЦЫ (БЕЗ ИЗМЕНЕНИЙ, КРОМЕ НЕБОЛЬШИХ КОРРЕКТИРОВОК)
# ============================================================

@app.get("/lead-magnet")
async def lead_magnet():
    return RedirectResponse(url="/", status_code=301)

@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<style>
    .form-card{background:rgba(26,29,58,0.7);backdrop-filter:blur(12px);border:1px solid rgba(40,224,198,0.15);border-radius:24px;padding:32px;box-shadow:0 4px 12px rgba(0,0,0,0.05);max-width:600px;margin:0 auto}
    .form-group{margin-bottom:24px}
    label{font-size:15px;font-weight:500;display:block;margin-bottom:8px;color:#fff}
    input,textarea{width:100%;padding:12px;font-size:15px;border:1px solid rgba(40,224,198,0.2);border-radius:10px;background:rgba(255,255,255,0.05);color:#fff;font-family:'Inter',sans-serif}
    input:focus,textarea:focus{outline:none;border-color:#28E0C6}
    .radio-group{display:flex;flex-direction:column;gap:12px;margin-top:8px}
    .radio-group label{display:flex;align-items:center;gap:8px;font-weight:normal;cursor:pointer;padding:8px 12px;background:rgba(255,255,255,0.03);border-radius:12px;transition:background 0.2s;color:#fff}
    .radio-group label:hover{background:rgba(40,224,198,0.1)}
    .radio-group input[type="radio"]{width:20px;height:20px;margin:0;cursor:pointer;accent-color:#28E0C6}
    .btn-main{display:inline-block;background:#28E0C6;color:#0F1331;text-decoration:none;padding:16px 48px;font-size:20px;font-weight:600;border-radius:48px;box-shadow:0 2px 8px rgba(40,224,198,0.3);transition:transform 0.2s,box-shadow 0.2s;border:none;cursor:pointer}
    .btn-main:hover{background:#1fb8a2;transform:scale(1.02);box-shadow:0 4px 12px rgba(40,224,198,0.4)}
</style>
<div class="hero" style="padding-top:40px;">
    <h1 style="color:#fff;">5 вопросов – и вы получите диагностику всей воронки</h1>
    <p style="font-size:18px;color:#a0aec0;">AI-аналитик оценит вашу нишу, найдёт слабые места и предложит первые шаги. Это займёт 2 минуты.</p>
</div>
<div class="form-card">
    <form action="/survey/submit" method="post" id="surveyForm">
        <div class="form-group"><label>1. Название вашего экспертного проекта</label><input type="text" name="business_name" placeholder="например: Продюсирую экспертов" required></div>
        <div class="form-group"><label>2. Чем вы помогаете клиентам? (кратко)</label><textarea name="business_description" rows="3" placeholder="Пример: Воронка: бесплатная диагностика → план запуска → разбор" required></textarea></div>
        <div class="form-group"><label>3. Средний чек (₽)</label><div class="radio-group"><label><input type="radio" name="q1" value="до 5k" required> до 5k</label><label><input type="radio" name="q1" value="5k-20k"> 5k-20k</label><label><input type="radio" name="q1" value="20k-50k"> 20k-50k</label><label><input type="radio" name="q1" value=">50k"> >50k</label></div></div>
        <div class="form-group"><label>4. Клиентов в месяц (примерно)</label><div class="radio-group"><label><input type="radio" name="q2" value="<10" required> меньше 10</label><label><input type="radio" name="q2" value="10-50"> 10-50</label><label><input type="radio" name="q2" value="50-200"> 50-200</label><label><input type="radio" name="q2" value=">200"> более 200</label></div></div>
        <div class="form-group"><label>5. Цель на 2026 (в деньгах)</label><div class="radio-group"><label><input type="radio" name="q3" value="300k/мес" required> 300k/мес</label><label><input type="radio" name="q3" value="500k/мес"> 500k/мес</label><label><input type="radio" name="q3" value="1M/мес"> 1M/мес</label><label><input type="radio" name="q3" value="Масштаб"> Масштаб (выход на новый уровень)</label></div></div>
        <div class="form-group">
            <label style="display:flex;align-items:center;gap:8px;color:#fff;">
                <input type="checkbox" name="consent" required style="width:20px;height:20px;accent-color:#28E0C6;">
                <span>Я принимаю условия публичной оферты и даю согласие на обработку персональных данных</span>
            </label>
        </div>
        <div style="text-align:center;margin-top:20px;">
            <button type="submit" class="btn-main" id="submitBtn" onclick="ym(108348240,'reachGoal','survey_submit'); return true;">
                Получить диагностику
            </button>
        </div>
    </form>
</div>
<script>
    document.getElementById('surveyForm').addEventListener('submit', function(e) {
        const submitBtn = document.getElementById('submitBtn');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Отправляю...';
    });
</script>
"""
    return HTMLResponse(content=render_page(content))

# === ОБРАБОТЧИК АНКЕТЫ ===
@app.post("/survey/submit")
async def survey_submit(
    request: Request,
    business_name: str = Form(...),
    business_description: str = Form(...),
    q1: str = Form(...),   # средний чек
    q2: str = Form(...),   # кол-во клиентов
    q3: str = Form(...),   # цель
    consent: str = Form(...)
):
    user_id = str(uuid.uuid4())
    logger.info(f"New survey submission: user_id={user_id}, business={business_name}")
    save_user(user_id, None, None)
    save_business_data(user_id, business_name, business_description)
    save_form(user_id, {"q1": q1, "q2": q2, "q3": q3, "q4": None, "q5": None})
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    save_consent(user_id, 'survey_and_offer', client_ip, user_agent)
    
    answers = {"q1": q1, "q2": q2, "q3": q3, "q4": None, "q5": None}
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
            fallback_text = f"Диагностика для бизнеса \"{business_name}\"\n\nОписание: {business_description}\n\nРекомендации:\n- Проанализируйте целевую аудиторию\n- Настройте воронку продаж\n- Добавьте призывы к действию"
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (fallback_text, report_id))
            logger.warning(f"Free report {report_id} using fallback text")
        conn.commit()
        conn.close()
    asyncio.create_task(generate_and_save())
    return RedirectResponse(url=f"/thank-you?user_id={user_id}", status_code=303)

# === СТРАНИЦА БЛАГОДАРНОСТИ (без изменений, но с новым стилем) ===
@app.get("/thank-you", response_class=HTMLResponse)
async def thank_you(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT status, report_text FROM reports WHERE user_id = ? AND report_type = 'free' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not row or row[0] != 'ready':
        return HTMLResponse(content=render_waiting_page(user_id, "free", f"/thank-you?user_id={user_id}"))

    report_text_html = row[1].replace("\n", "<br>") if row[1] else ""

    content = f'''
<div style="background:rgba(26,29,58,0.6); border-radius:28px; padding:24px; margin-top:20px; text-align:center;">
    <h1 style="font-size:32px; margin-bottom:8px;color:#fff;">Ваш план готов</h1>
    <p style="font-size:16px; color:#a0aec0; margin-bottom:16px;">
        В этом документе – конкретные шаги, основанные на том, что реально привело клиентов в 50+ нишах.
        <br><strong style="color:#28E0C6;">Листайте вниз, чтобы прочитать документ полностью.</strong>
    </p>
    <div style="max-height:300px; overflow-y:auto; background:rgba(0,0,0,0.3); border-radius:16px; padding:16px; text-align:left; font-size:14px; line-height:1.5; color:#fff;">
        <div style="white-space:pre-wrap;">{report_text_html}</div>
    </div>
</div>

<hr style="margin: 40px 0; border-color:rgba(40,224,198,0.2);">

<div style="text-align:center; max-width:600px; margin:0 auto;">
    <p style="font-size:18px;color:#fff;">Хотите, чтобы я лично внедрила этот план и привела вам клиентов?</p>
    <div style="display:flex; flex-direction:column; gap:16px; margin:24px 0;">
        <div style="background:rgba(26,29,58,0.6); border-radius:16px; padding:16px; border:1px solid rgba(40,224,198,0.1);">
            <p style="color:#fff;"><strong>Бесплатно</strong> – подпишитесь на мой канал в MAX, я разбираю реальные кейсы и отвечаю на вопросы.</p>
        </div>
        <div style="background:rgba(40,224,198,0.1); border-radius:16px; padding:16px; border:1px solid #28E0C6;">
            <p style="color:#fff;"><strong>Расширенный план (2500 ₽)</strong> – скрипты, бюджеты, контент-план, чек-лист из 50 пунктов + 30-мин консультация.</p>
        </div>
        <div style="background:rgba(255,107,107,0.1); border-radius:16px; padding:16px; border:1px solid #FF6B6B;">
            <p style="color:#fff;"><strong>Внедрение под ключ (14 900 ₽)</strong> – я лично настраиваю воронку, запускаю рекламу, пишу скрипты, еженедельно корректирую. <strong style="color:#28E0C6;">Гарантия:</strong> если через 14 дней нет заявок – я возвращаю деньги или работаю до первого клиента бесплатно.</p>
        </div>
    </div>
    <a href="/choose-plan?user_id={user_id}" class="btn-main" onclick="ym(108348240,'reachGoal','to_choose_plan'); return true;">
        Выбрать вариант
    </a>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === СТРАНИЦА ВЫБОРА СТРАТЕГИИ ===
@app.get("/choose-plan", response_class=HTMLResponse)
async def choose_plan(user_id: str):
    channel_link = "https://max.ru/id781407988795_biz"
    payment_link_2500 = f"/payment?user_id={user_id}&amount=2500"
    payment_link_14900 = f"/payment?user_id={user_id}&amount=14900"

    content = f'''
<div style="max-width:700px; margin:0 auto; padding:20px 16px;">
    <div style="background:rgba(26,29,58,0.4); border-radius:20px; padding:20px; margin-bottom:24px; text-align:center; border:1px solid rgba(40,224,198,0.1);">
        <h3 style="font-size:18px; margin-bottom:12px;color:#28E0C6;">Результаты, на которых обучен мой AI-аналитик</h3>
        <div style="display:flex; justify-content:space-around; flex-wrap:wrap; gap:12px;">
            <div><span style="font-weight:700; font-size:20px;color:#28E0C6;">+120 000 ₽</span><br><span style="font-size:14px; color:#a0aec0;">без блога</span></div>
            <div><span style="font-weight:700; font-size:20px;color:#28E0C6;">+187 000 ₽</span><br><span style="font-size:14px; color:#a0aec0;">с вебинара</span></div>
            <div><span style="font-weight:700; font-size:20px;color:#28E0C6;">+2 000 000 ₽</span><br><span style="font-size:14px; color:#a0aec0;">с марафона</span></div>
        </div>
        <p style="font-size:14px; color:#a0aec0; margin-top:12px;">50+ ниш – от психологов до онлайн-школ</p>
    </div>

    <div style="background:rgba(40,224,198,0.05); border-radius:16px; padding:16px; margin-bottom:20px; text-align:center; border:1px solid rgba(40,224,198,0.1);">
        <p style="font-size:16px;color:#fff;"><strong>Не уверены, что выбрать?</strong><br>
        Напишите мне в личный чат MAX – я бесплатно разберу ваш случай и подберу оптимальный тариф.</p>
        <a href="{channel_link}" target="_blank" class="btn-main" style="display:inline-block; padding:10px 24px; font-size:16px; background:#28E0C6; color:#0F1331; border-radius:48px; text-decoration:none;">Написать в MAX</a>
    </div>

    <h1 style="font-size:28px; font-weight:700; text-align:center; margin-bottom:8px;color:#fff;">Вы получили план. Теперь выберите, как мы будем работать с ним дальше.</h1>
    <p style="font-size:16px; color:#a0aec0; text-align:center; margin-bottom:32px;">
        Я, Вероника Макаревич, предлагаю три уровня – от бесплатной проверки до полного внедрения.
    </p>

    <!-- Вариант 1: Бесплатная проверка -->
    <div style="background:rgba(26,29,58,0.6); border-radius:20px; padding:24px; margin-bottom:16px; border:1px solid rgba(40,224,198,0.1);">
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
            <span style="font-size:28px;">🔍</span>
            <h2 style="font-size:22px; font-weight:600; margin:0;color:#fff;">Я проверю ваш план</h2>
        </div>
        <p style="font-size:15px; color:#a0aec0; margin-bottom:12px; line-height:1.5;">
            Подпишитесь на мой канал в MAX (там кейсы и разборы) – и напишите мне в личный чат слово «Проверка». Я посмотрю ваш план, укажу 3 ключевые ошибки и дам рекомендации по первым шагам.
        </p>
        <p style="font-size:14px; color:#a0aec0; margin-bottom:16px;">
            <em>Почему я?</em> Я, Вероника Макаревич, обучила AI-аналитика на своём опыте в 50+ нишах. Результаты: +120 000, +187 000, +2 000 000 – и это только часть.
        </p>
        <a href="{channel_link}" target="_blank" class="btn-primary" style="display:block; text-align:center; padding:14px 24px; font-size:17px; border-radius:48px; text-decoration:none; color:#0F1331;" onclick="ym(108348240,'reachGoal','choose_free'); return true;">
            Подписаться и написать «Проверка»
        </a>
        <p style="font-size:13px; color:#a0aec0; text-align:center; margin-top:12px;">
            Что делать: подписаться -> написать «Проверка» в личный чат MAX.
        </p>
    </div>

    <!-- Вариант 2: Расширенный план -->
    <div style="background:rgba(26,29,58,0.6); border-radius:20px; padding:24px; margin-bottom:16px; border:1px solid #28E0C6;">
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
            <span style="font-size:28px;">📄</span>
            <h2 style="font-size:22px; font-weight:600; margin:0;color:#fff;">Дорабатываю план под вас</h2>
        </div>
        <p style="font-size:15px; color:#a0aec0; margin-bottom:12px; line-height:1.5;">
            Вы получаете готовую структуру от AI-аналитика. После оплаты мы созваниваемся, я уточняю детали и дорабатываю план под ваш конкретный случай. В итоге вы получаете готовый документ:
        </p>
        <ul style="text-align:left; font-size:15px; padding-left:20px; margin-bottom:16px;color:#a0aec0;">
            <li>Бюджет на рекламу (что, куда, сколько)</li>
            <li>5 скриптов продаж (для холодных, тёплых, возражений)</li>
            <li>Воронка из 5 этапов с текстами для каждого касания</li>
            <li>Контент-план на месяц (темы, форматы, даты)</li>
            <li>Чек-лист из 50 пунктов – от регистрации до первых продаж</li>
        </ul>
        <p style="font-size:14px; color:#a0aec0; margin-bottom:16px;">
            <strong>Как получить:</strong> оплатить -> написать мне в MAX для созвона -> я дорабатываю план -> вы скачиваете готовый документ.
        </p>
        <a href="{payment_link_2500}" class="btn-primary" style="display:block; text-align:center; padding:14px 24px; font-size:17px; border-radius:48px; text-decoration:none; color:#0F1331; background:#28E0C6;" onclick="ym(108348240,'reachGoal','choose_paid'); return true;">
            Оплатить 2 500 ₽
        </a>
    </div>

    <!-- Вариант 3: Клиенты под ключ (усиленная гарантия) -->
    <div style="background:rgba(26,29,58,0.6); border-radius:20px; padding:24px; margin-bottom:16px; border:1px solid #FF6B6B;">
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
            <span style="font-size:28px;">🚀</span>
            <h2 style="font-size:22px; font-weight:600; margin:0;color:#fff;">Я дорабатываю и внедряю</h2>
        </div>
        <p style="font-size:15px; color:#a0aec0; margin-bottom:12px; line-height:1.5;">
            Вы получаете всё из расширенного плана, плюс я лично внедряю систему:
        </p>
        <ul style="text-align:left; font-size:15px; padding-left:20px; margin-bottom:16px;color:#a0aec0;">
            <li>Аудит вашего текущего маркетинга и воронки</li>
            <li>Настройка воронки и запуск рекламы (Яндекс.Директ, соцсети)</li>
            <li>Написание скриптов под вашу команду</li>
            <li>Еженедельные отчёты и корректировка стратегии</li>
        </ul>
        <p style="font-size:15px; color:#fff; margin-bottom:8px;">
            <strong>Результат:</strong> через 14 дней – минимум одна целевая заявка или консультация.
        </p>
        <p style="font-size:15px; color:#fff; margin-bottom:16px;">
            <strong>Гарантия:</strong> если за 14 дней не будет ни одной заявки – я <strong style="color:#28E0C6;">возвращаю деньги</strong> или продолжаю работу до первого клиента бесплатно (на ваш выбор).
        </p>
        <p style="font-size:14px; color:#a0aec0; margin-bottom:16px;">
            <strong>Как начать:</strong> оплатить -> написать мне в MAX с пометкой «Клиенты под ключ» и удобным временем для созвона.
        </p>
        <a href="{payment_link_14900}" class="btn-primary" style="display:block; text-align:center; padding:14px 24px; font-size:17px; border-radius:48px; text-decoration:none; color:#0F1331; background:#FF6B6B;" onclick="ym(108348240,'reachGoal','choose_pro'); return true;">
            Оплатить 14 900 ₽
        </a>
    </div>

    <p style="font-size:14px; color:#a0aec0; text-align:center; margin-top:24px;">
        Есть вопросы? <a href="{channel_link}" target="_blank" style="color:#28E0C6; text-decoration:none;">Напишите мне в MAX</a>
    </p>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === СТРАНИЦА ОПЛАТЫ (стиль обновлён, текст тот же) ===
@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str, amount: int = 2500):
    if amount not in (2500, 14900):
        return RedirectResponse(url=f"/payment?user_id={user_id}&amount=2500", status_code=303)
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    phone_value = row[0] if row and row[0] else ""
    
    if amount == 2500:
        title = "Расширенный план – 2 500 ₽"
        description = "Вы получаете готовую структуру от AI-аналитика. После оплаты мы созваниваемся, я дорабатываю план под ваш конкретный случай, и вы получаете готовый документ со скриптами, бюджетами, контент-планом и чек-листом."
        button_text = "Оплатить 2 500 ₽"
    else:  # 14900
        title = "Внедрение под ключ – 14 900 ₽"
        description = "Вы получаете всё из расширенного плана, плюс я лично внедряю систему: аудит, настройка воронки, запуск рекламы, скрипты, отчёты. Гарантия: если через 14 дней у вас нет заявок – я возвращаю деньги или работаю до первого клиента бесплатно (на ваш выбор)."
        button_text = "Оплатить 14 900 ₽"
    
    content = f'''
<div style="max-width:600px;margin:0 auto;padding:40px 20px;">
    <h1 style="color:#fff;text-align:center;font-size:32px;">{title}</h1>
    <p style="color:#a0aec0;text-align:center;font-size:18px;margin-bottom:32px;">{description}</p>
    <div style="background:rgba(26,29,58,0.6);border-radius:24px;padding:32px;border:1px solid rgba(40,224,198,0.1);">
        <form action="/create_yookassa_payment" method="post">
            <input type="hidden" name="user_id" value="{user_id}">
            <input type="hidden" name="amount" value="{amount}">
            <div style="margin-bottom:24px;">
                <label style="display:block;margin-bottom:8px;font-weight:500;color:#fff;">Телефон (для чека и связи)</label>
                <input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required style="width:100%;padding:12px;border-radius:8px;border:1px solid rgba(40,224,198,0.2);background:rgba(255,255,255,0.05);color:#fff;font-size:16px;" value="{phone_value}">
                <p style="font-size:12px;color:#a0aec0;margin-top:6px;">Никаких рассылок и звонков без вашего согласия.</p>
            </div>
            <div style="margin-bottom:24px;">
                <label style="display:flex;align-items:center;gap:8px;">
                    <input type="checkbox" name="consent" required style="width:20px;height:20px;accent-color:#28E0C6;">
                    <span style="font-size:14px;color:#a0aec0;">Я принимаю условия <a href="/oferta" target="_blank" style="color:#28E0C6;">публичной оферты</a> и даю согласие на обработку персональных данных</span>
                </label>
            </div>
            <button type="submit" class="btn-primary" style="width:100%;padding:16px;font-size:18px;border:none;border-radius:48px;cursor:pointer;" onclick="ym(108348240,'reachGoal','pay_click'); return true;">{button_text}</button>
            <p style="font-size:12px;text-align:center;margin-top:12px;color:#a0aec0;">Безопасная оплата через ЮKassa. Гарантия возврата 3 дня.</p>
        </form>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === СОЗДАНИЕ ПЛАТЕЖА (без изменений) ===
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
        return RedirectResponse(url=f"/payment?user_id={user_id}&amount={amount}", status_code=303)
    
    if amount == 2500:
        description = "Расширенный маркетинговый план + консультация"
    elif amount == 14900:
        description = "Внедрение под ключ: клиенты за 14 дней"
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

# === ВЕБХУК ===
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
                amount = 2500
        else:
            amount = 2500
        logger.info(f"Webhook parsed: event={event}, payment_id={payment_id}, status={status}, user_id={user_id}, amount={amount}")
        if event == "payment.succeeded" and status == "succeeded":
            update_payment_status(payment_id, "succeeded")
            if user_id:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE reports SET paid_at = CURRENT_TIMESTAMP WHERE user_id = ? AND report_type = 'premium'", (user_id,))
                conn.commit()
                conn.close()
                logger.info(f"Updated paid_at for user {user_id} after payment")
        return JSONResponse(content={"status": "ok"})
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return JSONResponse(content={"status": "error"}, status_code=500)

# === ПОДТВЕРЖДЕНИЕ ОПЛАТЫ ===
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
            amount = payment_info["amount"] if payment_info["amount"] is not None else 2500
            logger.info(f"Payment confirm: redirect via payment_id for user {user_id} amount {amount}")
            return RedirectResponse(url=f"/payment/success?user_id={user_id}&amount={amount}", status_code=303)
    if user_id:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT amount FROM payments WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        conn.close()
        if row:
            amount = row[0] if row[0] is not None else 2500
            logger.info(f"Payment confirm: redirecting to success for user {user_id} with amount {amount}")
            return RedirectResponse(url=f"/payment/success?user_id={user_id}&amount={amount}", status_code=303)
        else:
            logger.warning(f"Payment confirm: no payments found for user {user_id}")
    else:
        logger.warning("Payment confirm: neither payment_id nor user_id provided")
    return HTMLResponse(content="""<!DOCTYPE html><html><head><title>Подтверждение оплаты</title><style>body{font-family:sans-serif;text-align:center;padding:50px}.btn{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;border-radius:12px}</style></head><body><h1>Оплата прошла успешно!</h1><p>Вернитесь на сайт, чтобы завершить оформление</p><a href="/" class="btn">На главную</a></body></html>""", status_code=200)

# === СТРАНИЦА УСПЕХА ===
@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str, amount: int = 2500):
    logger.info(f"Payment success page for user {user_id}, amount={amount}")
    conn = sqlite3.connect(DB_PATH)
    payment_row = conn.execute("SELECT status, amount FROM payments WHERE user_id = ? AND status = 'succeeded' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not payment_row:
        return RedirectResponse(url="/", status_code=303)
    if payment_row[1] and payment_row[1] != amount:
        amount = payment_row[1]
        logger.info(f"Fixed amount from payment: {amount} for user {user_id}")

    report = get_report(user_id, "premium")

    if amount == 2500:
        title = "Оплата прошла."
        instruction = "Напишите мне в MAX с пометкой «Консультация 2500» и предложите 2–3 удобных времени для созвона. Я отвечу в течение суток, мы обсудим детали, и я доработаю план под вас."
        download_text = "Ваш расширенный план будет доступен после доработки."
        download_button = ""
    else:  # 14900
        title = "Оплата принята."
        instruction = "Перейдите в мой личный чат MAX и отправьте: название бизнеса, ссылку на сайт/аккаунт, три временных слота для созвона (ближайшие 48 часов). Я подготовлю гипотезы, мы созвонимся, я доработаю план и начну внедрение."
        download_text = "Ваш расширенный план будет доступен после доработки."
        download_button = ""

    guarantee_block = ""
    if amount == 14900:
        guarantee_block = """
    <hr style="margin:32px 0;border-color:rgba(40,224,198,0.2);">
    <div style="background:rgba(255,107,107,0.1); border-radius:16px; padding:16px; border:1px solid #FF6B6B;">
        <p style="font-size:15px;color:#fff;"><strong>Гарантия для тарифа "Внедрение под ключ":</strong> если через 14 дней у вас не будет ни одной новой заявки – я <strong>возвращаю деньги</strong> или продолжаю работу до первого клиента бесплатно (на ваш выбор).</p>
    </div>
    """

    html_content = f'''
<div style="max-width:600px;margin:0 auto;padding:40px 20px;">
    <h1 style="color:#fff;text-align:center;">✅ {title}</h1>
    <p style="color:#a0aec0;text-align:center;font-size:18px;">{instruction}</p>
    <div style="background:rgba(26,29,58,0.6);border-radius:24px;padding:32px;border:1px solid rgba(40,224,198,0.1);text-align:center;">
        <div style="background:rgba(40,224,198,0.05);border-radius:16px;padding:20px;margin:20px 0;">
            <p style="font-size:16px;color:#a0aec0;">{download_text}</p>
            {download_button}
        </div>
        {guarantee_block}
        <hr style="margin:32px 0;border-color:rgba(40,224,198,0.2);">
        <a href="/" class="btn-outline" style="display:inline-block;padding:12px 32px;border-radius:48px;border:1px solid #28E0C6;color:#28E0C6;text-decoration:none;">На главную</a>
        <hr style="margin:32px 0;border-color:rgba(40,224,198,0.2);">
        <div style="background:rgba(26,29,58,0.6); border-radius:24px; padding:24px; text-align:center;">
            <h3 style="font-size:22px; margin-bottom:12px;color:#fff;">🎁 Бесплатный разбор плана от продюсера</h3>
            <p style="font-size:16px; color:#a0aec0; margin-bottom:8px;">
                Вы купили план. Теперь я лично проверю его за 0 рублей, но только если у вас есть бюджет на внедрение.
            </p>
            <a href="/consultation?user_id={user_id}" class="btn-primary" style="display:inline-block;padding:12px 32px;border-radius:48px;text-decoration:none;color:#0F1331;background:#28E0C6;" onclick="ym(108348240,'reachGoal','free_review_click'); return true;">
                Записаться на бесплатный разбор
            </a>
        </div>
        <div style="background:rgba(40,224,198,0.05);border-radius:20px;padding:20px;margin-top:20px;">
            <p style="font-size:14px;color:#a0aec0;">Если у вас возникли вопросы, напишите мне в личный чат MAX: <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank" style="color:#28E0C6;">открыть чат</a></p>
        </div>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(html_content))

# === НОВЫЙ ЭНДПОИНТ ДЛЯ ГЕНЕРАЦИИ ПО ЗАПРОСУ ===
@app.post("/generate-premium-report")
async def generate_premium_report(request: Request, user_id: str = Form(...)):
    conn = sqlite3.connect(DB_PATH)
    payment = conn.execute("SELECT id FROM payments WHERE user_id = ? AND status = 'succeeded' LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not payment:
        raise HTTPException(status_code=403, detail="Оплата не найдена")
    
    existing = get_report(user_id, "premium")
    if existing and existing["status"] == "ready":
        return {"ready": True, "url": f"/download/{user_id}/premium"}
    if existing and existing["status"] == "generating":
        return {"status": "generating"}
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'premium', 'generating')", (user_id,))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    biz = get_business_data(user_id)
    answers = get_form_data(user_id)
    if biz and answers and DEEPSEEK_API_KEY:
        asyncio.create_task(generate_premium_report_background(user_id, biz["name"], biz["description"], answers, report_id))
        return {"status": "generating"}
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE reports SET status = 'failed' WHERE id = ?", (report_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Недостаточно данных для генерации")

# === СТРАНИЦА КОНСУЛЬТАЦИИ ===
@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str = None):
    if not user_id:
        user_id = str(uuid.uuid4())
        save_user(user_id, None, None)
    content = f'''
<div style="max-width:700px;margin:0 auto;padding:40px 20px;">
    <h1 style="color:#fff;font-size:36px;text-align:center;">Разговор по делу – 20 минут</h1>
    <p style="color:#a0aec0;font-size:18px;text-align:center;max-width:700px;margin:0 auto;">
        Если есть вопросы по плану, по сотрудничеству или вы хотите уточнить детали – напишите мне в MAX с пометкой «Консультация».
        Укажите ваш вопрос и три удобных времени для звонка (завтра/послезавтра).
    </p>
    <p style="color:#a0aec0;font-size:15px;text-align:center;margin-top:10px;">
        Условие: я провожу такие разговоры только с теми, кто имеет бюджет на внедрение от 50 000 ₽.
    </p>
    <div style="background:rgba(26,29,58,0.6);border-radius:24px;padding:32px;border:1px solid rgba(40,224,198,0.1);max-width:600px;margin:32px auto;text-align:center;">
        <div style="background:rgba(255,255,255,0.02);border-radius:16px;padding:20px;margin-bottom:24px;text-align:left;">
            <p style="font-size:16px;line-height:1.5;color:#a0aec0;margin:0;">
                <strong style="color:#fff;">Что вы получите за 20 минут:</strong><br>
                - Честный разбор – где план работает, а где требует доработки<br>
                - Ответ, какой канал даст вам первых клиентов уже на следующей неделе<br>
                - Конкретные шаги по внедрению, которые не требуют команды<br>
                - Чек-лист готовности – чтобы не тратить время на неважное
            </p>
        </div>
        <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank" class="btn-primary" style="display:inline-block;padding:16px 32px;border-radius:48px;text-decoration:none;color:#0F1331;background:#28E0C6;" onclick="ym(108348240,'reachGoal','consultation_click'); return true;">
            Написать в личный чат MAX
        </a>
        <p style="font-size:14px;color:#a0aec0;margin-top:10px;">
            Напишите цифру <strong>1</strong> в чат – и я вышлю вам разбор.
        </p>
        <div style="margin-top:30px;">
            <a href="/" class="btn-outline" style="display:inline-block;padding:12px 32px;border-radius:48px;border:1px solid #28E0C6;color:#28E0C6;text-decoration:none;">На главную</a>
        </div>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === СТРАНИЦА ВНЕДРЕНИЯ ПОД КЛЮЧ ===
@app.get("/implementation", response_class=HTMLResponse)
async def implementation_page(user_id: str = None):
    if not user_id:
        user_id = str(uuid.uuid4())
        save_user(user_id, None, None)
    content = f'''
<div style="max-width:700px;margin:0 auto;padding:40px 20px;">
    <h1 style="color:#fff;text-align:center;">Внедрение под ключ – ваш бизнес с системой за 14 дней</h1>
    <p style="color:#a0aec0;text-align:center;font-size:20px;">Я лично настрою воронку, чат-бота и скрипты. Вы получаете не просто отчёт, а работающий механизм.</p>
    <div style="background:rgba(26,29,58,0.6);border-radius:24px;padding:32px;border:1px solid rgba(40,224,198,0.1);">
        <h3 style="color:#fff;">Что входит:</h3>
        <ul style="list-style:none;padding:0;color:#a0aec0;">
            <li style="margin:10px 0;">✅ Аудит текущего маркетинга и воронки</li>
            <li style="margin:10px 0;">✅ Настройка автоворонки в MAX (Telegram, VK, GetCourse)</li>
            <li style="margin:10px 0;">✅ Готовые скрипты продаж и возражений</li>
            <li style="margin:10px 0;">✅ 2 недели поддержки в чате</li>
            <li style="margin:10px 0;">✅ 1 час личной стратегической сессии</li>
        </ul>
        <div style="background:rgba(40,224,198,0.1); border-radius:16px; padding:16px; margin:24px 0;">
            <p style="font-size:18px; font-weight:600; text-align:center;color:#28E0C6;">Цена: от 15 000 ₽</p>
            <p style="font-size:14px; text-align:center; color:#a0aec0;">Индивидуальный расчёт после созвона</p>
        </div>
        <div style="background:rgba(255,107,107,0.1); border-radius:16px; padding:16px; margin-bottom:24px;border:1px solid #FF6B6B;">
            <p style="font-size:14px; margin:0;color:#a0aec0;">Гарантия: если через месяц система не даст первых продаж – я бесплатно доработаю план.</p>
        </div>
        <div style="text-align:center;">
            <a href="/consultation?user_id={user_id}" class="btn-primary" style="display:inline-block;padding:12px 32px;border-radius:48px;text-decoration:none;color:#0F1331;background:#28E0C6;">Записаться на внедрение</a>
        </div>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === ЧЕК-СТАТУС ОТЧЁТА ===
@app.get("/check-premium-status")
async def check_premium_status(user_id: str):
    report = get_report(user_id, "premium")
    if report and report["status"] == "ready":
        return {"ready": True, "url": f"/download/{user_id}/premium"}
    return {"ready": False}

@app.get("/check_status")
async def check_status(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    return {"ready": row and row[0] == 'ready'}

# === СКАЧИВАНИЕ ОТЧЁТА ===
@app.get("/download/{user_id}/{report_type}")
async def download_report(request: Request, user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT file_path, report_text FROM reports WHERE user_id = ? AND report_type = ? ORDER BY id DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    base_url = str(request.base_url).rstrip('/')
    return_link = f"\n\n---\nВернуться на страницу плана: {base_url}/payment/success?user_id={user_id}"
    
    if row and row[0] and os.path.exists(row[0]):
        with open(row[0], "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content=content + return_link, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={report_type}_{user_id}.txt"})
    if row and row[1]:
        return Response(content=row[1] + return_link, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={report_type}_{user_id}.txt"})
    raise HTTPException(status_code=404, detail="Report not found")

# === АДМИН-ДАШБОРД ===
@app.get("/admin/logs")
async def admin_logs(auth: bool = Depends(verify_admin)):
    try:
        with open(LOGS_DIR / "salesplan.log", "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]
            return Response(content="".join(lines), media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/dashboard")
async def admin_dashboard(auth: bool = Depends(verify_admin)):
    dashboard_html = """<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Админ-дашборд | Salesplan</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>
        *{margin:0;padding:0;box-sizing:border-box} body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0F1331;color:#fff;padding:20px}
        .container{max-width:1400px;margin:0 auto} h1{font-size:28px;margin-bottom:20px;color:#28E0C6}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
        .stat-card{background:rgba(26,29,58,0.6);border-radius:16px;padding:20px;border:1px solid rgba(40,224,198,0.1)}
        .stat-card h3{font-size:14px;color:#a0aec0;margin-bottom:8px}
        .stat-card .value{font-size:32px;font-weight:700;color:#28E0C6}
        .stat-card .trend{font-size:12px;color:#34c759;margin-top:8px}
        .chart-container{background:rgba(26,29,58,0.6);border-radius:16px;padding:20px;margin-bottom:30px;border:1px solid rgba(40,224,198,0.1)} canvas{max-height:350px}
        .funnel-container{background:rgba(26,29,58,0.6);border-radius:16px;padding:20px;margin-bottom:30px;border:1px solid rgba(40,224,198,0.1)}
        .funnel-step{display:flex;align-items:center;margin:15px 0;padding:15px;background:rgba(255,255,255,0.03);border-radius:12px}
        .funnel-step .step-name{width:200px;font-weight:600;color:#fff}
        .funnel-step .step-count{width:100px;font-size:24px;font-weight:700;color:#28E0C6}
        .funnel-step .step-bar{flex:1;height:30px;background:rgba(255,255,255,0.05);border-radius:15px;overflow:hidden}
        .funnel-step .step-fill{height:100%;background:#28E0C6;border-radius:15px;display:flex;align-items:center;justify-content:flex-end;padding-right:10px;color:#0F1331;font-size:12px;font-weight:700}
        .tabs{display:flex;gap:10px;margin-bottom:20px;border-bottom:1px solid rgba(40,224,198,0.1);flex-wrap:wrap}
        .tab{padding:12px 24px;cursor:pointer;border:none;background:none;font-size:16px;transition:all 0.2s;color:#a0aec0}
        .tab.active{border-bottom:2px solid #28E0C6;color:#28E0C6;font-weight:500}
        .table-container{background:rgba(26,29,58,0.6);border-radius:16px;padding:20px;overflow-x:auto;border:1px solid rgba(40,224,198,0.1)} table{width:100%;border-collapse:collapse;color:#fff}
        th,td{padding:12px;text-align:left;border-bottom:1px solid rgba(40,224,198,0.05)} th{background:rgba(40,224,198,0.05);font-weight:600;color:#28E0C6}
        .badge{display:inline-block;padding:4px 8px;border-radius:12px;font-size:12px}
        .badge-success{background:rgba(40,224,198,0.2);color:#28E0C6} .badge-pending{background:rgba(255,159,10,0.2);color:#ff9f0a}
        .report-link{color:#28E0C6;text-decoration:none} .expand-btn{cursor:pointer;color:#28E0C6;font-size:12px}
        .row-detail{display:none;background:rgba(255,255,255,0.02)} .row-detail td{padding:20px}
        .detail-section{margin-bottom:15px} .detail-section strong{display:block;margin-bottom:5px;color:#fff}
        .detail-answers{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
        .answer-tag{background:rgba(40,224,198,0.1);padding:4px 12px;border-radius:20px;font-size:12px;color:#a0aec0}
        @media (max-width:700px){.funnel-step{flex-wrap:wrap}.funnel-step .step-name{width:100%;margin-bottom:10px}.stats-grid{grid-template-columns:repeat(2,1fr)}}
    </style></head>
<body><div class="container">
<h1>📊 Воронка продаж — Salesplan</h1>
<div class="stats-grid" id="statsGrid">
    <div class="stat-card"><h3>Уникальных посетителей</h3><div class="value" id="totalVisitors">-</div></div>
    <div class="stat-card"><h3>Бесплатных диагностик</h3><div class="value" id="totalDiagnostics">-</div><div class="trend" id="convVisitToDiag">-</div></div>
    <div class="stat-card"><h3>Оплатили план</h3><div class="value" id="totalPayments">-</div><div class="trend" id="convDiagToPayment">-</div></div>
    <div class="stat-card"><h3>Скачали отчет</h3><div class="value" id="totalDownloads">-</div></div>
    <div class="stat-card"><h3>Выручка</h3><div class="value" id="totalRevenue">-</div></div>
</div>
<div class="funnel-container"><h3>Воронка продаж (за 7 дней)</h3><div id="funnelSteps"></div></div>
<div class="chart-container"><canvas id="funnelChart"></canvas></div>
<div class="tabs"><button class="tab active" onclick="showTab('clients')">Оплатившие клиенты</button><button class="tab" onclick="showTab('diagnostics')">Бесплатные диагностики</button></div>
<div id="clientsTab" class="table-container"><h3>Клиенты, оплатившие премиум-план</h3><table id="clientsTable"><thead><tr><th>Дата</th><th>Телефон</th><th>Бизнес</th><th>Анкета</th><th>Отчет</th><th></th></tr></thead><tbody></tbody></table></div>
<div id="diagnosticsTab" class="table-container" style="display:none"><h3>Бесплатные диагностики</h3><table id="diagnosticsTable"><thead><tr><th>Дата</th><th>Телефон</th><th>Бизнес</th><th>Анкета</th><th>Статус</th><th></th></tr></thead><tbody></tbody></table></div>
</div>
<script>
let clientsData=[];
async function loadStats(){const res=await fetch('/admin/api/stats');const data=await res.json();
document.getElementById('totalVisitors').innerText=data.summary.visitors;
document.getElementById('totalDiagnostics').innerText=data.summary.diagnostics;
document.getElementById('totalPayments').innerText=data.summary.payments;
document.getElementById('totalDownloads').innerText=data.summary.downloads;
document.getElementById('totalRevenue').innerText=data.summary.total_revenue.toLocaleString()+' ₽';
document.getElementById('convVisitToDiag').innerHTML=`Конверсия: ${data.summary.conv_visit_to_diag}%`;
document.getElementById('convDiagToPayment').innerHTML=`Конверсия: ${data.summary.conv_diag_to_payment}%`;
const funnelDiv=document.getElementById('funnelSteps');
const steps=[[{name:'Посетители сайта',key:'visitors',color:'#28E0C6'},{name:'Бесплатная диагностика',key:'diagnostics',color:'#28E0C6'},{name:'Оплата плана',key:'payments',color:'#FF6B6B'},{name:'Скачивание отчета',key:'downloads',color:'#28E0C6'}]];
const maxCount=Math.max(data.summary.visitors,1);
funnelDiv.innerHTML=steps[0].map(step=>{const count=data.summary[step.key];const percent=(count/maxCount*100).toFixed(1);return `<div class="funnel-step"><div class="step-name">${step.name}</div><div class="step-count">${count}</div><div class="step-bar"><div class="step-fill" style="width:${percent}%;background:${step.color}">${percent}%</div></div></div>`;}).join('');
const ctx=document.getElementById('funnelChart').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:data.funnel.map(d=>d.date),datasets:[{label:'Посетители',data:data.funnel.map(d=>d.visitors),borderColor:'#28E0C6',backgroundColor:'rgba(40,224,198,0.1)',tension:0.3,fill:true},{label:'Диагностики',data:data.funnel.map(d=>d.diagnostics),borderColor:'#28E0C6',backgroundColor:'rgba(40,224,198,0.1)',tension:0.3,fill:true},{label:'Оплаты',data:data.funnel.map(d=>d.payments),borderColor:'#FF6B6B',backgroundColor:'rgba(255,107,107,0.1)',tension:0.3,fill:true},{label:'Скачивания',data:data.funnel.map(d=>d.downloads),borderColor:'#28E0C6',backgroundColor:'rgba(40,224,198,0.1)',tension:0.3,fill:true}]},options:{responsive:true,maintainAspectRatio:true}});}
async function loadClients(){const res=await fetch('/admin/api/clients');const data=await res.json();clientsData=data.clients;const tbody=document.querySelector('#clientsTable tbody');tbody.innerHTML='';
data.clients.forEach(client=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(client.payment_date).toLocaleDateString()}</td><td>${client.phone||'-'}</td><td><strong>${client.business_name||'-'}</strong><br><small style="color:#a0aec0;">${(client.business_description||'').substring(0,50)}...</small></td><td><span class="expand-btn" onclick="showAnswers(${JSON.stringify(client).replace(/"/g,'&quot;')})">Показать анкету</span></td><td>${client.report_path?'<a href="/download/'+client.user_id+'/premium" class="report-link">Скачать отчет</a>':'<span class="badge badge-pending">генерация...</span>'}</td><td><span class="expand-btn" onclick="toggleDetail(this)">Подробнее</span></td>`;const detailRow=tbody.insertRow();detailRow.className='row-detail';detailRow.style.display='none';detailRow.innerHTML=`<td colspan="6"><div class="detail-section"><strong>Полная анкета:</strong><div class="detail-answers"><span class="answer-tag">Продаёт: ${client.q1||'-'}</span><span class="answer-tag">Чек: ${client.q2||'-'}</span><span class="answer-tag">Клиентов: ${client.q3||'-'}</span><span class="answer-tag">Цель: ${client.q4||'-'}</span><span class="answer-tag">Воронка: ${client.q5||'-'}</span></div></div><div class="detail-section"><strong>Описание бизнеса:</strong><br>${client.business_description||'-'}</div>`;});}
async function loadDiagnostics(){const res=await fetch('/admin/api/diagnostics');const data=await res.json();const tbody=document.querySelector('#diagnosticsTable tbody');tbody.innerHTML='';data.diagnostics.forEach(d=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(d.date).toLocaleString()}</td><td>${d.phone||'-'}</td><td><strong>${d.business_name||'-'}</strong><br><small style="color:#a0aec0;">${(d.business_description||'').substring(0,50)}...</small></td><td><span class="expand-btn" onclick="showAnswersDialog('${d.q1}','${d.q2}','${d.q3}','${d.q4}','${d.q5}')">Показать</span></td><td><span class="badge ${d.report_status==='ready'?'badge-success':'badge-pending'}">${d.report_status==='ready'?'Готов':'Генерация'}</span></td><td>${d.report_status==='ready'?'<a href="/download/'+d.user_id+'/free" class="report-link">Скачать</a>':'-'}<tr>`;});}
function toggleDetail(btn){const row=btn.closest('tr');const detailRow=row.nextElementSibling;if(detailRow&&detailRow.classList.contains('row-detail')){const isHidden=detailRow.style.display==='none';detailRow.style.display=isHidden?'table-row':'none';btn.innerText=isHidden?'Скрыть':'Подробнее';}}
function showAnswers(client){alert(`АНКЕТА КЛИЕНТА\n\nПродаёт: ${client.q1||'-'}\nСредний чек: ${client.q2||'-'}\nКлиентов/мес: ${client.q3||'-'}\nЦель: ${client.q4||'-'}\nАвтоворонка: ${client.q5||'-'}`);}
function showAnswersDialog(q1,q2,q3,q4,q5){alert(`АНКЕТА\n\nПродаёт: ${q1||'-'}\nСредний чек: ${q2||'-'}\nКлиентов/мес: ${q3||'-'}\nЦель: ${q4||'-'}\nАвтоворонка: ${q5||'-'}`);}
function showTab(tab){document.getElementById('clientsTab').style.display=tab==='clients'?'block':'none';document.getElementById('diagnosticsTab').style.display=tab==='diagnostics'?'block':'none';document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));event.target.classList.add('active');}
loadStats();loadClients();loadDiagnostics();setInterval(()=>{loadStats();loadClients();loadDiagnostics();},30000);
</script>
</body>
</html>"""
    return HTMLResponse(content=dashboard_html)

# === API ДЛЯ АДМИНКИ ===
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

# === СТАРЫЕ СТРАНИЦЫ (редиректы) ===
@app.get("/diagnostic")
async def diagnostic_redirect():
    return RedirectResponse(url="/", status_code=301)

@app.get("/launch-online-school")
async def launch_online_school_redirect():
    return RedirectResponse(url="/", status_code=301)

@app.get("/funnel-7-days")
async def funnel_7_days_redirect():
    return RedirectResponse(url="/", status_code=301)

# === СТРАНИЦЫ ОФЕРТЫ И ПОЛИТИКИ ===
@app.get("/oferta", response_class=HTMLResponse)
async def oferta_page():
    content = """
<div style="max-width:800px;margin:0 auto;padding:40px 20px;">
    <h1 style="color:#28E0C6;">Публичная оферта</h1>
    <p style="color:#a0aec0;">о заключении договора купли-продажи цифрового товара</p>
    <div style="background:rgba(26,29,58,0.6);border-radius:16px;padding:24px;margin-top:20px;color:#a0aec0;">
        <p><strong style="color:#fff;">Индивидуальный предприниматель Макаревич Вероника Александровна,</strong><br>
        ИНН 781407988795, зарегистрированная в качестве налогоплательщика,<br>
        размещая настоящий документ на сайте, предлагает заключить договор купли-продажи цифрового товара.</p>
        <p>Дата публикации: «05» мая 2026 г.</p>
    </div>
</div>
"""
    return HTMLResponse(content=render_page(content))

@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    content = """
<div style="max-width:800px;margin:0 auto;padding:40px 20px;">
    <h1 style="color:#28E0C6;">Политика обработки персональных данных</h1>
    <p style="color:#a0aec0;">Индивидуального предпринимателя Макаревич Вероники Александровны</p>
    <div style="background:rgba(26,29,58,0.6);border-radius:16px;padding:24px;margin-top:20px;color:#a0aec0;">
        <p><strong style="color:#fff;">ИНН:</strong> 781407988795</p>
        <p><strong style="color:#fff;">Email:</strong> veranikamakarevich@yandex.ru</p>
        <p><strong style="color:#fff;">Дата публикации:</strong> «05» мая 2026 г.</p>
    </div>
</div>
"""
    return HTMLResponse(content=render_page(content))

# === ЗАПУСК ===
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
