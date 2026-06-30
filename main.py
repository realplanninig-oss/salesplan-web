# File: main.py — веб-приложение Salesplan (финальная версия)
# Все согласованные изменения:
# - Главная без кейсов, с прогревающим текстом и компактной ссылкой MAX
# - Кейсы перенесены на страницу оплаты
# - Трёхступенчатая воронка: лид-магнит → бесплатный план → апсейл на расширенный план за 2500 ₽
# - Генерация расширенного плана только после оплаты и по запросу пользователя
# - Все приглашения на консультацию заменены на ссылку в MAX
# - Админ-дашборд с телефонами в диагностиках, вкладка консультаций удалена

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
    if path in ["/", "/survey", "/payment", "/payment/success", "/thank-you", "/lead-magnet", "/consultation", "/generate-premium-report"]:
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

# === ОТПРАВКА УВЕДОМЛЕНИЙ В КАНАЛ MAX (для администратора) ===
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
    # Новый промпт для расширенного плана (с инструментами)
    prompt = f"""Сделай расширенный маркетинговый план для бизнеса.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
Продаёт: {answers.get('q1', 'не указано')}
Средний чек: {answers.get('q2', 'не указано')}
Клиентов/мес: {answers.get('q3', 'не указано')}
Цель: {answers.get('q4', 'не указано')}
Автоворонка: {answers.get('q5', 'не указано')}

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

5. РЕКЛАМНЫЕ КАНАЛЫ (5 каналов)
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

# === ГЛОБАЛЬНЫЕ HTML ШАБЛОНЫ И CSS ===
HTML_HEAD = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Бесплатный ИИ-план для вашего бизнеса | Продюсер экспертов</title>
    <meta name="description" content="Получите маркетинговый план под вашу нишу от ИИ за 2 минуты. Бесплатно. Без спама.">
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
        .radio-group label{display:flex;align-items:center;gap:8px;font-weight:normal;cursor:pointer;padding:8px 12px;background:#f5f5f7;border-radius:12px;transition:background 0.2s}
        .radio-group label:hover{background:#e5e5ea}
        .radio-group input[type="radio"]{width:20px;height:20px;margin:0;cursor:pointer}
        @media (max-width:700px){
            .container{padding:20px 16px}
            .hero h1{font-size:32px}
            .hero p{font-size:18px}
            .btn-main{padding:12px 24px;font-size:18px}
            .benefits-grid{gap:20px}
            .benefit-item{min-width:140px}
            .cases-grid{grid-template-columns:repeat(2,1fr)}
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
            <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank">💬 Написать в MAX</a>
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

# === ВСПОМОГАТЕЛЬНЫЕ СТРАНИЦЫ ОЖИДАНИЯ ===
def render_waiting_page(user_id: str, report_type: str, redirect_url: str):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Генерируем план</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;text-align:center;padding:60px 20px;background:#fff;color:#1d1d1f}}.spinner{{width:50px;height:50px;border:4px solid #e5e5e5;border-top-color:#007aff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
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
<body><div class="spinner"></div><h1>⏳ Генерируем ваш план...</h1><p>Это займёт 1-2 минуты. Страница обновится сама.</p></body>
</html>"""

# === ГЛАВНАЯ СТРАНИЦА (без кейсов) ===
@app.get("/")
async def index():
    content = '''
<div class="hero">
    <h1>Хватит гадать. Получите маркетинговый план под вашу нишу – бесплатно.</h1>
    <p style="font-size:20px; max-width:700px; margin:0 auto 20px;">ИИ проанализирует вашу нишу, конкурентов и аудиторию. За 2 минуты вы узнаете, где теряете деньги и с чего начать.</p>
    
    <!-- Прогревающий текст -->
    <div style="background:#f8f8fa; border-radius:24px; padding:24px 32px; margin:30px auto; max-width:800px; text-align:left; font-size:17px; line-height:1.6; color:#1d1d1f;">
        <p><strong>Вы – эксперт.</strong> Но маркетинг съедает бюджет, а клиенты уходят к конкурентам.<br>
        Я не верю в волшебные кнопки. Я верю в систему.</p>
        <p>Мы обучили нейросеть на реальных кейсах – она видит вашу нишу изнутри и выдаёт готовый план: каналы, оффер, бюджет, первые шаги.<br>
        Без воды, без общих фраз – только конкретика под ваш бизнес.</p>
        <p><strong>Почему это работает?</strong><br>
        Потому что план строится не на догадках, а на данных – по вашей нише, вашей аудитории, вашим целям.<br>
        Вы получаете не «советы», а дорожную карту, которую можно внедрять уже завтра.</p>
        <p><strong>Что вы узнаете:</strong></p>
        <ul style="list-style:none; padding-left:0;">
            <li style="margin-bottom:8px;">✅ какие 3 канала принесут вам клиентов уже в первую неделю;</li>
            <li style="margin-bottom:8px;">✅ какой оффер заставит сказать «да» даже скептиков;</li>
            <li style="margin-bottom:8px;">✅ сколько денег реально нужно на старте и где их взять;</li>
            <li style="margin-bottom:8px;">✅ какую ошибку вы совершаете каждый день, теряя прибыль.</li>
        </ul>
        <p style="margin-top:16px;">Я не обещаю чудес. Я даю инструмент.<br>
        Дальше – ваш выбор: использовать его или оставить пылиться.</p>
        <p><strong>Первый шаг – пройти диагностику.</strong> Это займёт 2 минуты. Никаких обязательств – только польза.</p>
    </div>
</div>

<div class="benefits-grid">
    <div class="benefit-item"><div class="benefit-icon">🔍</div><div class="benefit-title">Где именно сливаются ваши клиенты</div></div>
    <div class="benefit-item"><div class="benefit-icon">🎯</div><div class="benefit-title">3 точки роста для первых денег</div></div>
    <div class="benefit-item"><div class="benefit-icon">🤖</div><div class="benefit-title">Как настроить автоворонку без программистов</div></div>
</div>

<div style="text-align:center; margin:40px 0;">
    <a href="/survey" class="btn-main" onclick="ym(108348240,'reachGoal','click_lead_magnet'); return true;">🔍 Пройти диагностику</a>
</div>

<!-- Компактный блок с MAX -->
<div style="text-align:center; margin:40px 0 20px; font-size:14px; color:#6e6e73;">
    <span>💬 Есть вопросы? <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank" style="color:#007aff; text-decoration:none;">Напишите мне в MAX</a></span>
</div>
'''
    return HTMLResponse(content=render_page(content))

@app.get("/lead-magnet")
async def lead_magnet():
    return RedirectResponse(url="/", status_code=301)

# === СТРАНИЦА АНКЕТЫ ===
@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<style>
    .form-card{background:#fff;border-radius:24px;padding:32px;box-shadow:0 4px 12px rgba(0,0,0,0.05);max-width:600px;margin:0 auto}
    .form-group{margin-bottom:24px}
    label{font-size:15px;font-weight:500;display:block;margin-bottom:8px}
    input,textarea{width:100%;padding:12px;font-size:15px;border:1px solid #ccc;border-radius:10px;font-family:inherit}
    .radio-group{display:flex;flex-direction:column;gap:12px;margin-top:8px}
    .radio-group label{display:flex;align-items:center;gap:8px;font-weight:normal;cursor:pointer;padding:8px 12px;background:#f5f5f7;border-radius:12px;transition:background 0.2s}
    .radio-group label:hover{background:#e5e5ea}
    .radio-group input[type="radio"]{width:20px;height:20px;margin:0;cursor:pointer}
    .btn-main{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:16px 48px;font-size:20px;font-weight:600;border-radius:48px;box-shadow:0 2px 8px rgba(0,122,255,0.3);transition:transform 0.2s,box-shadow 0.2s;border:none;cursor:pointer}
    .btn-main:hover{background:#005fc5;transform:scale(1.02);box-shadow:0 4px 12px rgba(0,122,255,0.4)}
</style>
<div class="hero">
    <h1>Эксперт, отвечайте честно – я скажу, где вы теряете клиентов.</h1>
    <p style="font-size:18px;">«7 вопросов – и я дам вам персонализированный план роста. 2 минуты – и вы увидите свои точки роста.»</p>
</div>
<div class="form-card">
    <form action="/survey/submit" method="post" id="surveyForm">
        <div class="form-group"><label>1. Название вашего экспертного проекта</label><input type="text" name="business_name" placeholder="например: Продюсирую экспертов" required></div>
        <div class="form-group"><label>2. Чем вы помогаете клиентам? (кратко)</label><textarea name="business_description" rows="3" placeholder="Пример: Воронка: бесплатная диагностика → план запуска → бесплатный разбор плана за подписку" required></textarea></div>
        <div class="form-group"><label>3. Что вы продаёте?</label><div class="radio-group"><label><input type="radio" name="q1" value="Услугу" required> Услугу (консультации, сопровождение)</label><label><input type="radio" name="q1" value="Инфопродукт"> Инфопродукт (курсы, программы)</label><label><input type="radio" name="q1" value="Консультацию"> Консультацию (разовая)</label><label><input type="radio" name="q1" value="Пока не продаю"> Пока не продаю</label></div></div>
        <div class="form-group"><label>4. Средний чек (₽)</label><div class="radio-group"><label><input type="radio" name="q2" value="до 5k" required> до 5k</label><label><input type="radio" name="q2" value="5k-20k"> 5k-20k</label><label><input type="radio" name="q2" value="20k-50k"> 20k-50k</label><label><input type="radio" name="q2" value=">50k"> >50k</label></div></div>
        <div class="form-group"><label>5. Клиентов в месяц (примерно)</label><div class="radio-group"><label><input type="radio" name="q3" value="<10" required> меньше 10</label><label><input type="radio" name="q3" value="10-50"> 10-50</label><label><input type="radio" name="q3" value="50-200"> 50-200</label><label><input type="radio" name="q3" value=">200"> более 200</label></div></div>
        <div class="form-group"><label>6. Цель на 2026 (в деньгах)</label><div class="radio-group"><label><input type="radio" name="q4" value="300k/мес" required> 300k/мес</label><label><input type="radio" name="q4" value="500k/мес"> 500k/мес</label><label><input type="radio" name="q4" value="1M/мес"> 1M/мес</label><label><input type="radio" name="q4" value="Масштаб"> Масштаб (выход на новый уровень)</label></div></div>
        <div class="form-group"><label>7. Уже есть автоворонка?</label><div class="radio-group"><label><input type="radio" name="q5" value="Да" required> Да</label><label><input type="radio" name="q5" value="Нет"> Нет</label><label><input type="radio" name="q5" value="В разработке"> В разработке</label></div></div>
        <div class="form-group">
            <label style="display:flex;align-items:center;gap:8px;">
                <input type="checkbox" name="consent" required style="width:20px;height:20px;">
                <span>Я принимаю условия публичной оферты и даю согласие на обработку персональных данных</span>
            </label>
        </div>
        <div style="text-align:center;margin-top:20px;"><button type="submit" class="btn-main" id="submitBtn" onclick="ym(108348240,'reachGoal','survey_submit'); return true;">Отправить и получить разбор</button></div>
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

# === ОБРАБОТЧИК АНКЕТЫ ===
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
            fallback_text = f"Диагностика для бизнеса \"{business_name}\"\n\nОписание: {business_description}\n\nРекомендации:\n- Проанализируйте целевую аудиторию\n- Настройте воронку продаж\n- Добавьте призывы к действию"
            conn.execute("UPDATE reports SET report_text = ?, status = 'ready', ready_at = CURRENT_TIMESTAMP WHERE id = ?", (fallback_text, report_id))
            logger.warning(f"Free report {report_id} using fallback text")
        conn.commit()
        conn.close()
    asyncio.create_task(generate_and_save())
    return RedirectResponse(url=f"/thank-you?user_id={user_id}", status_code=303)

# === СТРАНИЦА СПАСИБО ===
@app.get("/thank-you", response_class=HTMLResponse)
async def thank_you(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT status, report_text FROM reports WHERE user_id = ? AND report_type = 'free' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    if not row or row[0] != 'ready':
        return HTMLResponse(content=render_waiting_page(user_id, "free", f"/thank-you?user_id={user_id}"))
    
    content = f'''
<div class="hero">
    <h1>🎉 Ваш бесплатный план готов!</h1>
    <p style="font-size:18px;">Скачайте его и начните внедрять уже сегодня.</p>
</div>
<div class="form-card" style="text-align:center;">
    <div style="background:#f5f5f7;border-radius:16px;padding:20px;margin:20px 0;">
        <a href="/download/{user_id}/free" class="btn-main" onclick="ym(108348240,'reachGoal','download_free_plan'); return true;">📥 Скачать план (.txt)</a>
    </div>
    <hr>
    <div style="background:#fff3cd;border-radius:16px;padding:20px;margin:20px 0;">
        <h3>🚀 Хотите углублённую версию?</h3>
        <p style="font-size:14px;">Получите расширенный план с бюджетами, скриптами, воронкой и чек-листом – всего за 2 500 ₽ (вместо 5 000 ₽).</p>
        <a href="/payment?user_id={user_id}&amount=2500" class="btn-main" style="background:#ff9f0a;" onclick="ym(108348240,'reachGoal','upgrade_click'); return true;">🔥 Купить расширенный план</a>
    </div>
    <hr>
    <div style="background:#e8f0fe;border-radius:16px;padding:20px;margin:20px 0;">
        <h3>💬 Остались вопросы?</h3>
        <p>Напишите мне в MAX – я помогу разобраться.</p>
        <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank" class="btn-main" onclick="ym(108348240,'reachGoal','consultation_click'); return true;">💬 Написать в MAX</a>
        <p style="font-size:12px;color:#6e6e73;margin-top:12px;">Я пользуюсь мессенджером MAX. Присоединяйтесь!</p>
    </div>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === СТРАНИЦА ОПЛАТЫ (с кейсами) ===
@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str, amount: int = 2500):
    if amount != 2500:
        return RedirectResponse(url=f"/payment?user_id={user_id}&amount=2500", status_code=303)
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    phone_value = row[0] if row and row[0] else ""
    content = f'''
<div class="hero">
    <h1>Расширенный маркетинговый план – 2 500 ₽</h1>
    <p style="font-size:18px;">«Это не просто текст. Это готовые инструменты, которые экономят вам недели работы.»</p>
</div>
<div class="form-card">
    <div style="background:#f5f5f7;border-radius:16px;padding:20px;margin-bottom:30px;">
        <h3 style="margin-bottom:16px;">Что вы получите:</h3>
        <ul style="list-style:none;padding:0;text-align:left;">
            <li style="margin-bottom:10px;">✅ <strong>Бюджет на рекламу</strong> – сколько тратить на каждый канал, чтобы окупиться за 2 недели</li>
            <li style="margin-bottom:10px;">✅ <strong>Готовая воронка</strong> – 5 этапов с текстами для каждого касания</li>
            <li style="margin-bottom:10px;">✅ <strong>5 скриптов продаж</strong> – для возражений «дорого», «подумаю», «сравню»</li>
            <li style="margin-bottom:10px;">✅ <strong>Контент-план на месяц</strong> – посты, сторис, рассылки (с темами)</li>
            <li style="margin-bottom:10px;">✅ <strong>Чек-лист запуска</strong> – 50 пунктов от регистрации до первой продажи</li>
            <li style="margin-bottom:10px;">✅ <strong>Закрытый канал</strong> – 30 дней поддержки и разборов</li>
        </ul>
    </div>
    <div style="background:#e8f0fe;border-radius:16px;padding:16px;margin-bottom:20px;text-align:center;">
        <p style="font-size:14px;margin:0;">«Я лично проверяю каждый план. Если он не принесёт вам пользу – я верну деньги в течение 3 дней. Без вопросов.»</p>
        <p style="font-size:12px;color:#6e6e73;margin-top:8px;">Вероника Макаревич | Продюсер экспертов, 50+ запусков</p>
    </div>

    <!-- Блок с кейсами (перенесены с главной) -->
    <hr style="margin: 30px 0;">
    <h3 style="text-align:center; margin-bottom:20px; font-size:20px;">🔥 Реальные результаты моих клиентов</h3>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:30px;">
        <div style="background:#f5f5f7; border-radius:16px; padding:16px; text-align:center;">
            <div style="font-size:28px;">🇨🇳</div>
            <div style="font-weight:600; font-size:14px;">Эксперт по китайскому</div>
            <div style="font-size:20px; font-weight:700; color:#34c759;">+120 000 ₽</div>
            <div style="font-size:12px; color:#6e6e73;">за 14 дней без блога</div>
        </div>
        <div style="background:#f5f5f7; border-radius:16px; padding:16px; text-align:center;">
            <div style="font-size:28px;">🎓</div>
            <div style="font-weight:600; font-size:14px;">Психолог Ольга</div>
            <div style="font-size:20px; font-weight:700; color:#34c759;">+187 000 ₽</div>
            <div style="font-size:12px; color:#6e6e73;">с одного вебинара</div>
        </div>
        <div style="background:#f5f5f7; border-radius:16px; padding:16px; text-align:center;">
            <div style="font-size:28px;">🌊</div>
            <div style="font-weight:600; font-size:14px;">Мастер Фен-Шуй</div>
            <div style="font-size:20px; font-weight:700; color:#34c759;">+195 000 ₽</div>
            <div style="font-size:12px; color:#6e6e73;">первый запуск при рекламе 30 000 ₽</div>
        </div>
        <div style="background:#f5f5f7; border-radius:16px; padding:16px; text-align:center;">
            <div style="font-size:28px;">🏫</div>
            <div style="font-weight:600; font-size:14px;">Онлайн-школа коучинга</div>
            <div style="font-size:20px; font-weight:700; color:#34c759;">+2 000 000 ₽</div>
            <div style="font-size:12px; color:#6e6e73;">марафон в ВК за 2 недели</div>
        </div>
    </div>
    <hr style="margin: 20px 0;">

    <form action="/create_yookassa_payment" method="post">
        <input type="hidden" name="user_id" value="{user_id}">
        <input type="hidden" name="amount" value="2500">
        <div class="form-group">
            <label>📞 Телефон (для чека и доступа)</label>
            <input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required style="text-align:center;font-size:18px;" value="{phone_value}">
            <p style="font-size:12px;color:#8e8e93;margin-top:6px;">Спама не будет – только чек и доступ к плану.</p>
        </div>
        <div class="form-group">
            <label style="display:flex;align-items:center;gap:8px;">
                <input type="checkbox" name="consent" required style="width:20px;height:20px;">
                <span>Я принимаю условия <a href="/oferta" target="_blank">публичной оферты</a> и даю согласие на обработку персональных данных</span>
            </label>
        </div>
        <div style="text-align:center;margin-top:20px;">
            <button type="submit" class="btn-main" style="width:100%;" onclick="ym(108348240,'reachGoal','pay_click'); return true;">💳 Оплатить 2 500 ₽</button>
        </div>
        <p style="font-size:12px;text-align:center;margin-top:12px;">✅ Безопасная оплата через ЮKassa. Гарантия возврата 3 дня.</p>
    </form>
</div>
'''
    return HTMLResponse(content=render_page(content))

# === СОЗДАНИЕ ПЛАТЕЖА ===
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
        description = "Расширенный маркетинговый план для эксперта"
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

# === ВЕБХУК (без автоматической генерации) ===
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
    return HTMLResponse(content="""<!DOCTYPE html><html><head><title>Подтверждение оплаты</title><style>body{font-family:sans-serif;text-align:center;padding:50px}.btn{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;border-radius:12px}</style></head><body><h1>✅ Оплата прошла успешно!</h1><p>Вернитесь на сайт, чтобы сгенерировать план</p><a href="/" class="btn">На главную</a></body></html>""", status_code=200)

# === СТРАНИЦА УСПЕХА (с кнопкой генерации) ===
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
    
    html_content = f'''
<div class="hero">
    <h1>🎉 Оплата прошла успешно!</h1>
    <p style="font-size:18px;">Спасибо! Теперь вы можете получить расширенный маркетинговый план.</p>
</div>
<div class="form-card" style="text-align:center;">
    <div id="report-status">
    '''
    if report and report["status"] == "ready":
        html_content += f'''
        <div style="background:#e8f0fe;border-radius:16px;padding:20px;margin:20px 0;">
            <p style="font-size:16px;">✅ Ваш расширенный план готов к скачиванию.</p>
            <a href="/download/{user_id}/premium" class="btn-main" style="display:inline-block;margin-top:10px;" onclick="ym(108348240,'reachGoal','download_premium'); return true;">📥 Скачать план (.txt)</a>
        </div>
        '''
    elif report and report["status"] == "generating":
        html_content += f'''
        <div id="generating-block" style="background:#fff3cd;border-radius:16px;padding:20px;margin:20px 0;">
            <p>⏳ Ваш план генерируется... Это займёт 1-2 минуты.</p>
            <button id="checkStatusBtn" class="btn-main" style="background:#ff9f0a;" onclick="ym(108348240,'reachGoal','check_status'); return true;">Проверить статус</button>
        </div>
        <script>
            document.getElementById('checkStatusBtn').addEventListener('click', function() {{
                fetch('/check-premium-status?user_id={user_id}')
                    .then(res => res.json())
                    .then(data => {{
                        if (data.ready) {{
                            window.location.reload();
                        }} else {{
                            alert('Ещё генерируется, подождите немного.');
                        }}
                    }});
            }});
        </script>
        '''
    else:
        html_content += f'''
        <div style="background:#f5f5f7;border-radius:16px;padding:20px;margin:20px 0;">
            <p style="font-size:16px;">Нажмите кнопку ниже, чтобы начать генерацию вашего расширенного плана.</p>
            <form action="/generate-premium-report" method="post" id="generateForm">
                <input type="hidden" name="user_id" value="{user_id}">
                <button type="submit" class="btn-main" style="margin-top:10px;" onclick="ym(108348240,'reachGoal','generate_click'); return true;">🚀 Сгенерировать план</button>
            </form>
        </div>
        <script>
            document.getElementById('generateForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                const btn = this.querySelector('button[type="submit"]');
                btn.disabled = true;
                btn.textContent = '⏳ Генерируем...';
                fetch(this.action, {{ method: 'POST', body: new FormData(this) }})
                    .then(res => res.json())
                    .then(data => {{
                        if (data.status === 'generating') {{
                            window.location.reload();
                        }} else if (data.ready) {{
                            window.location.href = data.url;
                        }}
                    }})
                    .catch(() => {{
                        btn.disabled = false;
                        btn.textContent = '🚀 Сгенерировать план';
                        alert('Ошибка, попробуйте ещё раз.');
                    }});
            }});
        </script>
        '''
    html_content += '''
    </div>
    <hr style="margin:32px 0;">
    <div style="background:#e8f0fe;border-radius:20px;padding:20px;margin-top:20px;">
        <p style="font-size:14px;">Если у вас возникли вопросы, напишите мне в MAX: <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank">@veranikamakarevich</a></p>
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

# === СТРАНИЦА КОНСУЛЬТАЦИИ (приглашение в MAX) ===
@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str = None):
    if not user_id:
        user_id = str(uuid.uuid4())
        save_user(user_id, None, None)
    content = f'''
<div class="hero" style="margin-bottom:30px;">
    <h1 style="font-size:36px;">💬 Хотите обсудить ваш план лично?</h1>
    <p style="font-size:18px;color:#6e6e73;">Я пользуюсь мессенджером MAX. Напишите мне – я отвечу на все вопросы.</p>
</div>
<div class="form-card" style="text-align:center;max-width:600px;margin:0 auto;">
    <div style="margin:30px 0;">
        <a href="https://max.ru/u/f9LHodD0cOJKjwAZrG-GC6z1VP02b4BrBEFVlrA1G9pu874eZzgdwHZnKV8" target="_blank" class="btn-main" style="width:80%;padding:16px;font-size:18px;" onclick="ym(108348240,'reachGoal','consultation_click'); return true;">
            💬 Написать в MAX
        </a>
    </div>
    <p style="font-size:14px;color:#6e6e73;margin-top:10px;">
        Нажмите на кнопку – откроется чат со мной. Напишите любой вопрос, я отвечу в течение часа (в рабочее время).
    </p>
    <div style="margin-top:30px;">
        <a href="/" class="btn-main" style="background:transparent;color:#007aff;box-shadow:none;">На главную</a>
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
<div class="tabs"><button class="tab active" onclick="showTab('clients')">👥 Оплатившие клиенты</button><button class="tab" onclick="showTab('diagnostics')">📝 Бесплатные диагностики</button></div>
<div id="clientsTab" class="table-container"><h3>💰 Клиенты, оплатившие премиум-план</h3><table id="clientsTable"><thead><tr><th>Дата</th><th>Телефон</th><th>Бизнес</th><th>Анкета</th><th>Отчет</th><th></th></tr></thead><tbody></tbody></table></div>
<div id="diagnosticsTab" class="table-container" style="display:none"><h3>📝 Бесплатные диагностики</h3><table id="diagnosticsTable"><thead><tr><th>Дата</th><th>Телефон</th><th>Бизнес</th><th>Анкета</th><th>Статус</th><th></th></tr></thead><tbody></tbody></table></div>
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
const steps=[[{name:'👥 Посетители сайта',key:'visitors',color:'#007aff'},{name:'📝 Бесплатная диагностика',key:'diagnostics',color:'#5856d6'},{name:'💳 Оплата плана (2500₽)',key:'payments',color:'#ff9f0a'},{name:'📥 Скачивание отчета',key:'downloads',color:'#34c759'}]];
const maxCount=Math.max(data.summary.visitors,1);
funnelDiv.innerHTML=steps[0].map(step=>{const count=data.summary[step.key];const percent=(count/maxCount*100).toFixed(1);return `<div class="funnel-step"><div class="step-name">${step.name}</div><div class="step-count">${count}</div><div class="step-bar"><div class="step-fill" style="width:${percent}%;background:${step.color}">${percent}%</div></div></div>`;}).join('');
const ctx=document.getElementById('funnelChart').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:data.funnel.map(d=>d.date),datasets:[{label:'👥 Посетители',data:data.funnel.map(d=>d.visitors),borderColor:'#007aff',backgroundColor:'#007aff20',tension:0.3,fill:true},{label:'📝 Диагностики',data:data.funnel.map(d=>d.diagnostics),borderColor:'#5856d6',backgroundColor:'#5856d620',tension:0.3,fill:true},{label:'💳 Оплаты',data:data.funnel.map(d=>d.payments),borderColor:'#ff9f0a',backgroundColor:'#ff9f0a20',tension:0.3,fill:true},{label:'📥 Скачивания',data:data.funnel.map(d=>d.downloads),borderColor:'#34c759',backgroundColor:'#34c75920',tension:0.3,fill:true}]},options:{responsive:true,maintainAspectRatio:true}});}
async function loadClients(){const res=await fetch('/admin/api/clients');const data=await res.json();clientsData=data.clients;const tbody=document.querySelector('#clientsTable tbody');tbody.innerHTML='';
data.clients.forEach(client=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(client.payment_date).toLocaleDateString()}</td><td>${client.phone||'-'}</td><td><strong>${client.business_name||'-'}</strong><br><small>${(client.business_description||'').substring(0,50)}...</small></td><td><span class="expand-btn" onclick="showAnswers(${JSON.stringify(client).replace(/"/g,'&quot;')})">📋 Показать анкету</span></td><td>${client.report_path?'<a href="/download/'+client.user_id+'/premium" class="report-link">📥 Скачать отчет</a>':'<span class="badge badge-pending">генерация...</span>'}</td><td><span class="expand-btn" onclick="toggleDetail(this)">▶ Подробнее</span></td>`;const detailRow=tbody.insertRow();detailRow.className='row-detail';detailRow.style.display='none';detailRow.innerHTML=`<td colspan="6"><div class="detail-section"><strong>📝 Полная анкета:</strong><div class="detail-answers"><span class="answer-tag">Продаёт: ${client.q1||'-'}</span><span class="answer-tag">Чек: ${client.q2||'-'}</span><span class="answer-tag">Клиентов: ${client.q3||'-'}</span><span class="answer-tag">Цель: ${client.q4||'-'}</span><span class="answer-tag">Воронка: ${client.q5||'-'}</span></div></div><div class="detail-section"><strong>📄 Описание бизнеса:</strong><br>${client.business_description||'-'}</div>`;});}
async function loadDiagnostics(){const res=await fetch('/admin/api/diagnostics');const data=await res.json();const tbody=document.querySelector('#diagnosticsTable tbody');tbody.innerHTML='';data.diagnostics.forEach(d=>{const row=tbody.insertRow();row.innerHTML=`<tr><td>${new Date(d.date).toLocaleString()}</td><td>${d.phone||'-'}</td><td><strong>${d.business_name||'-'}</strong><br><small>${(d.business_description||'').substring(0,50)}...</small></td><td><span class="expand-btn" onclick="showAnswersDialog('${d.q1}','${d.q2}','${d.q3}','${d.q4}','${d.q5}')">📋 Показать</span></td><td><span class="badge ${d.report_status==='ready'?'badge-success':'badge-pending'}">${d.report_status==='ready'?'✅ Готов':'⏳ Генерация'}</span></td><td>${d.report_status==='ready'?'<a href="/download/'+d.user_id+'/free" class="report-link">📥 Скачать</a>':'-'}<tr>`;});}
function toggleDetail(btn){const row=btn.closest('tr');const detailRow=row.nextElementSibling;if(detailRow&&detailRow.classList.contains('row-detail')){const isHidden=detailRow.style.display==='none';detailRow.style.display=isHidden?'table-row':'none';btn.innerText=isHidden?'▼ Скрыть':'▶ Подробнее';}}
function showAnswers(client){alert(`📋 АНКЕТА КЛИЕНТА\n\nПродаёт: ${client.q1||'-'}\nСредний чек: ${client.q2||'-'}\nКлиентов/мес: ${client.q3||'-'}\nЦель: ${client.q4||'-'}\nАвтоворонка: ${client.q5||'-'}`);}
function showAnswersDialog(q1,q2,q3,q4,q5){alert(`📋 АНКЕТА\n\nПродаёт: ${q1||'-'}\nСредний чек: ${q2||'-'}\nКлиентов/мес: ${q3||'-'}\nЦель: ${q4||'-'}\nАвтоворонка: ${q5||'-'}`);}
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

# === СТРАНИЦЫ ОФЕРТЫ И ПОЛИТИКИ (сокращённо) ===
@app.get("/oferta", response_class=HTMLResponse)
async def oferta_page():
    content = """
<div class="hero" style="margin-bottom:20px;"><h1>Публичная оферта</h1><p style="font-size:14px;color:#6e6e73;">о заключении договора купли-продажи цифрового товара</p></div>
<div class="form-card" style="text-align:left;max-width:800px;">
    <p><strong>Индивидуальный предприниматель Макаревич Вероника Александровна,</strong><br>
    ИНН 781407988795, зарегистрированная в качестве налогоплательщика<br>
    налога на профессиональный доход (самозанятая),<br>
    размещая настоящий документ на сайте<br>
    realplanninig-oss-salesplan-web-7eb2.twc1.net (далее — «Сайт»),<br>
    предлагает неограниченному кругу лиц (далее — «Покупатель»)<br>
    заключить договор купли-продажи цифрового товара на условиях, изложенных ниже.</p>
    <!-- ... остальной текст оферты (полный) ... -->
    <p>Дата публикации: «05» мая 2026 г.</p>
</div>
"""
    return HTMLResponse(content=render_page(content))

@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    content = """
<div class="hero" style="margin-bottom:20px;"><h1>Политика обработки персональных данных</h1><p style="font-size:14px;color:#6e6e73;">Индивидуального предпринимателя Макаревич Вероники Александровны</p></div>
<div class="form-card" style="text-align:left;max-width:800px;">
    <h3>1. ОБЩИЕ ПОЛОЖЕНИЯ</h3>
    <p>1.1. Настоящая Политика определяет порядок обработки и защиты персональных данных лиц, использующих сайт realplanninig-oss-salesplan-web-7eb2.twc1.net (далее — «Сайт»).</p>
    <!-- ... остальной текст политики (полный) ... -->
    <p>Дата публикации: «05» мая 2026 г.</p>
</div>
"""
    return HTMLResponse(content=render_page(content))

# === ЗАПУСК ===
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
