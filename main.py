# File: main.py — веб-приложение Salesplan (с API ЮKassa)

import logging
import sqlite3
import os
import requests
import uuid
import re
import asyncio
import base64
import secrets
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn

load_dotenv()

# Конфигурация
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

# ЮKassa настройки
YOOKASSA_SHOP_ID = os.getenv("YOOKASSA_SHOP_ID")
YOOKASSA_SECRET_KEY = os.getenv("YOOKASSA_SECRET_KEY")

# Админка
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

# Инициализация базы данных
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

# Аутентификация для админки
security = HTTPBasic()

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Admin not configured")
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# Вспомогательные функции
def format_phone(phone: str) -> str:
    digits = re.sub(r'\D', '', phone)
    if digits.startswith('7') or digits.startswith('8'):
        digits = '7' + digits[1:]
    if len(digits) == 11 and digits.startswith('7'):
        return '+' + digits
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

def send_telegram_message(text: str):
    if TELEGRAM_TOKEN and ADMIN_CHAT_ID:
        try:
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": ADMIN_CHAT_ID, "text": text}, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send telegram: {e}")

# Функции для DeepSeek
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
        report = get_report(user_id, "premium")
        if report and report.get("file_path"):
            filepath = Path(report["file_path"])
            if filepath.exists():
                try:
                    with open(filepath, "rb") as f:
                        await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: requests.post(
                                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument",
                                data={"chat_id": ADMIN_CHAT_ID, "caption": f"📄 План продаж для пользователя {user_id}"},
                                files={"document": f},
                                timeout=5
                            )
                        )
                except Exception as e:
                    logger.error(f"Failed to send file to admin: {e}")

# HTML шаблоны
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
        <p>Вероника Макаревич | Продюсер экспертов</p>
        <div class="social-links">
            <a href="https://t.me/YourProducerOnline">Telegram-канал</a>
            <a href="https://max.ru/id781407988795_biz">MAX-канал</a>
            <a href="https://t.me/zapuskintelega_bot">Мини-курс "Раскрутка блога без вложений" — 1490 ₽</a>
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
    <script type="text/javascript">
        (function(m,e,t,r,i,k,a){{m[i]=m[i]||function(){{(m[i].a=m[i].a||[]).push(arguments)}};
        m[i].l=1*new Date();
        for (var j = 0; j < document.scripts.length; j++) {{if (document.scripts[j].src === r) {{ return; }}}}
        k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)}})
        (window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
        ym(108348240, "init", {{clickmap:true,trackLinks:true,accurateTrackBounce:true,webvisor:true}});
    </script>
    <noscript><div><img src="https://mc.yandex.ru/watch/108348240" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#fff;color:#1d1d1f}}
        .container{{max-width:600px;margin:0 auto;padding:60px 20px;text-align:center}}
        .spinner{{width:50px;height:50px;border:4px solid #e5e5e5;border-top-color:#007aff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}
        @keyframes spin{{to{{transform:rotate(360deg)}}}}
        .btn{{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;font-size:16px;font-weight:500;border-radius:12px;cursor:pointer;border:none}}
        .btn:hover{{background:#005fc5}}
    </style>
    <script>
        let attempts = 0;
        let isRedirected = false;
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
                        if (attempts < 120) {{
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
    <h1>🔍 Анализируем конкурентов и рынок</h1>
    <p>Лопатим вашу нишу, ищем точки роста и слабые места. Это займет 1-2 минуты.</p>
    <p style="font-size:14px;color:#8e8e93;margin-top:20px">Страница обновится автоматически</p>
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
    <script type="text/javascript">
        (function(m,e,t,r,i,k,a){{m[i]=m[i]||function(){{(m[i].a=m[i].a||[]).push(arguments)}};
        m[i].l=1*new Date();
        for (var j = 0; j < document.scripts.length; j++) {{if (document.scripts[j].src === r) {{ return; }}}}
        k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)}})
        (window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
        ym(108348240, "init", {{clickmap:true,trackLinks:true,accurateTrackBounce:true,webvisor:true}});
    </script>
    <noscript><div><img src="https://mc.yandex.ru/watch/108348240" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",Helvetica,sans-serif;background:#fff;color:#1d1d1f}}
        .container{{max-width:600px;margin:0 auto;padding:60px 20px;text-align:center}}
        .spinner{{width:50px;height:50px;border:4px solid #e5e5e5;border-top-color:#007aff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 30px}}
        @keyframes spin{{to{{transform:rotate(360deg)}}}}
        .step{{display:inline-block;margin:20px 10px;padding:8px 16px;border-radius:20px;background:#f5f5f7;font-size:14px}}
        .step.active{{background:#007aff;color:#fff}}
        .btn{{display:inline-block;background:#007aff;color:#fff;text-decoration:none;padding:14px 28px;font-size:16px;font-weight:500;border-radius:12px;cursor:pointer;border:none}}
        .btn-outline{{background:transparent;border:1px solid #007aff;color:#007aff}}
        .btn-outline:hover{{background:#007aff;color:#fff}}
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
    <p>Готовим для вас персональную стратегию продаж.<br>Это занимает <strong>1–5 минут</strong>.</p>
    
    <div style="margin: 30px 0;">
        <span id="step1" class="step active">1. Анализ конкурентов</span>
        <span id="step2" class="step">2. Сбор стратегии</span>
        <span id="step3" class="step">3. Формирование плана</span>
    </div>
    
    <p style="font-size:14px;color:#8e8e93;margin:20px 0">Страница обновится автоматически, когда план будет готов</p>
    
    <hr style="margin: 30px 0;">
    
    <p style="font-size: 15px;">⚡️ Не хотите ждать?</p>
    <p style="font-size: 14px; color: #6e6e73;">Мы пришлём готовый план в MAX по вашему номеру телефона</p>
    <button onclick="requestByPhone()" class="btn btn-outline" style="margin-top: 15px;">📲 Отправить в MAX по номеру телефона</button>
</div>

<script>
    function requestByPhone() {{
        fetch('/request_report_by_phone?user_id={user_id}', {{ method: 'POST' }})
            .then(res => res.json())
            .then(data => {{
                if (data.success) {{
                    alert('Заявка принята! План придёт в MAX, как только будет готов.');
                }} else {{
                    alert('Ошибка. Пожалуйста, обновите страницу.');
                }}
            }});
    }}
</script>
</body>
</html>"""

# Эндпоинты
@app.get("/")
async def index():
    content = '<div class="hero"><h1>Готовый план запуска продаж для онлайн-бизнеса</h1><p>Узнайте, почему ваш бизнес не продаёт, и получите пошаговую стратегию</p></div><div class="features"><div class="feature"><div class="feature-icon">⭐️</div><h3>Бесплатный аудит — 2 минуты</h3><p>Узнайте слабые места вашего онлайн-бизнеса</p></div><div class="feature"><div class="feature-icon">🔥</div><h3>Готовая стратегия — 5 минут</h3><p>План продаж с анализом конкурентов</p></div><div class="feature"><div class="feature-icon">⚡️</div><h3>Первое действие — 15 минут</h3><p>Внедрите работающее решение</p></div></div><div style="text-align:center"><a href="/survey" class="btn">Начать диагностику</a></div>'
    return HTMLResponse(content=render_page(content))

@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<div class="hero">
    <h1>Расскажите о вашем бизнесе — 2 минуты</h1>
    <p>Анализируем данные — диагностика будет готова через 60 секунд</p>
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
            <button type="submit" class="btn" id="submitBtn" onclick="ym(108348240,'reachGoal','survey_submit'); return true;">Получить диагностику</button>
        </div>
    </form>
</div>

<script>
    document.getElementById('surveyForm').addEventListener('submit', function(e) {
        const submitBtn = document.getElementById('submitBtn');
        submitBtn.disabled = true;
        submitBtn.textContent = '⏳ Анализируем...';
        
        setTimeout(function() {
            if (submitBtn.disabled) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Получить диагностику';
            }
        }, 30000);
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
        diagnostic_text = call_deepseek_diagnostic(business_name, business_description, answers)
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
    <h1>✨ Ваша диагностика готова</h1>
    <p style="font-size: 18px;">Держите — это ваш первый шаг к стабильным продажам</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: linear-gradient(135deg, #f5f5f7 0%, #ffffff 100%); border-radius: 28px; padding: 32px; margin-bottom: 32px;">
        <div style="font-size: 56px; margin-bottom: 16px;">📄</div>
        <p style="font-size: 14px; color: #8e8e93; margin-top: 16px;">Полный текст диагностики ниже</p>
    </div>
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="margin: 32px 0; text-align: center;">
        <h2 style="font-size: 28px; margin-bottom: 16px;">🚀 Что дальше?</h2>
        <p style="font-size: 17px; color: #6e6e73; margin-bottom: 32px;">Вы получили бесплатный разбор — это только первый шаг. Чтобы реально увеличить продажи, нужен детальный маркетинговый план.</p>
    </div>
    
    <div style="background: linear-gradient(135deg, #007aff10 0%, #005fc510 100%); border-radius: 28px; padding: 32px; margin: 32px 0;">
        <h3 style="font-size: 24px; margin-bottom: 20px;">📋 В профессиональном маркетинговом плане запуска продаж:</h3>
        <div style="display: flex; flex-wrap: wrap; gap: 12px; justify-content: center;">
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">🔍 Разбор 5 конкурентов</span>
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">⚡ Готовая воронка под ваш бизнес</span>
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">📅 Пошаговый план запуска на месяц</span>
            <span style="background: #ffffff; padding: 8px 20px; border-radius: 30px; font-size: 14px;">💬 Скрипты для продаж</span>
        </div>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="margin: 32px 0;">
        <div class="price-old">4 900 ₽</div>
        <div class="price-new">490 ₽</div>
        <p style="margin-top: 8px;">⚡ Только сейчас — специальная цена для участников MAX-канала<br>Предложение действует 24 часа</p>
    </div>
    
    <!-- НА СТРАНИЦЕ ДИАГНОСТИКИ ТОЛЬКО КНОПКА, ТЕЛЕФОНА НЕТ -->
    <form action="/payment/create" method="post" style="margin-top: 24px;">
        <input type="hidden" name="user_id" value="{user_id}">
        <button type="submit" class="btn" style="width: 100%; padding: 16px; font-size: 18px;" onclick="ym(108348240,'reachGoal','payment_start'); return true;">🔥 Получить доступ к плану</button>
        <p style="font-size: 13px; color: #8e8e93; margin-top: 16px;">Никакого спама. Только профессиональный маркетинговый план и бонусы.</p>
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
    """Переход на страницу оплаты (телефон не требуется, он будет запрошен на странице оплаты)"""
    logger.info(f"Payment create for user {user_id}")
    
    # Проверяем, есть ли уже телефон у пользователя
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    # Если телефона нет, создаем запись без телефона
    if not row or not row[0]:
        save_user(user_id, None, None)
    
    return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)

@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str, status: str = None):
    error_message = ""
    if status == "cancelled":
        error_message = '<p style="color: red; margin-bottom: 20px;">❌ Платеж был отменен. Попробуйте снова.</p>'
    
    existing_report = get_report(user_id, "premium")
    if existing_report and existing_report["status"] == "ready":
        return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)
    
    # Получаем телефон пользователя из БД
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    phone = row[0] if row else ""
    
    content = f'''
<div class="hero">
    <h1>💰 План продаж — 490 ₽</h1>
</div>
<div class="form-card">
    {error_message}
    <h3>Что вы получите:</h3>
    <ul>
        <li>✅ Разбор 5 конкурентов</li>
        <li>✅ Готовую воронку продаж</li>
        <li>✅ Пошаговый план запуска продаж на месяц</li>
        <li>✅ Скрипты для продаж</li>
    </ul>
    <div class="price-old" style="text-align:center">4 900 ₽</div>
    <div class="price-new" style="text-align:center">490 ₽</div>
    <p style="text-align:center; margin-top:8px">⚡ Только сейчас — специальная цена для участников MAX-канала</p>
    
    <form action="/create_yookassa_payment" method="post" style="margin-top: 30px;">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group">
            <label>📞 Ваш номер телефона для отправки плана:</label>
            <input type="tel" name="phone" value="{phone}" placeholder="+7 (___) ___-__-__" required style="text-align: center; font-size: 18px;">
        </div>
        <div style="text-align:center;margin:20px 0">
            <button type="submit" class="btn" style="width: 100%;" onclick="ym(108348240,'reachGoal','pay_490'); return true;">💳 Оплатить 490 ₽</button>
        </div>
    </form>
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

# ГЛАВНЫЙ ЭНДПОИНТ - API ЮKassa
@app.post("/create_yookassa_payment")
async def create_yookassa_payment(request: Request, user_id: str = Form(...), phone: str = Form(...)):
    phone = format_phone(phone)
    logger.info(f"Creating YooKassa payment for user {user_id}, phone {phone}")
    save_user(user_id, phone, None)
    
    base_url = str(request.base_url).rstrip('/')
    
    # Проверяем наличие API ключей
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        logger.error("YooKassa credentials missing!")
        save_payment_request(user_id, phone)
        send_telegram_message(f"Новая заявка на оплату (fallback)!\nID: {user_id}\nТелефон: {phone}")
        return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)
    
    # Создаем платеж в ЮKassa с чеком
    payment_data = {
        "amount": {"value": "490.00", "currency": "RUB"},
        "confirmation": {"type": "redirect", "return_url": f"{base_url}/payment/confirm"},
        "capture": True,
        "description": f"План продаж для пользователя {user_id}",
        "metadata": {"user_id": user_id, "phone": phone},
        "receipt": {
            "customer": {"phone": phone},
            "items": [
                {
                    "description": "Профессиональный маркетинговый план продаж",
                    "quantity": "1.00",
                    "amount": {"value": "490.00", "currency": "RUB"},
                    "vat_code": "1",
                    "payment_mode": "full_payment",
                    "payment_subject": "service"
                }
            ]
        }
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
            send_telegram_message(f"💳 Создан платеж ЮKassa!\nID: {user_id}\nТелефон: {phone}\nPayment ID: {payment_id}")
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
        logger.info(f"Webhook received: {body}")
        
        event = body.get("event")
        payment = body.get("object", {})
        payment_id = payment.get("id")
        status = payment.get("status")
        
        if event == "payment.succeeded" and status == "succeeded":
            update_payment_status(payment_id, "succeeded")
            payment_info = get_payment_by_yookassa_id(payment_id)
            if payment_info:
                send_telegram_message(f"✅ ПОДТВЕРЖДЕНА ОПЛАТА через webhook!\nID: {payment_info['user_id']}\nТелефон: {payment_info['phone']}")
        return JSONResponse(content={"status": "ok"})
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return JSONResponse(content={"status": "error"}, status_code=500)

@app.get("/payment/confirm")
async def payment_confirm(request: Request):
    params = dict(request.query_params)
    logger.info(f"Payment confirm called with params: {params}")
    
    payment_id = params.get("paymentId") or params.get("payment_id")
    
    if not payment_id:
        return RedirectResponse(url="/", status_code=303)
    
    payment_info = get_payment_by_yookassa_id(payment_id)
    if not payment_info:
        return RedirectResponse(url="/", status_code=303)
    
    user_id = payment_info["user_id"]
    
    if YOOKASSA_SHOP_ID and YOOKASSA_SECRET_KEY:
        auth = base64.b64encode(f"{YOOKASSA_SHOP_ID}:{YOOKASSA_SECRET_KEY}".encode()).decode()
        try:
            response = requests.get(
                f"https://api.yookassa.ru/v3/payments/{payment_id}",
                headers={"Authorization": f"Basic {auth}"},
                timeout=30
            )
            if response.status_code == 200:
                payment = response.json()
                status = payment.get("status")
                if status == "succeeded":
                    update_payment_status(payment_id, "succeeded")
                    return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)
                else:
                    update_payment_status(payment_id, status)
                    return RedirectResponse(url=f"/payment?user_id={user_id}&status={status}", status_code=303)
        except Exception as e:
            logger.error(f"Error checking payment status: {e}")
    
    update_payment_status(payment_id, "succeeded")
    return RedirectResponse(url=f"/payment/success?user_id={user_id}", status_code=303)

@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str):
    logger.info(f"Payment success page for user {user_id}")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    phone = row[0] if row else "не указан"
    
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
    <h1>🎉 Спасибо за покупку!</h1>
    <p>Ваш профессиональный маркетинговый план — полная версия ниже</p>
</div>
<div class="form-card" style="text-align: center;">
    <div style="background: linear-gradient(135deg, #f5f5f7 0%, #ffffff 100%); border-radius: 28px; padding: 32px; margin-bottom: 32px;">
        <div style="font-size: 56px; margin-bottom: 16px;">📄</div>
        <p style="font-size: 14px; color: #8e8e93; margin-top: 16px;">Ваш профессиональный маркетинговый план — полная версия ниже</p>
    </div>
    
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; margin: 20px 0; text-align: left; max-height: 500px; overflow-y: auto;">
        <div style="white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{report_text_html}</div>
    </div>
    
    <div style="margin: 20px 0;">
        <a href="/download/{user_id}/premium" class="btn btn-outline" style="margin: 10px;">📥 Скачать план в TXT</a>
        <button onclick="requestByPhone()" class="btn btn-outline" style="margin: 10px;">📲 Отправить план в MAX</button>
    </div>
    
    <hr style="margin: 32px 0;">
    
    <div style="background: #f5f5f7; border-radius: 20px; padding: 20px; text-align: left;">
        <p style="font-size: 18px; font-weight: 600;">Хотите, чтобы я лично, как продюсер экспертов, разобрала ваш план запуска продаж и дала честный фидбек?</p>
        <p>Знаете, в чём главное отличие меня от других? Я не просто консультирую. Я беру эксперта за руку и веду к продажам по чёткой системе. Пока вы спите — воронка работает.</p>
        <div style="text-align:center;margin-top:20px">
            <a href="/consultation?user_id={user_id}" class="btn" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">→ Записаться на бесплатный разбор</a>
        </div>
    </div>
    
    <div style="margin: 32px 0;">
        <a href="https://vk.ru/topic-164421538_39653658" target="_blank" class="btn btn-outline" style="margin: 10px;">📸 Реальные отзывы моих клиентов (ВКонтакте)</a>
    </div>
</div>

<script>
    function requestByPhone() {{
        fetch('/request_report_by_phone?user_id={user_id}', {{ method: 'POST' }})
            .then(res => res.json())
            .then(data => {{
                if (data.success) {{
                    alert('Заявка принята! План придёт в MAX, как только будет готов.');
                }} else {{
                    alert('Ошибка. Пожалуйста, обновите страницу.');
                }}
            }});
    }}
</script>
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
    
    <div style="margin: 20px 0;">
        <a href="/download/{user_id}/premium" class="btn btn-outline" style="margin: 10px;">📥 Скачать план в TXT</a>
        <button onclick="requestByPhone()" class="btn btn-outline" style="margin: 10px;">📲 Отправить план в MAX</button>
    </div>
</div>

<script>
    function requestByPhone() {{
        fetch('/request_report_by_phone?user_id={user_id}', {{ method: 'POST' }})
            .then(res => res.json())
            .then(data => {{
                if (data.success) {{
                    alert('Заявка принята!');
                }} else {{
                    alert('Ошибка');
                }}
            }});
    }}
</script>
'''
        return HTMLResponse(content=render_page(content))

@app.get("/check_premium_status")
async def check_premium_status(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT status FROM reports WHERE user_id = ? AND report_type = 'premium' ORDER BY id DESC LIMIT 1", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return {"ready": row and row[0] == 'ready'}

@app.post("/request_report_by_phone")
async def request_report_by_phone(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row and row[0]:
        send_telegram_message(f"📱 Запрос на отправку плана в MAX!\nID: {user_id}\nТелефон: {row[0]}")
        return {"success": True}
    return {"success": False, "error": "Телефон не найден"}

@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    phone = row[0] if row else "не указан"
    
    content = f'''
<div class="hero">
    <h1>🔥 Первым 100 подписчикам — консультация бесплатно!</h1>
    <p style="font-size: 18px;">Диагностика бизнеса эксперта: 3 точки утечки клиентов и точный первый шаг для их устранения</p>
</div>

<div class="form-card" style="text-align: center;">
    <p style="font-size: 16px; color: #007aff; margin-bottom: 20px;">✅ После проверки подписки я свяжусь с вами в MAX для согласования времени</p>
    
    <div style="margin-bottom: 30px;">
        <div style="font-size: 48px; font-weight: 700; color: #007aff;">Осталось мест: <span id="counter">87</span></div>
        <p style="color: #6e6e73; margin-top: 10px;">Только для первых 100 подписчиков</p>
    </div>
    
    <div style="margin: 30px 0;">
        <a href="https://max.ru/id781407988795_biz" target="_blank" class="btn" style="width: auto; padding: 16px 32px;">📢 Подписаться на канал в MAX</a>
    </div>
    
    <hr style="margin: 30px 0;">
    
    <div id="formBlock">
        <form action="/consultation/submit" method="post">
            <input type="hidden" name="user_id" value="{user_id}">
            <div class="form-group">
                <label>Ваш телефон (проверим подписку)</label>
                <input type="tel" name="phone" value="{phone}" placeholder="+7 (___) ___-__-__" required>
            </div>
            <div class="form-group">
                <label>🕐 Удобное время для созвона (по Москве)</label>
                <input type="text" name="time" placeholder="например: завтра в 15:00" required>
            </div>
            <div style="text-align: center;">
                <button type="submit" class="btn" onclick="ym(108348240,'reachGoal','consultation_request'); return true;">Отправить заявку</button>
            </div>
        </form>
    </div>
</div>

<script>
    let counter = 87;
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
    message = f"📞 Новая заявка на консультацию!\nID: {user_id}\nВремя: {time}"
    if phone:
        message += f"\nТелефон: {phone}"
    send_telegram_message(message)
    
    content = f"""
<div class="hero">
    <h1>✅ Заявка принята!</h1>
</div>
<div class="form-card" style="text-align: center;">
    <p>✅ Я свяжусь с вами в MAX в ближайшее время, чтобы подтвердить время разбора.</p>
    
    <hr style="margin: 32px 0;">
    
    <div class="course-card">
        <h2 style="font-size: 28px; margin-bottom: 16px;">📚 А пока ждёте...</h2>
        <p style="font-size: 17px; margin-bottom: 24px;">Хотите уже сейчас начать привлекать клиентов бесплатно?</p>
        
        <h3 style="font-size: 22px; margin-bottom: 16px;">Мини-курс «Раскрутка блога без вложений»</h3>
        <p>Пошаговая система для экспертов, которые хотят привлекать клиентов бесплатно</p>
        
        <div style="margin: 24px 0;">
            <p><strong>Что вы получите:</strong></p>
            <ul style="text-align: left; display: inline-block;">
                <li>✅ 7 видеоуроков по 10 минут</li>
                <li>✅ Готовую структуру блога, который продаёт</li>
                <li>✅ 10 рабочих тем для постов</li>
                <li>✅ Чек-лист «Как привлечь первых 10 клиентов»</li>
                <li>✅ Обратную связь от меня лично</li>
            </ul>
        </div>
        
        <div class="price-old" style="text-align: center;">14 900 ₽</div>
        <div class="price-new" style="text-align: center;">1 490 ₽</div>
        <p style="text-align: center; margin: 16px 0;">📌 Только сейчас — специальная цена</p>
        
        <div style="text-align: center;">
            <a href="https://t.me/zapuskintelega_bot" target="_blank" class="btn">🎓 Получить мини-курс в боте</a>
        </div>
        
        <p style="font-size: 13px; color: #8e8e93; margin-top: 24px; text-align: center;">После оплаты в боте вы получите доступ к урокам и обратную связь от Вероники</p>
    </div>
    
    <div style="text-align:center;margin-top: 32px;">
        <a href="/" class="btn btn-outline">→ На главную</a>
    </div>
</div>
"""
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

# Админка - защищенный эндпоинт для просмотра логов
@app.get("/admin/logs")
async def admin_logs(auth: bool = Depends(verify_admin)):
    try:
        with open(LOGS_DIR / "salesplan.log", "r", encoding="utf-8") as f:
            lines = f.readlines()[-500:]
            return Response(content="".join(lines), media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
