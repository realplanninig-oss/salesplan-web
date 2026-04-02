
# File: main.py — веб-приложение Salesplan
# План запуска продаж для онлайн-бизнеса
# Яндекс.Метрика: 108348240
# Оплата через ЮKassa (прямая ссылка, без вебхука)
# DeepSeek API для генерации диагностики и плана продаж

import logging
import sqlite3
import os
import requests
import uuid
import re
import asyncio
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

load_dotenv()

# === КОНФИГУРАЦИЯ ===
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
PAYMENT_URL = "https://yookassa.ru/my/i/ac4jwv2G_TJt/l"

# === НАСТРОЙКА ЛОГИРОВАНИЯ ===
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

# === БАЗА ДАННЫХ ===
DB_PATH = "salesplan.db"
REPORTS_DIR = Path("./reports")
REPORTS_DIR.mkdir(exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, phone TEXT, name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS business_data (user_id TEXT PRIMARY KEY, business_name TEXT, business_description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS forms (user_id TEXT PRIMARY KEY, q1 TEXT, q2 TEXT, q3 TEXT, q4 TEXT, q5 TEXT, q6 TEXT, q7 TEXT, completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, report_type TEXT NOT NULL, report_text TEXT, file_path TEXT, status TEXT DEFAULT 'generating', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ready_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS consultations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, time TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, phone TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()

init_db()

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
    return {"name": row[0], "description": row[1]} if row else None

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
    return {"id": row[0], "text": row[1], "file_path": row[2], "status": row[3]} if row else None

def save_consultation(user_id: str, time: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO consultations (user_id, time) VALUES (?, ?)", (user_id, time))
    conn.commit()
    conn.close()

def save_payment_request(user_id: str, phone: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO payments (user_id, phone) VALUES (?, ?)", (user_id, phone))
    conn.commit()
    conn.close()

def send_telegram_message(text: str):
    if TELEGRAM_TOKEN and ADMIN_CHAT_ID:
        try:
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": ADMIN_CHAT_ID, "text": text})
        except Exception as e:
            logger.error(f"Failed to send telegram: {e}")

# === DEEPSEEK API ФУНКЦИИ ===
def call_deepseek_diagnostic(name: str, description: str, answers: dict) -> str:
    """Вызов DeepSeek API для генерации диагностики"""
    
    q1_map = {
        "Услугу": "Услугу",
        "Инфопродукт": "Инфопродукт",
        "Консультацию": "Консультацию",
        "Пока не продаю": "Пока не продаю"
    }
    q2_map = {
        "до 5k": "до 5000 ₽",
        "5k-20k": "5000-20000 ₽",
        "20k-50k": "20000-50000 ₽",
        ">50k": "более 50000 ₽"
    }
    q3_map = {
        "<10": "менее 10",
        "10-50": "10-50",
        "50-200": "50-200",
        ">200": "более 200"
    }
    q4_map = {
        "300k/мес": "300 000 ₽/мес",
        "500k/мес": "500 000 ₽/мес",
        "1M/мес": "1 000 000 ₽/мес",
        "Масштаб": "масштабирование"
    }
    q5_map = {
        "Да": "да",
        "Нет": "нет",
        "В разработке": "в разработке"
    }
    
    survey_info = f"""
ДАННЫЕ О БИЗНЕСЕ:
• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}
• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}
• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}
• Цель на 2026: {q4_map.get(answers.get('q4'), 'не указано')}
• Есть автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}
"""
    
    prompt = f"""Сделай профессиональный маркетинговый разбор онлайн-бизнеса на основе предоставленных данных.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши структурированный отчет на русском языке в разговорном стиле, включив:

1. ОБЩАЯ ИНФОРМАЦИЯ
   - Ниша бизнеса
   - Целевая аудитория (кто, их главная боль, какое решение ищут)
   - Оценка текущего уровня от 0 до 100

2. АНАЛИЗ
   - 3 сильные стороны
   - 3 зоны роста

3. ПЕРСОНАЛЬНЫЕ РЕКОМЕНДАЦИИ
   - 3 конкретных шага для увеличения продаж

ВАЖНО:
- Пиши как Вероника, продюсер экспертов. Живо, с эмодзи, с обращением на "ты"
- Не используй символы *, #, _ для форматирования
- Для списков используй дефисы (-)
- В разделе "Целевая аудитория" обязательно опиши: кто это, их главная проблема, какое решение ищут
- В третьем разделе обязательно дай рекомендацию по настройке простой воронки продаж"""
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": "Ты Вероника, продюсер экспертов с 8-летним опытом. Говоришь разговорно, с эмодзи, на 'ты'."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 2000
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=120)
        if response.status_code == 200:
            result = response.json()
            return result["choices"][0]["message"]["content"]
        else:
            logger.error(f"DeepSeek error: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"DeepSeek failed: {e}")
        return None

def generate_premium_report_sync(user_id: str, name: str, description: str, answers: dict, report_id: int):
    """Синхронная генерация премиум отчета через DeepSeek"""
    
    q1_map = {
        "Услугу": "Услугу",
        "Инфопродукт": "Инфопродукт",
        "Консультацию": "Консультацию",
        "Пока не продаю": "Пока не продаю"
    }
    q2_map = {
        "до 5k": "до 5k",
        "5k-20k": "5k-20k",
        "20k-50k": "20k-50k",
        ">50k": ">50k"
    }
    q3_map = {
        "<10": "<10",
        "10-50": "10-50",
        "50-200": "50-200",
        ">200": ">200"
    }
    q4_map = {
        "300k/мес": "300k/мес",
        "500k/мес": "500k/мес",
        "1M/мес": "1M/мес",
        "Масштаб": "Масштаб"
    }
    q5_map = {
        "Да": "да",
        "Нет": "нет",
        "В разработке": "в разработке"
    }
    
    survey_info = f"""
ДАННЫЕ О БИЗНЕСЕ:
• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}
• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}
• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}
• Цель: {q4_map.get(answers.get('q4'), 'не указано')}
• Автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}
"""
    
    prompt = f"""Сделай профессиональный план запуска продаж для онлайн-бизнеса.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
{survey_info}

Напиши структурированный план на русском языке в разговорном стиле Вероники:

1. ОЦЕНКА СИТУАЦИИ
2. АНАЛИЗ РЫНКА И КОНКУРЕНТОВ (3-5 игроков)
3. КОМУ ПРОДАВАТЬ (ЦА)
4. СИЛЬНЫЕ И СЛАБЫЕ СТОРОНЫ
5. ВОРОНКА ПРОДАЖ ШАГ ЗА ШАГОМ
6. ПЛАН ДЕЙСТВИЙ НА МЕСЯЦ

Оформление:
- Заголовки ЗАГЛАВНЫМИ БУКВАМИ, отступы пустыми строками
- Списки через дефисы
- Пиши живо, с эмодзи, как Вероника"""
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": "Ты Вероника, продюсер экспертов с 8-летним опытом."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 4000
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=180)
        if response.status_code == 200:
            result = response.json()
            report_text = result["choices"][0]["message"]["content"]
            
            filename = f"premium_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = REPORTS_DIR / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_text)
            
            update_report_status(report_id, 'ready', str(filepath))
            logger.info(f"Premium report generated for {user_id}")
        else:
            update_report_status(report_id, 'failed')
            logger.error(f"DeepSeek error: {response.status_code}")
    except Exception as e:
        update_report_status(report_id, 'failed')
        logger.error(f"Premium report error: {e}")

async def generate_premium_report_background(user_id: str, name: str, description: str, answers: dict, report_id: int):
    """Фоновая генерация премиум отчета"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, generate_premium_report_sync, user_id, name, description, answers, report_id)

# === FastAPI приложение ===
app = FastAPI(title="Salesplan")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>{title} | Salesplan</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'SF Pro Display', Helvetica, sans-serif; background: #ffffff; color: #1d1d1f; line-height: 1.2; -webkit-font-smoothing: antialiased; }
        .container { max-width: 1000px; margin: 0 auto; padding: 60px 24px; }
        .hero { text-align: center; margin-bottom: 80px; }
        .hero h1 { font-size: 48px; font-weight: 700; letter-spacing: -0.5px; color: #1d1d1f; margin-bottom: 20px; line-height: 1.1; }
        .hero p { font-size: 24px; color: #6e6e73; max-width: 700px; margin: 0 auto; line-height: 1.3; }
        .features { display: flex; flex-wrap: wrap; gap: 30px; justify-content: center; margin-bottom: 80px; }
        .feature { flex: 1; min-width: 240px; background: #ffffff; border-radius: 24px; padding: 32px 24px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.04); }
        .feature-icon { font-size: 40px; margin-bottom: 20px; }
        .feature h3 { font-size: 20px; font-weight: 600; margin-bottom: 12px; color: #1d1d1f; }
        .feature p { font-size: 16px; color: #6e6e73; line-height: 1.4; }
        .btn { display: inline-block; background: #007aff; color: white; text-decoration: none; padding: 16px 32px; font-size: 17px; font-weight: 500; border-radius: 12px; border: none; cursor: pointer; transition: background 0.2s ease; text-align: center; }
        .btn:hover { background: #005fc5; }
        .form-card { background: #ffffff; border-radius: 24px; padding: 48px; box-shadow: 0 4px 16px rgba(0,0,0,0.04); max-width: 640px; margin: 0 auto; }
        .form-group { margin-bottom: 28px; }
        label { font-size: 16px; font-weight: 500; color: #1d1d1f; margin-bottom: 10px; display: block; }
        input, textarea { width: 100%; padding: 14px 16px; font-size: 16px; font-family: inherit; border: 1px solid #d2d2d7; border-radius: 12px; background: #fff; transition: all 0.2s ease; }
        input:focus, textarea:focus { outline: none; border-color: #007aff; box-shadow: 0 0 0 4px rgba(0,122,255,0.1); }
        .radio-group { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; }
        .radio-group label { display: flex; align-items: center; gap: 8px; font-size: 16px; font-weight: normal; cursor: pointer; }
        .radio-group input[type="radio"] { width: 18px; height: 18px; margin: 0; }
        .footer { text-align: center; margin-top: 80px; padding-top: 32px; border-top: 1px solid #e5e5e7; font-size: 14px; color: #8e8e93; }
        .social-links { margin-top: 20px; display: flex; flex-wrap: wrap; justify-content: center; gap: 24px; }
        .social-links a { color: #007aff; text-decoration: none; font-size: 14px; }
        hr { margin: 40px 0; border: none; border-top: 1px solid #e5e5e7; }
        @media (max-width: 700px) {
            .container { padding: 40px 20px; }
            .hero h1 { font-size: 32px; }
            .hero p { font-size: 18px; }
            .features { gap: 16px; margin-bottom: 48px; }
            .feature { min-width: 180px; padding: 24px 16px; }
            .feature-icon { font-size: 32px; }
            .feature h3 { font-size: 17px; }
            .feature p { font-size: 13px; }
            .form-card { padding: 28px 20px; }
            .btn { width: 100%; }
            .radio-group { flex-direction: column; gap: 12px; }
        }
    </style>
    <script type="text/javascript">(function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};m[i].l=1*new Date();for(var j=0;j<document.scripts.length;j++){if(document.scripts[j].src===r){return;}}k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)}})(window,document,'script','https://mc.yandex.ru/metrika/tag.js','ym');ym(108348240,'init',{webvisor:true,clickmap:true,trackLinks:true,accurateTrackBounce:true});</script>
    <noscript><div><img src="https://mc.yandex.ru/watch/108348240" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
</head>
<body>
<div class="container">
    {content}
    <div class="footer">
        <p>📱 Вероника Макаревич | Продюсер экспертов</p>
        <div class="social-links">
            <a href="https://t.me/YourProducerOnline">Telegram-канал</a>
            <a href="https://max.ru/id781407988795_biz">MAX-канал</a>
            <a href="https://t.me/zapuskintelega_bot">Мини-курс "Раскрутка блога без вложений"</a>
            <a href="https://vk.ru/makarevichveronika">ВКонтакте</a>
        </div>
        <p>© 2026 Все права защищены</p>
    </div>
</div>
</body>
</html>"""

def render_page(content: str, title: str = "Salesplan"):
    return HTML_TEMPLATE.format(title=title, content=content)

@app.get("/", response_class=HTMLResponse)
async def index():
    content = """
<div class="hero">
    <h1>Готовый план запуска продаж для онлайн-бизнеса</h1>
    <p>Узнайте, почему ваш бизнес не продаёт, и получите пошаговую стратегию</p>
</div>
<div class="features">
    <div class="feature">
        <div class="feature-icon">⭐️</div>
        <h3>Бесплатный аудит — 2 минуты</h3>
        <p>Узнайте слабые места вашего онлайн-бизнеса</p>
    </div>
    <div class="feature">
        <div class="feature-icon">🔥</div>
        <h3>Готовая стратегия — 5 минут</h3>
        <p>План продаж с анализом конкурентов</p>
    </div>
    <div class="feature">
        <div class="feature-icon">⚡️</div>
        <h3>Первое действие — 15 минут</h3>
        <p>Внедрите работающее решение</p>
    </div>
</div>
<div style="text-align: center;">
    <a href="/survey" class="btn">→ Начать диагностику</a>
</div>
"""
    return HTMLResponse(content=render_page(content, "Главная"))

@app.get("/survey", response_class=HTMLResponse)
async def survey():
    content = """
<div class="hero">
    <h1>Расскажите о вашем бизнесе — 2 минуты</h1>
    <p>Анализируем данные — диагностика будет готова через 60 секунд</p>
</div>
<div class="form-card">
    <form action="/survey/submit" method="post">
        <div class="form-group">
            <label>1. Название бизнеса</label>
            <input type="text" name="business_name" required>
        </div>
        <div class="form-group">
            <label>2. Короткое описание (чем занимаетесь, кому помогаете)</label>
            <textarea name="business_description" rows="3" required></textarea>
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
                <label><input type="radio" name="q2" value="до 5k" required> &lt;5k</label>
                <label><input type="radio" name="q2" value="5k-20k"> 5k-20k</label>
                <label><input type="radio" name="q2" value="20k-50k"> 20k-50k</label>
                <label><input type="radio" name="q2" value=">50k"> &gt;50k</label>
            </div>
        </div>
        <div class="form-group">
            <label>5. Клиентов в месяц (примерно)</label>
            <div class="radio-group">
                <label><input type="radio" name="q3" value="<10" required> &lt;10</label>
                <label><input type="radio" name="q3" value="10-50"> 10-50</label>
                <label><input type="radio" name="q3" value="50-200"> 50-200</label>
                <label><input type="radio" name="q3" value=">200"> &gt;200</label>
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
        <div style="text-align: center;">
            <button type="submit" class="btn">→ Получить диагностику</button>
        </div>
    </form>
</div>
"""
    return HTMLResponse(content=render_page(content, "Опрос"))

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
    
    save_user(user_id, None, None)
    save_business_data(user_id, business_name, business_description)
    save_form(user_id, {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5})
    
    # Генерация диагностики через DeepSeek
    answers = {"q1": q1, "q2": q2, "q3": q3, "q4": q4, "q5": q5}
    diagnostic_text = call_deepseek_diagnostic(business_name, business_description, answers)
    
    if diagnostic_text:
        save_report(user_id, "free", diagnostic_text)
    else:
        # Запасной вариант
        fallback_text = f"""Диагностика для бизнеса "{business_name}"

Описание: {business_description}

На основе предоставленных данных:
• Продаёт: {q1}
• Средний чек: {q2}
• Клиентов/мес: {q3}
• Цель: {q4}
• Автоворонка: {q5}

Рекомендации:
1. Проанализируйте свою целевую аудиторию
2. Настройте простую воронку продаж
3. Добавьте призывы к действию в контент
"""
        save_report(user_id, "free", fallback_text)
    
    return RedirectResponse(url=f"/diagnostic?user_id={user_id}", status_code=303)

@app.get("/diagnostic", response_class=HTMLResponse)
async def diagnostic(user_id: str):
    biz = get_business_data(user_id)
    report = get_report(user_id, "free")
    
    report_text = report['text'] if report else 'Диагностика временно недоступна'
    formatted_text = report_text.replace("\n", "<br>")
    
    content = f"""
<div class="hero">
    <h1>✅ Ваша диагностика готова</h1>
</div>
<div class="form-card">
    <div style="background: #f5f5f7; padding: 20px; border-radius: 20px; margin-bottom: 20px; white-space: pre-wrap; font-size: 14px; line-height: 1.5;">
        {formatted_text}
    </div>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/download/{user_id}/free" class="btn">📄 Скачать диагностику (.txt)</a>
    </div>
    <hr>
    <h2>🔥 Что дальше?</h2>
    <p>Вы получили бесплатный разбор — это только первый шаг. Чтобы реально увеличить продажи, нужен детальный план. Я проанализирую ваш бизнес — это займет всего около 5 минут.</p>
    
    <p><strong>Я Вероника, продюсер экспертов. За 8 лет помогла десяткам специалистов выйти на стабильные продажи.</strong></p>
    
    <div style="margin: 20px 0; background: #f5f5f7; padding: 20px; border-radius: 20px;">
        <p><strong>🔥 Эксперт по китайскому</strong> — без блога, только таргет и бот, заработала 120 000 ₽ за 2 недели</p>
        <p><strong>🔥 Психолог Елена</strong> — 7 клиентов за 2 недели, доход с 0 до 180 000 ₽</p>
        <p><strong>🔥 Мастер Фен Шуй</strong> — первый запуск принес 195 000 ₽ при рекламе 30 000 ₽</p>
        <p><strong>🔥 Онлайн-школа</strong> — 2 000 000 ₽ за 2 недели через марафон в ВК</p>
    </div>
    
    <h3>В детальном плане продаж:</h3>
    <ul style="margin-left: 20px; margin-bottom: 20px;">
        <li>✅ Разбор 5 конкурентов — увидите, как их обойти</li>
        <li>✅ Готовая воронка под ваш бизнес</li>
        <li>✅ Пошаговый план запуска продаж на месяц (что делать каждую неделю)</li>
        <li>✅ Скрипты для продаж</li>
    </ul>
    
    <p><strong>Только сейчас — специальная цена 490 ₽ вместо 990 ₽. Предложение действует 24 часа.</strong></p>
    
    <form action="/payment/create" method="post" style="margin-top: 30px;">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group">
            <label>📞 Оставьте ваш номер телефона — я пришлю ссылку на оплату:</label>
            <input type="tel" name="phone" placeholder="+7 (___) ___-__-__" required>
        </div>
        <div style="text-align: center;">
            <button type="submit" class="btn">→ Получить доступ к плану</button>
        </div>
        <p style="text-align: center; font-size: 14px; margin-top: 15px;">Никакого спама. Только план продаж и бонусы.</p>
    </form>
</div>
"""
    return HTMLResponse(content=render_page(content, "Диагностика"))

@app.post("/payment/create")
async def payment_create(user_id: str = Form(...), phone: str = Form(...)):
    phone = format_phone(phone)
    save_user(user_id, phone, None)
    save_payment_request(user_id, phone)
    
    # Отправляем уведомление админу
    send_telegram_message(f"💰 Новая заявка на оплату!\n\nID: {user_id}\nТелефон: {phone}")
    
    return RedirectResponse(url=f"/payment?user_id={user_id}", status_code=303)

@app.get("/payment", response_class=HTMLResponse)
async def payment_page(user_id: str):
    content = f"""
<div class="hero">
    <h1>💰 План продаж — 490 ₽</h1>
</div>
<div class="form-card">
    <h3>Что вы получите:</h3>
    <ul style="margin-left: 20px; margin-bottom: 20px;">
        <li>✅ Разбор 5 конкурентов</li>
        <li>✅ Готовую воронку продаж</li>
        <li>✅ Пошаговый план запуска продаж на месяц (что делать каждую неделю)</li>
        <li>✅ Скрипты для продаж</li>
    </ul>
    <div style="text-align: center; margin: 30px 0;">
        <a href="{PAYMENT_URL}" target="_blank" class="btn">💳 Оплатить 490 ₽</a>
    </div>
    <hr>
    <div style="text-align: center;">
        <p>✅ Уже оплатили?</p>
        <a href="/payment/success?user_id={user_id}" class="btn" style="margin-top: 16px;">→ Я оплатил(а) — получить план</a>
    </div>
</div>
"""
    return HTMLResponse(content=render_page(content, "Оплата"))

@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    phone = row[0] if row else "не указан"
    
    send_telegram_message(f"✅ ПОДТВЕРЖДЕНА ОПЛАТА!\n\nID: {user_id}\nТелефон: {phone}\nСумма: 490 ₽")
    
    # Получаем данные бизнеса и ответы на опрос
    biz = get_business_data(user_id)
    answers = get_form_data(user_id)
    
    if biz and answers and DEEPSEEK_API_KEY:
        # Создаем отчет в фоне
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("INSERT INTO reports (user_id, report_type, status) VALUES (?, 'premium', 'generating')", (user_id,))
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Запускаем фоновую генерацию
        asyncio.create_task(generate_premium_report_background(user_id, biz["name"], biz["description"], answers, report_id))
        
        # Ждем немного и показываем страницу с сообщением о генерации
        content = f"""
<div class="hero">
    <h1>🎉 Спасибо за покупку!</h1>
</div>
<div class="form-card">
    <p>Ваш план продаж генерируется. Это займет около 5 минут.</p>
    <p>Как только план будет готов, он появится здесь:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/payment/check/{user_id}" class="btn">→ Проверить статус</a>
    </div>
</div>
"""
    else:
        # Запасной вариант
        premium_text = f"""
План продаж для вашего бизнеса

1. ОЦЕНКА СИТУАЦИИ
Ваш бизнес имеет потенциал для роста. Основные точки роста: ...

2. АНАЛИЗ КОНКУРЕНТОВ
- Конкурент 1: ...
- Конкурент 2: ...
- Конкурент 3: ...

3. ВОРОНКА ПРОДАЖ
Шаг 1: ...
Шаг 2: ...
Шаг 3: ...

4. ПЛАН ДЕЙСТВИЙ НА МЕСЯЦ
Неделя 1: ...
Неделя 2: ...
Неделя 3: ...
Неделя 4: ...
"""
        save_report(user_id, "premium", premium_text)
        
        content = f"""
<div class="hero">
    <h1>🎉 Спасибо за покупку!</h1>
</div>
<div class="form-card">
    <p>Ваш план продаж готов к скачиванию:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/download/{user_id}/premium" class="btn">📄 Скачать план продаж (.txt)</a>
    </div>
    <hr>
    <h2>👩‍💼 Хотите разобрать план вместе со мной?</h2>
    <p>Прочитали план? Отлично! А теперь давай начистоту: сможешь внедрить всё сама? Я знаю эту боль — информации много, а результата нет.</p>
    <p>Поэтому я предлагаю 30-минутный разбор твоего плана:</p>
    <ul style="margin-left: 20px; margin-bottom: 20px;">
        <li>✅ Я найду ТВОЁ одно действие, которое принесёт деньги прямо сейчас</li>
        <li>✅ Никакой воды — только то, что сработает именно в твоей ситуации</li>
    </ul>
    <div style="text-align: center; margin-top: 20px;">
        <a href="/consultation?user_id={user_id}" class="btn">→ Записаться на разбор</a>
    </div>
</div>
"""
    return HTMLResponse(content=render_page(content, "Успех"))

@app.get("/payment/check/{user_id}", response_class=HTMLResponse)
async def payment_check(user_id: str):
    """Проверка статуса генерации премиум отчета"""
    report = get_report(user_id, "premium")
    
    if report and report["status"] == "ready":
        content = f"""
<div class="hero">
    <h1>🎉 План готов!</h1>
</div>
<div class="form-card">
    <p>Ваш план продаж готов к скачиванию:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/download/{user_id}/premium" class="btn">📄 Скачать план продаж (.txt)</a>
    </div>
    <hr>
    <h2>👩‍💼 Хотите разобрать план вместе со мной?</h2>
    <p>Прочитали план? Отлично! А теперь давай начистоту: сможешь внедрить всё сама? Я знаю эту боль — информации много, а результата нет.</p>
    <p>Поэтому я предлагаю 30-минутный разбор твоего плана:</p>
    <ul>
        <li>✅ Я найду ТВОЁ одно действие, которое принесёт деньги прямо сейчас</li>
        <li>✅ Никакой воды — только то, что сработает именно в твоей ситуации</li>
    </ul>
    <div style="text-align: center; margin-top: 20px;">
        <a href="/consultation?user_id={user_id}" class="btn">→ Записаться на разбор</a>
    </div>
</div>
"""
    elif report and report["status"] == "generating":
        content = f"""
<div class="hero">
    <h1>⏳ План генерируется</h1>
</div>
<div class="form-card">
    <p>Ваш план продаж ещё не готов. Обычно это занимает около 5 минут.</p>
    <p>Пожалуйста, обновите страницу через минуту.</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/payment/check/{user_id}" class="btn">→ Обновить</a>
    </div>
</div>
"""
    else:
        content = f"""
<div class="hero">
    <h1>❌ Ошибка</h1>
</div>
<div class="form-card">
    <p>Не удалось сгенерировать план. Пожалуйста, свяжитесь с поддержкой.</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/" class="btn">→ На главную</a>
    </div>
</div>
"""
    return HTMLResponse(content=render_page(content, "Проверка"))

@app.get("/consultation", response_class=HTMLResponse)
async def consultation_page(user_id: str):
    content = f"""
<div class="hero">
    <h1>👩‍💼 Разбор плана продаж — 30 минут</h1>
</div>
<div class="form-card">
    <p>Оставьте заявку — я свяжусь с вами по телефону, который вы указали, чтобы согласовать время.</p>
    <p><strong>Вот что я сделаю на разборе:</strong></p>
    <ul>
        <li>✅ Найду твоё одно действие, которое принесёт деньги прямо сейчас</li>
        <li>✅ Покажу, почему сейчас не продаётся (даже если контент хороший)</li>
        <li>✅ Дам конкретный план на неделю. Не абстрактный, а под твой бизнес</li>
    </ul>
    <p>Это не консультация «про всё». Это хирургически точный разбор.</p>
    <form action="/consultation/submit" method="post">
        <input type="hidden" name="user_id" value="{user_id}">
        <div class="form-group">
            <label>🕐 Удобное время для созвона (по Москве)</label>
            <input type="text" name="time" placeholder="например: завтра в 15:00" required>
        </div>
        <div style="text-align: center;">
            <button type="submit" class="btn">→ Отправить заявку</button>
        </div>
    </form>
    <p style="text-align: center; font-size: 14px; margin-top: 15px;">После отправки я свяжусь с вами в ближайшее время.</p>
</div>
"""
    return HTMLResponse(content=render_page(content, "Консультация"))

@app.post("/consultation/submit")
async def consultation_submit(user_id: str = Form(...), time: str = Form(...)):
    save_consultation(user_id, time)
    send_telegram_message(f"📞 Новая заявка на консультацию!\n\nID: {user_id}\nВремя: {time}")
    content = """
<div class="hero">
    <h1>✅ Заявка принята!</h1>
</div>
<div class="form-card">
    <p>Я свяжусь с вами в ближайшее время, чтобы подтвердить время.</p>
    <div style="text-align: center; margin-top: 20px;">
        <a href="/" class="btn">→ На главную</a>
    </div>
</div>
"""
    return HTMLResponse(content=render_page(content, "Заявка принята"))

@app.get("/download/{user_id}/{report_type}")
async def download_report(user_id: str, report_type: str):
    report = get_report(user_id, report_type)
    if not report or not report["text"]:
        raise HTTPException(status_code=404, detail="Report not found")
    
    filename = f"{report_type}_{user_id}.txt"
    return Response(
        content=report["text"],
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
