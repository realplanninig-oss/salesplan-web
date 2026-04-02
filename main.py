# File: main.py — веб-приложение Salesplan

import logging
import sqlite3
import os
import requests
import uuid
import re
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
PAYMENT_URL = "https://yookassa.ru/my/i/ac4jwv2G_TJt/l"

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

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, phone TEXT, name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS business_data (user_id TEXT PRIMARY KEY, business_name TEXT, business_description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS forms (user_id TEXT PRIMARY KEY, q1 TEXT, q2 TEXT, q3 TEXT, q4 TEXT, q5 TEXT, q6 TEXT, q7 TEXT, completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, report_type TEXT NOT NULL, report_text TEXT, file_path TEXT, status TEXT DEFAULT 'ready', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, ready_at TIMESTAMP)")
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

def save_form(user_id: str, answers: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO forms (user_id, q1, q2, q3, q4, q5, q6, q7) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (user_id, answers.get("q1"), answers.get("q2"), answers.get("q3"), answers.get("q4"), answers.get("q5"), answers.get("q6"), answers.get("q7")))
    conn.commit()
    conn.close()

def save_report(user_id: str, report_type: str, report_text: str, file_path: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO reports (user_id, report_type, report_text, file_path, status) VALUES (?, ?, ?, ?, 'ready')", (user_id, report_type, report_text, file_path))
    conn.commit()
    conn.close()

def get_report(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT id, report_text, file_path FROM reports WHERE user_id = ? AND report_type = ? ORDER BY created_at DESC LIMIT 1", (user_id, report_type))
    row = cursor.fetchone()
    conn.close()
    return {"id": row[0], "text": row[1], "file_path": row[2]} if row else None

def save_consultation(user_id: str, time: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO consultations (user_id, time) VALUES (?, ?)", (user_id, time))
    conn.commit()
    conn.close()

def save_payment(user_id: str, phone: str):
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

app = FastAPI(title="Salesplan")

def get_base_html(content: str, title: str = "Salesplan") -> str:
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} | Salesplan</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', Helvetica, sans-serif; background: #f5f5f7; color: #1d1d1f; line-height: 1.4; }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; }}
        .hero {{ text-align: center; margin-bottom: 40px; }}
        .hero h1 {{ font-size: 48px; font-weight: 700; background: linear-gradient(135deg, #1d1d1f 0%, #434345 100%); background-clip: text; -webkit-background-clip: text; color: transparent; margin-bottom: 20px; }}
        .hero p {{ font-size: 21px; color: #6e6e73; max-width: 700px; margin: 0 auto; }}
        .features {{ display: flex; flex-wrap: wrap; gap: 30px; justify-content: center; margin-bottom: 40px; }}
        .feature {{ flex: 1; min-width: 250px; background: white; border-radius: 24px; padding: 30px 24px; text-align: center; box-shadow: 0 8px 20px rgba(0,0,0,0.05); }}
        .feature-icon {{ font-size: 44px; margin-bottom: 20px; }}
        .feature h3 {{ font-size: 22px; font-weight: 600; margin-bottom: 12px; }}
        .feature p {{ font-size: 17px; color: #6e6e73; }}
        .btn {{ display: inline-block; background: #007aff; color: white; text-decoration: none; padding: 16px 32px; font-size: 17px; font-weight: 600; border-radius: 14px; border: none; cursor: pointer; transition: background 0.2s ease; }}
        .btn:hover {{ background: #005fc5; }}
        .form-card {{ background: white; border-radius: 28px; padding: 40px; box-shadow: 0 12px 30px rgba(0,0,0,0.08); max-width: 600px; margin: 0 auto; }}
        .form-group {{ margin-bottom: 20px; }}
        input, textarea {{ width: 100%; padding: 16px 18px; font-size: 17px; font-family: inherit; border: 1px solid #d2d2d7; border-radius: 14px; background: #fff; }}
        input:focus, textarea:focus {{ outline: none; border-color: #007aff; box-shadow: 0 0 0 4px rgba(0,122,255,0.1); }}
        .radio-group {{ display: flex; flex-wrap: wrap; gap: 15px; margin-top: 10px; }}
        .radio-group label {{ display: flex; align-items: center; gap: 8px; font-size: 16px; }}
        .footer {{ text-align: center; margin-top: 60px; padding-top: 30px; border-top: 1px solid #d2d2d7; font-size: 14px; color: #8e8e93; }}
        .social-links {{ margin-top: 20px; display: flex; flex-wrap: wrap; justify-content: center; gap: 20px; }}
        .social-links a {{ color: #007aff; text-decoration: none; }}
        @media (max-width: 700px) {{ .hero h1 {{ font-size: 36px; }} .hero p {{ font-size: 18px; }} .form-card {{ padding: 28px; }} }}
    </style>
    <script type="text/javascript">(function(m,e,t,r,i,k,a){{m[i]=m[i]||function(){{(m[i].a=m[i].a||[]).push(arguments)}};m[i].l=1*new Date();for(var j=0;j<document.scripts.length;j++){{if(document.scripts[j].src===r){{return;}}}}k=e.createElement(t),a=e.getElementsByTagName(t)[0],k.async=1,k.src=r,a.parentNode.insertBefore(k,a)}})(window,document,'script','https://mc.yandex.ru/metrika/tag.js','ym');ym(108348240,'init',{{webvisor:true,clickmap:true,trackLinks:true,accurateTrackBounce:true}});</script>
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
    return HTMLResponse(content=get_base_html(content, "Главная"))

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
    return HTMLResponse(content=get_base_html(content, "Опрос"))

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
    
    diagnostic_text = f"""
Диагностика для бизнеса "{business_name}"

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
    
    save_report(user_id, "free", diagnostic_text)
    
    return RedirectResponse(url=f"/diagnostic?user_id={user_id}", status_code=303)

@app.get("/diagnostic", response_class=HTMLResponse)
async def diagnostic(user_id: str):
    biz = get_business_data(user_id)
    report = get_report(user_id, "free")
    
    content = f"""
<div class="hero">
    <h1>✅ Ваша диагностика готова</h1>
</div>
<div class="form-card">
    <p>{report['text'] if report else 'Диагностика временно недоступна'}</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="/download/{user_id}/free" class="btn">📄 Скачать диагностику (.txt)</a>
    </div>
    <hr style="margin: 30px 0;">
    <h2>🔥 Что дальше?</h2>
    <p>Вы получили бесплатный разбор — это только первый шаг. Чтобы реально увеличить продажи, нужен детальный план. Я проанализирую ваш бизнес — это займет всего около 5 минут.</p>
    
    <div style="margin: 20px 0; background: #f5f5f7; padding: 20px; border-radius: 20px;">
        <p><strong>🔥 Психолог Елена</strong> — 7 клиентов за 2 недели, доход с 0 до 180 000 ₽</p>
        <p><strong>🔥 Мастер Фен Шуй Анна</strong> — первый запуск принес 200 000 ₽ при рекламе 30 000 ₽</p>
        <p><strong>🔥 Эксперт по китайскому</strong> — без блога, только таргет и бот, заработала 120 000 ₽ за 2 недели</p>
        <p><strong>🔥 Онлайн-школа</strong> — 2 000 000 ₽ за 2 недели через марафон в ВК</p>
    </div>
    
    <p>Я Вероника, продюсер экспертов. За 8 лет помогла десяткам специалистов выйти на стабильные продажи.</p>
    
    <h3>В детальном плане продаж:</h3>
    <ul>
        <li>✅ Разбор 5 конкурентов — увидите, как их обойти</li>
        <li>✅ Готовая воронка под ваш бизнес</li>
        <li>✅ Пошаговый план на месяц</li>
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
    return HTMLResponse(content=get_base_html(content, "Диагностика"))

@app.post("/payment/create")
async def payment_create(user_id: str = Form(...), phone: str = Form(...)):
    phone = format_phone(phone)
    save_user(user_id, phone, None)
    save_payment(user_id, phone)
    
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
    <ul>
        <li>✅ Разбор 5 конкурентов</li>
        <li>✅ Готовую воронку продаж</li>
        <li>✅ Пошаговый план на месяц</li>
        <li>✅ Скрипты для продаж</li>
    </ul>
    <div style="text-align: center; margin: 20px 0;">
        <a href="{PAYMENT_URL}" target="_blank" class="btn">💳 Оплатить 490 ₽</a>
    </div>
    <hr>
    <div style="text-align: center;">
        <p>✅ Уже оплатили?</p>
        <a href="/payment/success?user_id={user_id}" class="btn">→ Я оплатил(а) — получить план</a>
    </div>
</div>
"""
    return HTMLResponse(content=get_base_html(content, "Оплата"))

@app.get("/payment/success", response_class=HTMLResponse)
async def payment_success(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT phone FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    phone = row[0] if row else "не указан"
    
    send_telegram_message(f"✅ ПОДТВЕРЖДЕНА ОПЛАТА!\n\nID: {user_id}\nТелефон: {phone}\nСумма: 490 ₽")
    
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
    <hr style="margin: 30px 0;">
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
    return HTMLResponse(content=get_base_html(content, "Успех"))

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
    return HTMLResponse(content=get_base_html(content, "Консультация"))

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
    return HTMLResponse(content=get_base_html(content, "Заявка принята"))

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
