# File: main.py — бот Salesplan (версия 10.4: улучшенные промпты, уведомления продюсеру в личку)
# Часть 1/3

import asyncio
import logging
import sqlite3
import os
import json
import traceback
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import asynccontextmanager
from io import StringIO

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
import aiohttp
import requests
import uvicorn

load_dotenv()

# === КОНФИГУРАЦИЯ ===
MAX_BOT_TOKEN = os.getenv("MAX_BOT_TOKEN")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
HELP_URL = os.getenv("HELP_URL", "https://max.ru/u/f9LHodD0cOJp3NEa7OYZr1MKfUuC1hYDyKh2f4HFkfTXT88W3txWaBaFQmU")
PRODUCER_USER_ID = os.getenv("PRODUCER_USER_ID", "24585087")   # ID продюсера – сюда идут уведомления
REVIEWS_URL = os.getenv("REVIEWS_URL", "https://vk.ru/topic-164421538_39653658")

if not MAX_BOT_TOKEN:
    raise RuntimeError("ERROR: MAX_BOT_TOKEN not found in .env")

LOGS_DIR = Path("./logs")
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler(LOGS_DIR / "salesplan_bot.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

DB_PATH = "salesplan_bot.db"

# === СОСТОЯНИЯ ===
STATE_MENU = "menu"
STATE_AWAITING_BUSINESS_NAME = "awaiting_business_name"
STATE_AWAITING_BUSINESS_DESCRIPTION = "awaiting_business_description"
STATE_SURVEY = "survey"
STATE_AI_CHAT = "ai_chat"
STATE_AWAITING_IMPLEMENTATION = "awaiting_implementation"
STATE_AWAITING_FEEDBACK_REASON = "awaiting_feedback_reason"
STATE_AWAITING_CONSULT_PHONE = "awaiting_consult_phone"
STATE_AWAITING_CONSULT_TIME = "awaiting_consult_time"
STATE_AWAITING_CONSULT_COMMENT = "awaiting_consult_comment"

# === CALLBACK DATA ===
CALLBACK_AUDIT = "audit"
CALLBACK_ASK_AI = "ask_ai"
CALLBACK_CHALLENGE_TASK = "challenge_task"
CALLBACK_CHALLENGE_DONE = "challenge_done"
CALLBACK_CHALLENGE_PROGRESS = "challenge_progress"
CALLBACK_IMPLEMENTATION = "implementation"
CALLBACK_MENU = "menu"
CALLBACK_RESET = "reset"
CALLBACK_FEEDBACK_YES = "feedback_yes"
CALLBACK_FEEDBACK_NO = "feedback_no"
CALLBACK_START_SURVEY = "start_survey"
CALLBACK_BOOK_CONSULT = "book_consult"

# === ОПРОСНИК ===
Q1_SERVICE = "q1_service"
Q1_INFO = "q1_info"
Q1_CONSULT = "q1_consult"
Q1_NONE = "q1_none"
Q2_LT5 = "q2_lt5"
Q2_5_20 = "q2_5_20"
Q2_20_50 = "q2_20_50"
Q2_50P = "q2_50p"
Q3_LT10 = "q3_lt10"
Q3_10_50 = "q3_10_50"
Q3_50_200 = "q3_50_200"
Q3_200P = "q3_200p"
Q4_300 = "q4_300"
Q4_500 = "q4_500"
Q4_1M = "q4_1m"
Q4_SCALE = "q4_scale"
Q5_YES = "q5_yes"
Q5_NO = "q5_no"
Q5_PROGRESS = "q5_progress"

SURVEY_QUESTIONS = [
    {"key": "q1", "text": "Что вы продаёте?", "options": [
        (Q1_SERVICE, "Услугу"),
        (Q1_INFO, "Инфопродукт"),
        (Q1_CONSULT, "Консультацию"),
        (Q1_NONE, "Пока не продаю"),
    ]},
    {"key": "q2", "text": "Средний чек (₽)", "options": [
        (Q2_LT5, "до 5 000 ₽"),
        (Q2_5_20, "5 000 - 20 000 ₽"),
        (Q2_20_50, "20 000 - 50 000 ₽"),
        (Q2_50P, "более 50 000 ₽"),
    ]},
    {"key": "q3", "text": "Клиентов в месяц (примерно)", "options": [
        (Q3_LT10, "менее 10"),
        (Q3_10_50, "10-50"),
        (Q3_50_200, "50-200"),
        (Q3_200P, "более 200"),
    ]},
    {"key": "q4", "text": "Цель на 2026", "options": [
        (Q4_300, "300 000 ₽/мес"),
        (Q4_500, "500 000 ₽/мес"),
        (Q4_1M, "1 000 000 ₽/мес"),
        (Q4_SCALE, "Масштабирование"),
    ]},
    {"key": "q5", "text": "Уже есть автоворонка?", "options": [
        (Q5_YES, "Да"),
        (Q5_NO, "Нет"),
        (Q5_PROGRESS, "В разработке"),
    ]},
]

# === БАЗА ДАННЫХ ===
def init_bot_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS user_state (user_id TEXT PRIMARY KEY, state TEXT, data TEXT, updated_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS business_data (user_id TEXT PRIMARY KEY, business_name TEXT, business_description TEXT, created_at TIMESTAMP, reminder_sent_24h BOOLEAN DEFAULT 0, reminder_sent_7d BOOLEAN DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS forms (user_id TEXT PRIMARY KEY, q1 TEXT, q2 TEXT, q3 TEXT, q4 TEXT, q5 TEXT, completed_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, report_type TEXT NOT NULL, report_text TEXT, status TEXT DEFAULT 'generating', created_at TIMESTAMP, ready_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS challenges (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, start_date TIMESTAMP, current_day INTEGER, tasks_completed INTEGER, status TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS challenge_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, challenge_id INTEGER NOT NULL, day_number INTEGER NOT NULL, task_text TEXT NOT NULL, is_completed BOOLEAN, completed_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS chat_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, role TEXT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS deepseek_queries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, query_type TEXT NOT NULL, prompt TEXT, created_at TIMESTAMP)")
    conn.execute("CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, rating INTEGER, reason TEXT, created_at TIMESTAMP)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS consultations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            phone TEXT,
            preferred_time TEXT,
            comment TEXT,
            status TEXT DEFAULT 'new',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        conn.execute("ALTER TABLE business_data ADD COLUMN reminder_sent_24h BOOLEAN DEFAULT 0")
    except: pass
    try:
        conn.execute("ALTER TABLE business_data ADD COLUMN reminder_sent_7d BOOLEAN DEFAULT 0")
    except: pass
    conn.commit()
    conn.close()

init_bot_db()

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
def get_moscow_time():
    return datetime.utcnow() + timedelta(hours=3)

def format_moscow_time(dt=None):
    if dt is None: dt = get_moscow_time()
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def log_event(user_id: str, event_type: str, event_data: str = None):
    logger.info(f"Event: {event_type} | User: {user_id} | Data: {event_data}")

def log_deepseek_query(user_id: str, query_type: str, prompt: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO deepseek_queries (user_id, query_type, prompt) VALUES (?, ?, ?)", (user_id, query_type, prompt))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log DeepSeek query: {e}")

def get_user_state(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT state, data FROM user_state WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return (row[0], json.loads(row[1]) if row[1] else {}) if row else (STATE_MENU, {})

def save_user_state(user_id: str, state: str, data: dict = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO user_state (user_id, state, data, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                 (user_id, state, json.dumps(data or {}, ensure_ascii=False)))
    conn.commit()
    conn.close()

def save_business_data(user_id: str, name: str, description: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO business_data (user_id, business_name, business_description, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                 (user_id, name, description))
    conn.commit()
    conn.close()

def get_business_data(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT business_name, business_description, reminder_sent_24h, reminder_sent_7d FROM business_data WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    if row:
        return {"name": row[0], "description": row[1], "reminder_sent_24h": bool(row[2]), "reminder_sent_7d": bool(row[3])}
    return None

def update_reminder_flags(user_id: str, reminder_24h: bool = None, reminder_7d: bool = None):
    conn = sqlite3.connect(DB_PATH)
    if reminder_24h is not None:
        conn.execute("UPDATE business_data SET reminder_sent_24h = ? WHERE user_id = ?", (reminder_24h, user_id))
    if reminder_7d is not None:
        conn.execute("UPDATE business_data SET reminder_sent_7d = ? WHERE user_id = ?", (reminder_7d, user_id))
    conn.commit()
    conn.close()

def save_form(user_id: str, answers: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO forms (user_id, q1, q2, q3, q4, q5, completed_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                 (user_id, answers.get("q1"), answers.get("q2"), answers.get("q3"), answers.get("q4"), answers.get("q5")))
    conn.commit()
    conn.close()

def get_form(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT q1, q2, q3, q4, q5 FROM forms WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return {"q1": row[0], "q2": row[1], "q3": row[2], "q4": row[3], "q5": row[4]} if row else None

def save_report(user_id: str, report_type: str, report_text: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO reports (user_id, report_type, report_text, status, ready_at) VALUES (?, ?, ?, 'ready', CURRENT_TIMESTAMP)",
                 (user_id, report_type, report_text))
    conn.commit()
    conn.close()

def update_report_status(user_id: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE reports SET status = ?, ready_at = CASE WHEN ? = 'ready' THEN CURRENT_TIMESTAMP ELSE ready_at END WHERE user_id = ? AND report_type = 'premium' AND status != 'ready'",
                 (status, status, user_id))
    conn.commit()
    conn.close()

def get_report(user_id: str, report_type: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT report_text, status FROM reports WHERE user_id = ? AND report_type = ? ORDER BY created_at DESC LIMIT 1", (user_id, report_type)).fetchone()
    conn.close()
    return {"text": row[0], "status": row[1]} if row else None

def save_feedback(user_id: str, rating: int, reason: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO feedback (user_id, rating, reason) VALUES (?, ?, ?)", (user_id, rating, reason))
    conn.commit()
    conn.close()

def save_consultation_request(user_id: str, phone: str, preferred_time: str, comment: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO consultations (user_id, phone, preferred_time, comment) VALUES (?, ?, ?, ?)",
                 (user_id, phone, preferred_time, comment))
    conn.commit()
    conn.close()

# === ОТПРАВКА СООБЩЕНИЙ ===
async def send_message(chat_id: str, text: str, keyboard: list = None):
    url = f"https://platform-api.max.ru/messages?user_id={chat_id}"
    payload = {"text": text}
    if keyboard:
        payload["attachments"] = [{"type": "inline_keyboard", "payload": {"buttons": keyboard}}]
    headers = {"Authorization": MAX_BOT_TOKEN, "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status != 200:
                logger.error(f"send_message failed: {resp.status} - {await resp.text()}")
            return await resp.text()

async def send_long_message(chat_id: str, text: str, keyboard: list = None):
    max_len = 3900
    if len(text) <= max_len:
        await send_message(chat_id, text, keyboard)
        return
    await send_message(chat_id, text[:max_len], None)
    remaining = text[max_len:]
    while remaining:
        part = remaining[:max_len]
        await send_message(chat_id, part, None)
        remaining = remaining[max_len:]
    if keyboard:
        await send_message(chat_id, "⬆️ Продолжение выше. Что дальше?", keyboard)

async def send_callback_answer(callback_id: str, text: str, keyboard: list = None):
    url = f"https://platform-api.max.ru/answers?callback_id={callback_id}"
    payload = {"message": {"text": text}}
    if keyboard:
        payload["message"]["attachments"] = [{"type": "inline_keyboard", "payload": {"buttons": keyboard}}]
    headers = {"Authorization": MAX_BOT_TOKEN, "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status != 200:
                logger.error(f"send_callback_answer failed: {resp.status} - {await resp.text()}")
            return await resp.text()

async def notify_producer(text: str):
    """Отправляет уведомление продюсеру в личный чат."""
    if PRODUCER_USER_ID and PRODUCER_USER_ID != "24585087" and PRODUCER_USER_ID.strip():
        await send_message(PRODUCER_USER_ID, text, None)
    else:
        logger.warning(f"PRODUCER_USER_ID not set or using default, notification not sent: {text[:200]}")

async def send_animation(user_id: str):
    steps = [
        "🔍 Анализируем бизнес...\n\n⏳ 1/4",
        "📊 Изучаем целевую аудиторию...\n\n⏳ 2/4",
        "🎯 Ищем точки роста...\n\n⏳ 3/4",
        "📝 Формируем план...\n\n⏳ 4/4"
    ]
    for step in steps:
        await send_message(user_id, step, None)
        await asyncio.sleep(2)
        # File: main.py — бот Salesplan (версия 10.4: улучшенные промпты, уведомления продюсеру в личку)
# Часть 2/3 — клавиатуры, функции отправки сообщений, анимация, AI-функции

# === КЛАВИАТУРЫ ===
def get_main_menu_keyboard():
    return [
        [{"type": "callback", "text": "📊 Пройти анкету", "payload": CALLBACK_AUDIT}],
        [{"type": "callback", "text": "💬 Задать вопрос AI", "payload": CALLBACK_ASK_AI}],
        [{"type": "callback", "text": "🏆 Челлендж 14 дней", "payload": CALLBACK_CHALLENGE_TASK}],
        [{"type": "callback", "text": "🎯 Записаться к продюсеру", "payload": CALLBACK_BOOK_CONSULT}],
        [{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}]
    ]

def get_after_plan_keyboard():
    return [
        [{"type": "callback", "text": "💬 Задать вопрос AI", "payload": CALLBACK_ASK_AI}],
        [{"type": "callback", "text": "🏆 Начать челлендж 14 дней", "payload": CALLBACK_CHALLENGE_TASK}],
        [{"type": "callback", "text": "🎯 Записаться к продюсеру", "payload": CALLBACK_BOOK_CONSULT}],
        [{"type": "callback", "text": "🔄 Пройти анкету заново", "payload": CALLBACK_AUDIT}],
        [{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}]
    ]

def get_survey_keyboard(question_index: int):
    if question_index >= len(SURVEY_QUESTIONS):
        return None
    q = SURVEY_QUESTIONS[question_index]
    keyboard = [[{"type": "callback", "text": label, "payload": payload}] for payload, label in q["options"]]
    keyboard.append([{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}])
    return keyboard

def get_challenge_with_help_keyboard():
    return [
        [{"type": "callback", "text": "📋 Получить задание", "payload": CALLBACK_CHALLENGE_TASK}],
        [{"type": "callback", "text": "✅ Выполнил задание", "payload": CALLBACK_CHALLENGE_DONE}],
        [{"type": "callback", "text": "📊 Мой прогресс", "payload": CALLBACK_CHALLENGE_PROGRESS}],
        [{"type": "callback", "text": "🎯 Записаться к продюсеру", "payload": CALLBACK_BOOK_CONSULT}],
        [{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}],
        [{"type": "callback", "text": "🏠 Главное меню", "payload": CALLBACK_MENU}]
    ]

def get_ai_keyboard():
    return [
        [{"type": "callback", "text": "🏆 Челлендж 14 дней", "payload": CALLBACK_CHALLENGE_TASK}],
        [{"type": "callback", "text": "🎯 Записаться к продюсеру", "payload": CALLBACK_BOOK_CONSULT}],
        [{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}],
        [{"type": "callback", "text": "🏠 Главное меню", "payload": CALLBACK_MENU}]
    ]

def get_implementation_keyboard():
    return [
        [{"type": "callback", "text": "📞 Оставить заявку", "payload": CALLBACK_IMPLEMENTATION}],
        [{"type": "callback", "text": "🎯 Записаться к продюсеру", "payload": CALLBACK_BOOK_CONSULT}],
        [{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}],
        [{"type": "callback", "text": "🏠 Главное меню", "payload": CALLBACK_MENU}]
    ]

def get_feedback_keyboard():
    return [
        [{"type": "callback", "text": "👍 Полезно!", "payload": CALLBACK_FEEDBACK_YES}],
        [{"type": "callback", "text": "👎 Не помогло", "payload": CALLBACK_FEEDBACK_NO}]
    ]

def get_start_survey_keyboard():
    return [
        [{"type": "callback", "text": "✅ Да, хочу план за 2 минуты", "payload": CALLBACK_START_SURVEY}],
        [{"type": "callback", "text": "🎯 Записаться к продюсеру", "payload": CALLBACK_BOOK_CONSULT}],
        [{"type": "link", "text": "🆘 Помощь / Связаться", "url": HELP_URL}]
    ]

def get_consult_keyboards():
    return {
        "phone": [[{"type": "callback", "text": "Отмена", "payload": CALLBACK_MENU}]],
        "time": [[{"type": "callback", "text": "Отмена", "payload": CALLBACK_MENU}]],
        "comment": [
            [{"type": "callback", "text": "Пропустить", "payload": "skip_comment"}],
            [{"type": "callback", "text": "Отмена", "payload": CALLBACK_MENU}]
        ]
    }

# === DEEPSEEK API (улучшенные промпты) ===
async def call_deepseek_marketing_plan(name: str, description: str, answers: dict, user_id: str = None) -> str:
    if not DEEPSEEK_API_KEY:
        logger.error("DEEPSEEK_API_KEY not configured")
        return None
    
    q1_map = {Q1_SERVICE: "Услугу", Q1_INFO: "Инфопродукт", Q1_CONSULT: "Консультацию", Q1_NONE: "Пока не продаю"}
    q2_map = {Q2_LT5: "до 5000 ₽", Q2_5_20: "5000-20000 ₽", Q2_20_50: "20000-50000 ₽", Q2_50P: "более 50000 ₽"}
    q3_map = {Q3_LT10: "менее 10", Q3_10_50: "10-50", Q3_50_200: "50-200", Q3_200P: "более 200"}
    q4_map = {Q4_300: "300 000 ₽/мес", Q4_500: "500 000 ₽/мес", Q4_1M: "1 000 000 ₽/мес", Q4_SCALE: "масштабирование"}
    q5_map = {Q5_YES: "да", Q5_NO: "нет", Q5_PROGRESS: "в разработке"}
    
    survey_info = f"""
ДАННЫЕ О БИЗНЕСЕ:
• Продаёт: {q1_map.get(answers.get('q1'), 'не указано')}
• Средний чек: {q2_map.get(answers.get('q2'), 'не указано')}
• Клиентов/мес: {q3_map.get(answers.get('q3'), 'не указано')}
• Цель на 2026: {q4_map.get(answers.get('q4'), 'не указано')}
• Автоворонка: {q5_map.get(answers.get('q5'), 'не указано')}
"""
    prompt = f"""Сделай профессиональный маркетинговый план для онлайн-бизнеса.

ДАННЫЕ О БИЗНЕСЕ:
Название: {name}
Описание: {description}
{survey_info}

ВАЖНЫЕ ОГРАНИЧЕНИЯ:
- НЕ используй Instagram, Telegram, WhatsApp, Facebook для продвижения (они не работают в РФ).
- Используй только: VK, Яндекс.Директ, автоворонку в мессенджере MAX.
- Везде, где нужно написать пост, укажи VK.
- Везде, где нужно сделать рассылку или автоворонку, используй MAX.
- Везде, где нужно настроить рекламу, используй Яндекс.Директ.

Требования к плану:
- Только факты и конкретные шаги. Без воды.
- Не пиши «проанализируйте», «подумайте», «изучите». Только действия.
- Приведи 1-2 реальных примера из смежных ниш.
- Не используй форматирование (*, #, _).
- Для списков используй дефис.

Структура:
1. РЕАЛЬНОСТЬ (коротко, 2-3 предложения)
2. КОНКУРЕНТЫ (2-3 имени + их фишки в VK/MAX)
3. ТВОЙ КЛИЕНТ (боли, возражения, где ищет в VK)
4. СИЛЬНЫЕ И СЛАБЫЕ СТОРОНЫ (3 и 3)
5. ВОРОНКА (пошагово, от первого касания в VK до оплаты через MAX)
6. ПЛАН НА МЕСЯЦ (по неделям, с конкретными задачами)
"""
    if user_id:
        log_deepseek_query(user_id, "marketing_plan", prompt)
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "deepseek-chat",
        "messages": [{"role": "system", "content": "Ты — профессиональный бизнес-консультант. Даёшь только конкретные действия, без общих фраз."}, {"role": "user", "content": prompt}],
        "temperature": 0.5,
        "max_tokens": 4000
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=120)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            logger.error(f"DeepSeek error: {response.status_code}")
            return None
    except Exception as e:
        logger.error(f"DeepSeek failed: {e}")
        return None

async def call_deepseek_chat(question: str, user_id: str, report_text: str, history: list) -> str:
    history_text = ""
    for msg in history[-5:]:
        role = "Пользователь" if msg["role"] == "user" else "Вероника"
        history_text += f"{role}: {msg['message']}\n"
    
    prompt = f"""Ты — профессиональный бизнес-консультант.
Вот маркетинговый план пользователя:
{report_text[:3000]}
История диалога:
{history_text}
Теперь пользователь спрашивает:
{question}

ВАЖНЫЕ ОГРАНИЧЕНИЯ:
- НЕ предлагай Telegram, Instagram, WhatsApp. Только VK, Яндекс.Директ, MAX.

Ответь в деловом, практичном стиле, без воды. Если вопрос сложный (просит настроить рекламу, сделать воронку) — скажи: «🔥 Это задача для профессионального внедрения. Оставь заявку, я свяжусь с тобой»."""
    log_deepseek_query(user_id, "chat_question", prompt)
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "deepseek-chat",
        "messages": [{"role": "system", "content": "Ты — бизнес-консультант. Отвечай только по делу, без общих фраз."}, {"role": "user", "content": prompt}],
        "temperature": 0.5,
        "max_tokens": 1000
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            return "Ой, что-то пошло не так. Попробуй переформулировать вопрос."
    except Exception as e:
        logger.error(f"DeepSeek chat failed: {e}")
        return "Не могу ответить сейчас. Попробуй позже."

async def generate_challenge_task(user_id: str, day: int, report_text: str) -> str:
    if not DEEPSEEK_API_KEY:
        return f"""ЗАДАНИЕ ДЕНЬ {day}

Напиши пост в VK о своей экспертизе (300-500 символов) с призывом оставить комментарий «хочу».

КАК СДЕЛАТЬ:
1. Открой VK и перейди в свой блог.
2. Опиши одну проблему клиента и как ты её решаешь.
3. В конце напиши: «Напиши "хочу" в комментариях, если тоже сталкивался с этим».
4. Опубликуй и ответь всем.

ПОЧЕМУ ЭТО ВАЖНО:
Комментарии поднимают пост в ленте и дают первых лидов."""
    
    prompt = f"""Ты — бизнес-наставник. Твоя задача — дать пользователю ОДНО конкретное действие, которое приблизит его к первой продаже.

Вот маркетинговый план пользователя (первые 3000 символов):
{report_text[:3000]}

Сегодня день {day} из 14.

ВАЖНЫЕ ОГРАНИЧЕНИЯ:
- НЕ предлагай Telegram, Instagram, WhatsApp. Только VK, Яндекс.Директ, MAX.
- Действие должно занимать не более 2 часов.
- Фокус: привлечение первых клиентов через VK, запуск автоворонки в MAX, или настройка объявления в Яндекс.Директе.

Правила:
1. Дай ТОЛЬКО ОДНО действие (не список, не чек-лист).
2. Опиши КАК ИМЕННО это сделать — пошагово, но в одном абзаце.
3. Не используй маркированные списки (дефисы, звёздочки, цифры с точкой).
4. Не пиши «изучи план», «напиши идеи» — только конкретные действия.

Пример хорошего задания для эксперта:
«Напиши пост для VK на 500-700 символов о проблеме, которую решает твой продукт. Используй структуру: боль клиента → последствия → твоё решение → призыв написать в личку. Опубликуй в 2-х профильных группах и в своём блоге.»

Пример плохого задания:
«Изучи свой план и найди 3 идеи для продвижения. Запиши их. Сделай чек-лист.»

Формат ответа (строго, без лишних символов):
ЗАДАНИЕ ДЕНЬ {day}

[Одно предложение с действием]

КАК СДЕЛАТЬ:
[2-3 предложения с конкретными шагами]

ПОЧЕМУ ЭТО ВАЖНО:
[Одно предложение]"""
    
    log_deepseek_query(user_id, "challenge_task", prompt)
    
    url = "https://api.deepseek.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "deepseek-chat",
        "messages": [{"role": "system", "content": "Ты — бизнес-наставник. Даёшь только одно конкретное действие, без списков и чек-листов."}, {"role": "user", "content": prompt}],
        "temperature": 0.3,
        "top_p": 0.9,
        "max_tokens": 600
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)
        if response.status_code == 200:
            task_text = response.json()["choices"][0]["message"]["content"]
            # Постобработка: убираем лишние маркеры
            task_text = clean_task_response(task_text, day)
            return task_text
        else:
            return fallback_challenge_task(day)
    except Exception as e:
        logger.error(f"Generate task error: {e}")
        return fallback_challenge_task(day)

def clean_task_response(text: str, day: int) -> str:
    """Убирает маркированные списки, лишние дефисы, звёздочки."""
    import re
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        # Убираем маркированные списки в начале строки
        if re.match(r'^\s*[-*•]\s+', line):
            continue
        if re.match(r'^\s*\d+\.\s+', line):
            continue
        # Убираем звёздочки и лишние пробелы
        line = re.sub(r'[*_~`]', '', line)
        # Убираем дефисы, которые не являются частью слов
        line = re.sub(r'^- ', '', line)
        cleaned.append(line)
    result = '\n'.join(cleaned)
    # Проверяем, что результат не слишком короткий
    if len(result.strip()) < 80 or "ЗАДАНИЕ" not in result:
        return fallback_challenge_task(day)
    return result

def fallback_challenge_task(day: int) -> str:
    return f"""ЗАДАНИЕ ДЕНЬ {day}

Создай пост в VK: опиши одну из проблем твоих клиентов и предложи решение.

КАК СДЕЛАТЬ:
Открой VK, напиши пост на 300–500 слов. Заголовок: «Почему вы теряете деньги?» В конце добавь призыв: «Напиши "разбор" в комментариях — сделаю бесплатный разбор твоей ситуации». Опубликуй и ответь первым трём комментаторам.

ПОЧЕМУ ЭТО ВАЖНО:
Это даст тебе заявки и обратную связь от целевой аудитории."""

# === ФУНКЦИИ ДЛЯ ЧАТА И ЧЕЛЛЕНДЖА ===
def save_chat_message(user_id: str, role: str, message: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO chat_history (user_id, role, message) VALUES (?, ?, ?)", (user_id, role, message))
    conn.commit()
    conn.close()

def get_chat_history(user_id: str, limit: int = 10) -> list:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT role, message FROM chat_history WHERE user_id = ? ORDER BY created_at ASC LIMIT ?", (user_id, limit)).fetchall()
    conn.close()
    return [{"role": r[0], "message": r[1]} for r in rows]

def get_active_challenge(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT id, current_day, tasks_completed, status FROM challenges WHERE user_id = ? AND status = 'active' ORDER BY start_date DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()
    return {"id": row[0], "current_day": row[1], "tasks_completed": row[2]} if row else None

def start_new_challenge(user_id: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("INSERT INTO challenges (user_id, start_date, current_day, tasks_completed, status) VALUES (?, CURRENT_TIMESTAMP, 1, 0, 'active')", (user_id,))
    conn.commit()
    return cursor.lastrowid

def save_challenge_task(challenge_id: int, day_number: int, task_text: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO challenge_tasks (challenge_id, day_number, task_text) VALUES (?, ?, ?)", (challenge_id, day_number, task_text))
    conn.commit()
    conn.close()

def get_current_task(challenge_id: int, day_number: int):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT id, task_text, is_completed FROM challenge_tasks WHERE challenge_id = ? AND day_number = ?", (challenge_id, day_number)).fetchone()
    conn.close()
    return {"id": row[0], "task_text": row[1], "is_completed": bool(row[2])} if row else None

def mark_task_completed(challenge_id: int, day_number: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE challenge_tasks SET is_completed = 1, completed_at = CURRENT_TIMESTAMP WHERE challenge_id = ? AND day_number = ?", (challenge_id, day_number))
    conn.execute("UPDATE challenges SET tasks_completed = tasks_completed + 1 WHERE id = ?", (challenge_id,))
    conn.commit()
    conn.close()

def advance_challenge_day(challenge_id: int, new_day: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE challenges SET current_day = ? WHERE id = ?", (new_day, challenge_id))
    conn.commit()
    conn.close()

def complete_challenge(challenge_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE challenges SET status = 'completed' WHERE id = ?", (challenge_id,))
    conn.commit()
    conn.close()
    # File: main.py — бот Salesplan (версия 10.4: улучшенные промпты, уведомления продюсеру в личку)
# Часть 3/3 — обработчики, напоминания, FastAPI, запуск

# === ОБРАБОТЧИК СООБЩЕНИЙ ===
async def process_message(user_id: str, text: str):
    state, data = get_user_state(str(user_id))

    # Команда /stats (только для продюсера)
    if text == "/stats":
        if str(user_id) != PRODUCER_USER_ID:
            await send_message(str(user_id), "❌ У вас нет доступа к этой команде.", None)
            return
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("""
            SELECT id, user_id, query_type, substr(prompt, 1, 100) as preview, created_at
            FROM deepseek_queries ORDER BY created_at DESC LIMIT 30
        """).fetchall()
        conn.close()
        if not rows:
            await send_message(str(user_id), "📭 Пока нет запросов к DeepSeek.", None)
            return
        msg = "📊 Последние 30 запросов:\n\n"
        for r in rows:
            msg += f"#{r[0]} | {r[1]} | {r[2]} | {r[3][:50]}... | {r[4]}\n"
        await send_long_message(str(user_id), msg, None)
        return

    if text == "/start":
        save_user_state(str(user_id), STATE_MENU, {})
        await send_message(str(user_id),
            "👋 Привет! Я Вероника, продюсер экспертов.\n\n"
            "Хотите маркетинговый план или записаться на консультацию?",
            get_start_survey_keyboard())
        return

    # Состояние сбора номера для консультации
    if state == STATE_AWAITING_CONSULT_PHONE:
        if len(text) < 5 or not re.search(r'[\d\+]', text):
            await send_message(str(user_id), "Введите корректный номер телефона (например, +7 123 456-78-90):")
            return
        save_user_state(str(user_id), STATE_AWAITING_CONSULT_TIME, {"phone": text})
        await send_message(str(user_id), "Укажите удобное время для звонка (например, 'завтра в 15:00' или 'среда после 18:00'):", get_consult_keyboards()["time"])
        return

    if state == STATE_AWAITING_CONSULT_TIME:
        new_data = data.copy()
        new_data["time"] = text
        save_user_state(str(user_id), STATE_AWAITING_CONSULT_COMMENT, new_data)
        await send_message(str(user_id), "Если есть комментарий к вашему запросу, напишите его (или нажмите 'Пропустить'):", get_consult_keyboards()["comment"])
        return

    if state == STATE_AWAITING_CONSULT_COMMENT:
        comment = text if text != "skip_comment" else None
        phone = data.get("phone")
        pref_time = data.get("time")
        save_consultation_request(str(user_id), phone, pref_time, comment)
        # Уведомление продюсеру в личку
        await notify_producer(
            f"📞 НОВАЯ ЗАЯВКА НА КОНСУЛЬТАЦИЮ\n\n"
            f"Пользователь: {user_id}\n"
            f"Телефон: {phone}\n"
            f"Время: {pref_time}\n"
            f"Комментарий: {comment or '—'}\n"
            f"⏰ {format_moscow_time()}"
        )
        await send_message(str(user_id),
            "✅ Заявка принята! Продюсер свяжется с вами в ближайшее время.\n\n"
            "А пока можете изучить маркетинговый план или задать вопрос AI.",
            get_main_menu_keyboard())
        save_user_state(str(user_id), STATE_MENU, {})
        return

    # Состояния анкеты и бизнеса
    if state == STATE_AWAITING_BUSINESS_NAME:
        if len(text) > 100:
            await send_message(str(user_id), "Название слишком длинное, сократите (до 100 символов):")
            return
        save_user_state(str(user_id), STATE_AWAITING_BUSINESS_DESCRIPTION, {"business_name": text})
        await send_message(str(user_id), "Отлично! Теперь опишите бизнес кратко (что делаете, кому помогаете, какая ваша уникальность):")
        return

    if state == STATE_AWAITING_BUSINESS_DESCRIPTION:
        if len(text) > 500:
            await send_message(str(user_id), "Описание слишком длинное, сократите до 500 символов:")
            return
        name = data.get("business_name")
        save_business_data(str(user_id), name, text)
        save_user_state(str(user_id), STATE_SURVEY, {"answers": {}, "survey_step": 0})
        await send_message(str(user_id), SURVEY_QUESTIONS[0]["text"], get_survey_keyboard(0))
        return

    if state == STATE_AI_CHAT:
        report = get_report(str(user_id), "premium")
        if not report or report["status"] != "ready":
            await send_message(str(user_id),
                "💬 Сначала пройдите анкету и получите маркетинговый план.",
                [[{"type": "callback", "text": "📊 Пройти анкету", "payload": CALLBACK_AUDIT}]])
            save_user_state(str(user_id), STATE_MENU, {})
            return
        save_chat_message(str(user_id), "user", text)
        hard_keywords = ["настрой", "сделай", "запусти", "воронку", "таргет", "внедрение", "помоги сделать", "напиши скрипт", "яндекс директ", "настрой рекламу"]
        if any(kw in text.lower() for kw in hard_keywords):
            answer = "🔥 Это задача для профессионального внедрения. Если хотите сделать это правильно — оставьте заявку, и я свяжусь с вами.\n\n👇 Нажмите кнопку ниже."
            await send_message(str(user_id), answer, get_implementation_keyboard())
        else:
            await send_message(str(user_id), "🤔 Думаю...", None)
            history = get_chat_history(str(user_id), 10)
            answer = await call_deepseek_chat(text, str(user_id), report["text"], history)
            answer += "\n\n📜 *Листай вверх к началу плана*"
            await send_message(str(user_id), answer, get_ai_keyboard())
        save_chat_message(str(user_id), "assistant", answer)
        return

    if state == STATE_AWAITING_IMPLEMENTATION:
        await notify_producer(
            f"📞 ЗАЯВКА НА ВНЕДРЕНИЕ\n\n"
            f"Пользователь: {user_id}\n"
            f"Запрос: {text}\n"
            f"⏰ {format_moscow_time()}"
        )
        await send_message(str(user_id), "✅ Заявка принята! Продюсер свяжется с вами в ближайшее время.", get_main_menu_keyboard())
        save_user_state(str(user_id), STATE_MENU, {})
        return

    if state == STATE_AWAITING_FEEDBACK_REASON:
        save_feedback(str(user_id), 0, text)
        await send_message(str(user_id),
            "Спасибо за честность! Учту и улучшу сервис.\n\n"
            "Попробуете пройти анкету заново или записаться на консультацию?",
            get_start_survey_keyboard())
        save_user_state(str(user_id), STATE_MENU, {})
        return

    # Если состояние не распознано или пользователь написал что-то неожиданное
    save_user_state(str(user_id), STATE_MENU, {})
    await send_message(str(user_id),
        "👋 Я Вероника, продюсер экспертов. Выберите действие:",
        get_start_survey_keyboard())

# === ОБРАБОТЧИК КОЛБЭКОВ ===
async def process_callback(chat_id: str, callback_id: str, callback_data: str):
    state, user_data = get_user_state(chat_id)

    if callback_data == CALLBACK_MENU:
        save_user_state(chat_id, STATE_MENU, {})
        await send_callback_answer(callback_id, "🏠 Главное меню", get_main_menu_keyboard())
        return

    if callback_data == CALLBACK_START_SURVEY:
        save_user_state(chat_id, STATE_AWAITING_BUSINESS_NAME, {})
        await send_callback_answer(callback_id,
            "🚀 Отлично! Напишите название вашего проекта (как вы представляете его клиентам):",
            None)
        return

    if callback_data == CALLBACK_RESET:
        save_user_state(chat_id, STATE_MENU, {})
        await send_callback_answer(callback_id,
            "Начнём сначала. Хотите маркетинговый план или записаться на консультацию?",
            get_start_survey_keyboard())
        return

    if callback_data == CALLBACK_AUDIT:
        if state in (STATE_SURVEY, STATE_AWAITING_BUSINESS_NAME, STATE_AWAITING_BUSINESS_DESCRIPTION):
            await send_callback_answer(callback_id,
                "⚠️ Анкета уже запущена. Если хотите начать заново — нажмите кнопку ниже.",
                [[{"type": "callback", "text": "🔄 Начать заново", "payload": CALLBACK_RESET}]])
            return
        save_user_state(chat_id, STATE_AWAITING_BUSINESS_NAME, {})
        await send_callback_answer(callback_id, "Введите название вашего проекта:", None)
        return

    if callback_data == CALLBACK_ASK_AI:
        report = get_report(chat_id, "premium")
        if not report or report["status"] != "ready":
            await send_callback_answer(callback_id,
                "💬 Сначала пройдите анкету и получите план.",
                [[{"type": "callback", "text": "📊 Пройти анкету", "payload": CALLBACK_AUDIT}]])
            return
        save_user_state(chat_id, STATE_AI_CHAT, {})
        await send_callback_answer(callback_id,
            "💬 Задавайте любые вопросы по вашему маркетинговому плану. Я на связи 24/7.",
            None)
        return

    if callback_data == CALLBACK_BOOK_CONSULT:
        save_user_state(chat_id, STATE_AWAITING_CONSULT_PHONE, {})
        await send_callback_answer(callback_id,
            "📞 Для записи на консультацию укажите ваш номер телефона:",
            get_consult_keyboards()["phone"])
        return

    if callback_data == CALLBACK_FEEDBACK_YES:
        save_feedback(chat_id, 1)
        await send_callback_answer(callback_id,
            "✨ Рад, что помогло! Если нужен полный план действий или консультация — кнопки ниже.",
            get_after_plan_keyboard())
        return

    if callback_data == CALLBACK_FEEDBACK_NO:
        await send_callback_answer(callback_id,
            "🤔 Мне жаль, что не помогло. Напишите кратко (2-3 слова), чего не хватило:",
            None)
        save_user_state(chat_id, STATE_AWAITING_FEEDBACK_REASON, {})
        return

    if callback_data == CALLBACK_IMPLEMENTATION:
        save_user_state(chat_id, STATE_AWAITING_IMPLEMENTATION, {})
        await send_callback_answer(callback_id,
            "🔥 Расскажите, что именно нужно внедрить (воронка, настройка рекламы, скрипты и т.д.), и я передам продюсеру.",
            None)
        return

    # Челлендж
    if callback_data == CALLBACK_CHALLENGE_TASK:
        report = get_report(chat_id, "premium")
        if not report or report["status"] != "ready":
            await send_callback_answer(callback_id,
                "🏆 Челлендж доступен после получения плана.",
                [[{"type": "callback", "text": "📊 Пройти анкету", "payload": CALLBACK_AUDIT}]])
            return
        challenge = get_active_challenge(chat_id)
        if not challenge:
            cid = start_new_challenge(chat_id)
            task_text = await generate_challenge_task(chat_id, 1, report["text"])
            save_challenge_task(cid, 1, task_text)
            await send_callback_answer(callback_id,
                f"🏆 Челлендж «Первые клиенты за 14 дней» начался!\n\n{task_text}\n\n"
                f"👇 Когда сделаете — нажмите «Выполнил задание»",
                get_challenge_with_help_keyboard())
        else:
            current = get_current_task(challenge["id"], challenge["current_day"])
            if current and not current["is_completed"]:
                await send_callback_answer(callback_id,
                    f"📋 Задание дня {challenge['current_day']}:\n\n{current['task_text']}\n\n"
                    f"👇 Когда сделаете — нажмите «Выполнил задание»",
                    get_challenge_with_help_keyboard())
            else:
                remaining = 14 - challenge["current_day"]
                await send_callback_answer(callback_id,
                    f"🏆 Прогресс: день {challenge['current_day']} из 14, выполнено {challenge['tasks_completed']} заданий.\n"
                    f"🎯 Осталось дней: {remaining}\n\n"
                    f"Нажмите «Получить задание», чтобы продолжить.",
                    get_challenge_with_help_keyboard())
        return

    if callback_data == CALLBACK_CHALLENGE_DONE:
        challenge = get_active_challenge(chat_id)
        if not challenge:
            await send_callback_answer(callback_id,
                "❌ Нет активного челленджа. Нажмите «Челлендж 14 дней» для старта.",
                get_main_menu_keyboard())
            return
        current = get_current_task(challenge["id"], challenge["current_day"])
        if not current or current["is_completed"]:
            await send_callback_answer(callback_id,
                "✅ Задание на сегодня уже выполнено! Завтра получите новое.",
                get_challenge_with_help_keyboard())
            return
        mark_task_completed(challenge["id"], challenge["current_day"])
        if challenge["current_day"] >= 14:
            complete_challenge(challenge["id"])
            await send_callback_answer(callback_id,
                f"🎉 ПОЗДРАВЛЯЮ! Вы прошли 14-дневный челлендж!\n\n"
                f"✅ Выполнено заданий: {challenge['tasks_completed'] + 1} из 14\n\n"
                f"Теперь вы знаете, как получать клиентов. Если нужен разбор — запишитесь на консультацию.",
                get_after_plan_keyboard())
        else:
            new_day = challenge["current_day"] + 1
            advance_challenge_day(challenge["id"], new_day)
            report = get_report(chat_id, "premium")
            new_task = await generate_challenge_task(chat_id, new_day, report["text"])
            save_challenge_task(challenge["id"], new_day, new_task)
            await send_callback_answer(callback_id,
                f"✅ Отлично! Задание дня {challenge['current_day']} выполнено!\n\n"
                f"🏆 Прогресс: {challenge['tasks_completed'] + 1} заданий\n\n"
                f"💪 ЗАДАНИЕ ДЕНЬ {new_day}\n\n{new_task}\n\n"
                f"👇 Продолжайте в том же духе!",
                get_challenge_with_help_keyboard())
        return

    if callback_data == CALLBACK_CHALLENGE_PROGRESS:
        challenge = get_active_challenge(chat_id)
        if not challenge:
            await send_callback_answer(callback_id,
                "❌ Нет активного челленджа. Нажмите «Челлендж 14 дней» для старта.",
                get_main_menu_keyboard())
            return
        await send_callback_answer(callback_id,
            f"🏆 ТВОЙ ПРОГРЕСС\n\n"
            f"📅 День {challenge['current_day']} из 14\n"
            f"✅ Выполнено: {challenge['tasks_completed']}\n"
            f"🎯 Осталось: {14 - challenge['current_day']}\n\n"
            f"Продолжайте выполнять задания!",
            get_challenge_with_help_keyboard())
        return

    # Обработка ответов на анкету
    if callback_data in [Q1_SERVICE, Q1_INFO, Q1_CONSULT, Q1_NONE, Q2_LT5, Q2_5_20, Q2_20_50, Q2_50P,
                         Q3_LT10, Q3_10_50, Q3_50_200, Q3_200P, Q4_300, Q4_500, Q4_1M, Q4_SCALE,
                         Q5_YES, Q5_NO, Q5_PROGRESS]:
        _, u_data = get_user_state(chat_id)
        if u_data is None:
            u_data = {}
        u_data.setdefault("answers", {})
        u_data.setdefault("survey_step", 0)
        step = u_data["survey_step"]
        if step < len(SURVEY_QUESTIONS):
            key = SURVEY_QUESTIONS[step]["key"]
            u_data["answers"][key] = callback_data
            u_data["survey_step"] = step + 1
            save_user_state(chat_id, STATE_SURVEY, u_data)
            if step + 1 < len(SURVEY_QUESTIONS):
                await send_callback_answer(callback_id, SURVEY_QUESTIONS[step + 1]["text"], get_survey_keyboard(step + 1))
            else:
                save_form(chat_id, u_data["answers"])
                biz = get_business_data(chat_id)
                if not biz:
                    await send_callback_answer(callback_id, "❌ Ошибка, начните заново.", get_main_menu_keyboard())
                    return
                existing = get_report(chat_id, "premium")
                if existing and existing["status"] == "ready":
                    report_text = existing["text"]
                elif existing and existing["status"] == "generating":
                    await send_callback_answer(callback_id, "⏳ План уже генерируется, подождите...", None)
                    return
                else:
                    save_report(chat_id, "premium", "")
                    await send_callback_answer(callback_id, "🔍 Запускаю анализ...", None)
                    await send_animation(chat_id)
                    report_text = await call_deepseek_marketing_plan(biz["name"], biz["description"], u_data["answers"], chat_id)
                    if not report_text:
                        await send_message(chat_id, "❌ Не удалось сгенерировать план. Попробуйте позже.", get_main_menu_keyboard())
                        update_report_status(chat_id, "failed")
                        return
                    save_report(chat_id, "premium", report_text)
                final_text = report_text + "\n\n📜 *Листай вверх к началу плана*"
                await send_long_message(chat_id, "✅ ВАШ МАРКЕТИНГОВЫЙ ПЛАН ГОТОВ!\n\n" + final_text, None)
                await asyncio.sleep(2)
                await send_message(chat_id, "Было полезно? Поделитесь мнением, это поможет улучшить сервис.", get_feedback_keyboard())
        return

    # Если колбэк не распознан
    await send_callback_answer(callback_id, "Неизвестная команда. Используйте главное меню.", get_main_menu_keyboard())

# === ФОНОВАЯ ЗАДАЧА НАПОМИНАНИЙ ===
async def reminders_task():
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("""
                SELECT b.user_id, r.ready_at, b.reminder_sent_24h, b.reminder_sent_7d
                FROM business_data b
                JOIN reports r ON b.user_id = r.user_id AND r.report_type = 'premium' AND r.status = 'ready'
                WHERE (b.reminder_sent_24h = 0 OR b.reminder_sent_7d = 0)
            """).fetchall()
            for user_id, ready_at, sent24, sent7 in rows:
                delta = get_moscow_time() - datetime.fromisoformat(ready_at)
                if not sent24 and delta >= timedelta(hours=24):
                    await send_message(user_id,
                        "📌 Напоминание: у вас есть маркетинговый план. Начните с первого пункта.\n\n"
                        "Если нужна помощь — задайте вопрос AI или запишитесь на консультацию (кнопки в меню).",
                        None)
                    update_reminder_flags(user_id, reminder_24h=True)
                    await asyncio.sleep(2)
                if not sent7 and delta >= timedelta(days=7):
                    await send_message(user_id,
                        "🔥 7 дней прошло! 70% моих клиентов получают первые деньги через 2 недели.\n\n"
                        "Продолжайте внедрять план. Если застряли — запишитесь на консультацию, разберём ваш случай.",
                        None)
                    update_reminder_flags(user_id, reminder_7d=True)
                    await asyncio.sleep(2)
            conn.close()
        except Exception as e:
            logger.error(f"Reminders error: {e}")
        await asyncio.sleep(21600)  # 6 часов

# === FASTAPI ПРИЛОЖЕНИЕ ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Salesplan bot started")
    asyncio.create_task(reminders_task())
    yield
    logger.info("Salesplan bot stopped")

app = FastAPI(title="Salesplan Bot", lifespan=lifespan)

@app.get("/")
async def root():
    return {"status": "Salesplan bot is running", "version": "10.4"}

@app.get("/health")
async def health():
    return {"status": "alive", "timestamp": datetime.now().isoformat()}

@app.post("/webhook")
async def webhook(request: Request):
    try:
        payload = await request.json()
        if "message" in payload and "callback" not in payload:
            msg = payload["message"]
            user_id = msg.get("sender", {}).get("user_id")
            text = msg.get("body", {}).get("text")
            if user_id and text:
                await process_message(str(user_id), text.strip())
        elif "callback" in payload:
            cb = payload["callback"]
            user_id = cb.get("user", {}).get("user_id")
            callback_id = cb.get("callback_id")
            data = cb.get("payload")
            if user_id and data:
                await process_callback(str(user_id), str(callback_id), data)
        return Response(status_code=200)
    except Exception as e:
        logger.error(f"Webhook error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
