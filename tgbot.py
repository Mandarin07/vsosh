import logging
import os
import json
from datetime import datetime
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv
import yaml

# Импорт анализаторов
from static import StaticAnalyzer

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
DOWNLOAD_FOLDER = "downloads"
USERS_FILE = "allowed_users.json"

bot = telebot.TeleBot(BOT_TOKEN)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/tgbot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Загрузка конфига для StaticAnalyzer
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Инициализация анализаторов
static_analyzer = StaticAnalyzer(config)

# Попытка загрузить динамический анализатор
try:
    from dynamic import DynamicAnalyzer
    dynamic_analyzer = DynamicAnalyzer(timeout=30, db_path="logs/dynamic_analysis.db")
    DYNAMIC_ENABLED = True
    logger.info("Dynamic analysis enabled")
except (ImportError, RuntimeError) as e:
    logger.warning(f"Dynamic analysis disabled: {e}")
    dynamic_analyzer = None
    DYNAMIC_ENABLED = False

def escape_markdown(text: str) -> str:
    """Экранирует специальные символы Markdown"""
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, '\\' + char)
    return text

# ==================== USER MANAGEMENT ====================

def load_users():
    """Загрузка пользователей из JSON"""
    if not os.path.exists(USERS_FILE):
        default_data = {
            "users": [],
            "admin": [],
            "privat_admin": [],
            "allowed_groups": []
        }
        save_users(default_data)
        return default_data
    try:
        with open(USERS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return {"users": data, "admin": [], "privat_admin": [], "allowed_groups": []}
            data.setdefault("users", [])
            data.setdefault("admin", [])
            data.setdefault("privat_admin", [])
            data.setdefault("allowed_groups", [])
            return data
    except Exception:
        return {"users": [], "admin": [], "privat_admin": [], "allowed_groups": []}


def save_users(data):
    """Сохранение пользователей в JSON"""
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)


USER_DATA = load_users()
PRIVATE_ADMINS = USER_DATA.get("privat_admin", [])
ADMINS = USER_DATA.get("admin", [])
ALL_USERS = USER_DATA.get("users", [])
ALLOWED_USERS = list(set(PRIVATE_ADMINS + ADMINS))
ALLOWED_GROUPS = USER_DATA.get("allowed_groups", [])


def is_private_admin(user_id: int) -> bool:
    """Проверка, является ли пользователь супер-админом"""
    return user_id in PRIVATE_ADMINS


def has_bot_access(user_id: int) -> bool:
    """Проверка доступа к боту (admin или privat_admin)"""
    return user_id in ALLOWED_USERS


def is_group_allowed(chat_id: int) -> bool:
    """Проверка, разрешена ли группа для использования бота"""
    return chat_id in USER_DATA.get("allowed_groups", [])


def is_group_chat(message) -> bool:
    """Проверка, является ли чат группой"""
    return message.chat.type in ['group', 'supergroup']


def get_user_folder(user_id: int) -> str:
    """Получить папку пользователя"""
    folder = os.path.join(DOWNLOAD_FOLDER, str(user_id))
    os.makedirs(folder, exist_ok=True)
    return folder


def get_group_folder(chat_id: int) -> str:
    """Получить папку для файлов группы"""
    folder = os.path.join(DOWNLOAD_FOLDER, f"group_{abs(chat_id)}")
    os.makedirs(folder, exist_ok=True)
    return folder


def get_file_size(message) -> int:
    """Получить размер файла из сообщения"""
    if message.document:
        return message.document.file_size
    elif message.photo:
        return message.photo[-1].file_size
    elif message.video:
        return message.video.file_size
    elif message.audio:
        return message.audio.file_size
    elif message.voice:
        return message.voice.file_size
    return 0


def check_file_size(file_size: int, max_size: int = 20 * 1024 * 1024) -> tuple[bool, str]:
    """
    Проверить размер файла
    Returns: (is_ok, error_message)
    """
    if file_size > max_size:
        size_mb = file_size / (1024 * 1024)
        max_mb = max_size / (1024 * 1024)
        return False, f"Файл слишком большой: {size_mb:.1f} MB (максимум {max_mb:.0f} MB)"
    return True, ""


# ==================== KEYBOARDS ====================

def main_menu_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Главное меню"""
    markup = InlineKeyboardMarkup()
    markup.row(InlineKeyboardButton("📂 Мои файлы", callback_data="files"))
    if is_private_admin(user_id):
        markup.row(InlineKeyboardButton("🔒 Админ-панель", callback_data="admin_panel"))
    return markup


def admin_keyboard() -> InlineKeyboardMarkup:
    """Меню админ-панели"""
    markup = InlineKeyboardMarkup()
    markup.row(InlineKeyboardButton("➕ Добавить пользователя", callback_data="add_admin_user"))
    markup.row(InlineKeyboardButton("👑 Добавить супер-админа", callback_data="add_private_admin"))
    markup.row(InlineKeyboardButton("🚫 Заблокировать", callback_data="block_user"))
    markup.row(InlineKeyboardButton("👥 Добавить группу", callback_data="add_group"))
    markup.row(InlineKeyboardButton("🗑 Удалить группу", callback_data="remove_group"))
    markup.row(InlineKeyboardButton("📜 Список доступа", callback_data="list_users"))
    markup.row(InlineKeyboardButton("🔙 Назад", callback_data="back_main"))
    return markup


def files_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Список файлов пользователя"""
    markup = InlineKeyboardMarkup()
    folder = get_user_folder(user_id)
    files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
    
    if not files:
        markup.row(InlineKeyboardButton("Список пуст", callback_data="ignore"))
    else:
        for idx, fname in enumerate(files):
            btn_text = fname if len(fname) < 25 else fname[:22] + "..."
            markup.row(InlineKeyboardButton(f"📄 {btn_text}", callback_data=f"file_index:{idx}"))
    
    markup.row(InlineKeyboardButton("🔙 Назад", callback_data="back_main"))
    return markup


def file_actions_keyboard(idx: int, has_dynamic: bool = False) -> InlineKeyboardMarkup:
    """Действия с файлом"""
    markup = InlineKeyboardMarkup()
    if not has_dynamic and DYNAMIC_ENABLED:
        markup.row(InlineKeyboardButton("🔬 Полный анализ", callback_data=f"full_analyze:{idx}"))
    markup.row(InlineKeyboardButton("🔍 Статический анализ", callback_data=f"analyze:{idx}"))
    markup.row(InlineKeyboardButton("🗑 Удалить файл", callback_data=f"delete_file:{idx}"))
    markup.row(InlineKeyboardButton("К списку", callback_data="files"))
    return markup


def group_menu_keyboard() -> InlineKeyboardMarkup:
    """Меню для группы"""
    markup = InlineKeyboardMarkup()
    markup.row(InlineKeyboardButton("📂 Файлы группы", callback_data="group_files"))
    return markup


def group_files_keyboard(chat_id: int) -> InlineKeyboardMarkup:
    """Список файлов группы"""
    markup = InlineKeyboardMarkup()
    folder = get_group_folder(chat_id)
    files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
    
    if not files:
        markup.row(InlineKeyboardButton("Список пуст", callback_data="ignore"))
    else:
        for idx, fname in enumerate(files):
            btn_text = fname if len(fname) < 25 else fname[:22] + "..."
            markup.row(InlineKeyboardButton(f"📄 {btn_text}", callback_data=f"group_file:{idx}"))
    
    markup.row(InlineKeyboardButton("🔙 Назад", callback_data="group_back_main"))
    return markup


def group_file_actions_keyboard(idx: int) -> InlineKeyboardMarkup:
    """Действия с файлом группы"""
    markup = InlineKeyboardMarkup()
    markup.row(InlineKeyboardButton("🔍 Повторный анализ", callback_data=f"group_analyze:{idx}"))
    markup.row(InlineKeyboardButton("🗑 Удалить", callback_data=f"group_delete:{idx}"))
    markup.row(InlineKeyboardButton("К списку", callback_data="group_files"))
    return markup


# ==================== ADMIN PROCESS FUNCTIONS ====================

def process_add_group(message):
    """Добавление разрешенной группы"""
    try:
        group_id = int(message.text.strip())
        
        if group_id >= 0:
            bot.send_message(message.chat.id, "⚠️ ID группы должен быть отрицательным!")
            return
        
        if group_id in ALLOWED_GROUPS:
            bot.send_message(message.chat.id, "Группа уже добавлена")
        else:
            USER_DATA["allowed_groups"].append(group_id)
            ALLOWED_GROUPS.append(group_id)
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"✅ Группа добавлена: `{group_id}`", parse_mode="Markdown")
    except ValueError:
        bot.send_message(message.chat.id, "❌ Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


def process_remove_group(message):
    """Удаление группы из разрешенных"""
    try:
        group_id = int(message.text.strip())
        
        if group_id not in ALLOWED_GROUPS:
            bot.send_message(message.chat.id, "Группа не найдена в списке")
        else:
            USER_DATA["allowed_groups"].remove(group_id)
            ALLOWED_GROUPS.remove(group_id)
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"🗑 Группа удалена: `{group_id}`", parse_mode="Markdown")
    except ValueError:
        bot.send_message(message.chat.id, "❌ Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


def process_add_admin_user(message):
    """Добавление обычного пользователя (доступ к боту без админ-панели)"""
    try:
        new_id = int(message.text.strip())
        
        # Добавляем в общий список users
        if new_id not in USER_DATA["users"]:
            USER_DATA["users"].append(new_id)
            ALL_USERS.append(new_id)
        
        # Добавляем в admin (доступ к боту)
        if new_id in ADMINS:
            bot.send_message(message.chat.id, "Уже имеет доступ")
        else:
            USER_DATA["admin"].append(new_id)
            ADMINS.append(new_id)
            ALLOWED_USERS.append(new_id)
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"✅ Добавлен пользователь: `{new_id}`", parse_mode="Markdown")
    except ValueError:
        bot.send_message(message.chat.id, "Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


def process_add_private_admin(message):
    """Добавление супер-админа (полный доступ)"""
    try:
        new_id = int(message.text.strip())
        
        # Добавляем в общий список users
        if new_id not in USER_DATA["users"]:
            USER_DATA["users"].append(new_id)
            ALL_USERS.append(new_id)
        
        # Добавляем в privat_admin
        if new_id in PRIVATE_ADMINS:
            bot.send_message(message.chat.id, "Уже является супер-админом")
        else:
            USER_DATA["privat_admin"].append(new_id)
            PRIVATE_ADMINS.append(new_id)
            if new_id not in ALLOWED_USERS:
                ALLOWED_USERS.append(new_id)
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"👑 Добавлен супер-админ: `{new_id}`", parse_mode="Markdown")
    except ValueError:
        bot.send_message(message.chat.id, "Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


def process_block_user(message):
    """Блокировка пользователя (убираем доступ к боту)"""
    try:
        block_id = int(message.text.strip())
        
        if block_id in PRIVATE_ADMINS:
            bot.send_message(message.chat.id, "Супер-админа нельзя заблокировать!")
        elif block_id not in ALLOWED_USERS:
            bot.send_message(message.chat.id, "Уже заблокирован или не существует")
        else:
            # Удаляем из admin
            if block_id in USER_DATA["admin"]:
                USER_DATA["admin"].remove(block_id)
            if block_id in ADMINS:
                ADMINS.remove(block_id)
            if block_id in ALLOWED_USERS:
                ALLOWED_USERS.remove(block_id)
            
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"🚫 Заблокирован: `{block_id}`", parse_mode="Markdown")
    except ValueError:
        bot.send_message(message.chat.id, "Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


def process_add_user(message):
    """Добавление пользователя (устаревшая функция, оставлена для совместимости)"""
    try:
        new_id = int(message.text.strip())
        if new_id in ALLOWED_USERS:
            bot.send_message(message.chat.id, "Уже есть")
        else:
            USER_DATA["users"].append(new_id)
            ALLOWED_USERS.append(new_id)
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"✅ Добавлен: `{new_id}`", parse_mode="Markdown")
    except ValueError:
        bot.send_message(message.chat.id, "Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


def process_del_user(message):
    """Удаление пользователя"""
    try:
        del_id = int(message.text.strip())
        if del_id in PRIVATE_ADMINS:
            bot.send_message(message.chat.id, "Супер-админа нельзя удалить")
        elif del_id in ALLOWED_USERS:
            if del_id in USER_DATA["users"]:
                USER_DATA["users"].remove(del_id)
            if del_id in USER_DATA["admin"]:
                USER_DATA["admin"].remove(del_id)
            if del_id in ADMINS:
                ADMINS.remove(del_id)
            ALLOWED_USERS.remove(del_id)
            save_users(USER_DATA)
            bot.send_message(message.chat.id, f"🗑 Удален: `{del_id}`", parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id, "Нет такого ID")
    except ValueError:
        bot.send_message(message.chat.id, "Ошибка! Нужно число")
    
    bot.send_message(message.chat.id, "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.", reply_markup=main_menu_keyboard(message.from_user.id))


# ==================== ANALYSIS FUNCTIONS ====================

def run_static_analysis(file_path: str) -> dict:
    """Запуск статического анализа"""
    try:
        result = static_analyzer.run(file_path)
        return result
    except Exception as e:
        logger.error(f"Static analysis error: {e}", exc_info=True)
        return {"error": str(e), "verdict": "ERROR"}

def run_dynamic_analysis(file_path: str) -> dict:
    """Запуск динамического анализа"""
    if not DYNAMIC_ENABLED or dynamic_analyzer is None:
        return {"error": "Dynamic analysis not available"}
    try:
        result = dynamic_analyzer.run(file_path)
        return result
    except Exception as e:
        logger.error(f"Dynamic analysis error: {e}", exc_info=True)
        return {"error": str(e)}


def format_analysis_report(static_result: dict, dynamic_result: dict = None, filename: str = "") -> str:
    """Форматирование отчета анализа"""
    verdict = static_result.get("verdict", "UNKNOWN")
    score = static_result.get("score", 0)
    
    emoji_map = {
        "CLEAN": "✅",
        "SUSPICIOUS": "⚠️",
        "MALICIOUS": "🚨",
        "UNKNOWN": "❓",
        "ERROR": "❌"
    }
    emoji = emoji_map.get(verdict, "❓")
    
    report = f"{emoji} **Анализ файла**\n"
    report += f"📄 `{filename}`\n\n"
    report += f"**Вердикт:** `{verdict}`\n"
    report += f"**Score:** {score}\n\n"
    
    # YARA
    if static_result.get("yara_matches"):
        report += f"**🔍 YARA совпадения:**\n"
        for match in static_result["yara_matches"][:5]:
            report += f"  • `{match}`\n"
        if len(static_result["yara_matches"]) > 5:
            report += f"  _... и еще {len(static_result['yara_matches']) - 5}_\n"
        report += "\n"
    
    # ClamAV
    if static_result.get("clamav", {}).get("infected"):
        report += f"**🦠 ClamAV:** `{static_result['clamav']['signature']}`\n\n"
    
    # Hash
    if static_result.get("hash"):
        report += f"**#️⃣ SHA256:**\n`{static_result['hash']}`\n\n"
    
    # Suspicious imports
    if static_result.get("suspicious_imports"):
        report += f"**⚠️ Подозрительные импорты:**\n"
        for imp in static_result["suspicious_imports"][:5]:
            report += f"  • `{imp}`\n"
        report += "\n"
    
    # Dynamic analysis results
    if dynamic_result and not dynamic_result.get("error"):
        report += "**🔬 Динамический анализ:**\n"
        if dynamic_result.get("network_activity"):
            report += f"  • Сетевая активность: Да\n"
        if dynamic_result.get("file_operations"):
            report += f"  • Файловые операции: {len(dynamic_result['file_operations'])}\n"
        if dynamic_result.get("suspicious_behavior"):
            report += f"  • Подозрительное поведение: Да\n"
    
    return report


# ==================== COMMANDS ====================

@bot.message_handler(commands=["start"])
def cmd_start(message):
    uid = message.from_user.id
    chat_id = message.chat.id
    
    # ========== РЕЖИМ ГРУППЫ ==========
    if is_group_chat(message):
        if chat_id not in ALLOWED_GROUPS:
            bot.reply_to(message, "❌ Группа не авторизована")
            return
        
        bot.send_message(
            chat_id,
            "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.",
            reply_markup=group_menu_keyboard(),
            parse_mode="Markdown"
        )
        return
    
    # ========== РЕЖИМ ЛИЧНЫХ СООБЩЕНИЙ ==========
    if uid not in USER_DATA["users"]:
        USER_DATA["users"].append(uid)
        ALL_USERS.append(uid)
        save_users(USER_DATA)
        logger.info(f"New user added: {uid}")
    
    if uid in ALLOWED_USERS:
        bot.send_message(
            uid,
            "👋 **TBMI Sandbox**\n\nОтправьте файл для быстрой проверки",
            reply_markup=main_menu_keyboard(uid),
            parse_mode="Markdown"
        )
    else:
        bot.send_message(uid, "У вас нет доступа к этому боту")


@bot.message_handler(commands=["groupid"])
def cmd_groupid(message):
    """Показывает ID текущего чата"""
    uid = message.from_user.id
    if uid not in PRIVATE_ADMINS:
        return
    
    chat_id = message.chat.id
    chat_type = message.chat.type
    chat_title = message.chat.title or "Личный чат"
    
    info = f"**Информация о чате:**\n\n"
    info += f"**ID:** `{chat_id}`\n"
    info += f"**Тип:** {chat_type}\n"
    info += f"**Название:** {chat_title}\n"
    
    if chat_id in ALLOWED_GROUPS:
        info += f"**Статус:** ✅ Авторизована\n"
    else:
        info += f"**Статус:** ❌ Не авторизована\n"
    
    bot.reply_to(message, info, parse_mode="Markdown")


@bot.message_handler(commands=["myid"])
def cmd_myid(message):
    """Показывает ID пользователя"""
    uid = message.from_user.id
    bot.reply_to(message, f"Ваш ID: `{uid}`", parse_mode="Markdown")


@bot.message_handler(commands=["admin"])
def cmd_admin(message):
    """Быстрый доступ к админ-панели"""
    uid = message.from_user.id
    if not is_private_admin(uid):
        bot.reply_to(message, "❌ Только для супер-админов")
        return
    
    bot.send_message(
        message.chat.id,
        f"🔒 **Админ-панель**\n\n"
        f"👑 Супер-админов: {len(PRIVATE_ADMINS)}\n"
        f"👤 Пользователей: {len(ADMINS)}\n"
        f"👥 Групп: {len(ALLOWED_GROUPS)}\n"
        f"📊 Всего в базе: {len(ALL_USERS)}",
        reply_markup=admin_keyboard(),
        parse_mode="Markdown"
    )


# ==================== FILE HANDLER ====================

@bot.message_handler(content_types=["document", "photo", "video", "audio", "voice"])
def handle_files(message):
    uid = message.from_user.id
    chat_id = message.chat.id
    
    if is_group_chat(message):
        if chat_id not in ALLOWED_GROUPS:
            logger.info(f"File from unauthorized group {chat_id}")
            return
        
        try:
            file_id = None
            file_name = None
            file_size = get_file_size(message)
            
            # Проверяем размер файла
            is_size_ok, size_error = check_file_size(file_size)
            if not is_size_ok:
                bot.reply_to(message, f"❌ {size_error}\n\n💡 Попробуйте сжать файл или отправить меньшую часть для анализа")
                return
            
            if message.document:
                file_id = message.document.file_id
                file_name = message.document.file_name
            elif message.photo:
                file_id = message.photo[-1].file_id
                file_name = f"photo_{message.photo[-1].file_unique_id}.jpg"
            elif message.video:
                file_id = message.video.file_id
                file_name = message.video.file_name or f"video_{message.video.file_unique_id}.mp4"
            elif message.audio:
                file_id = message.audio.file_id
                file_name = message.audio.file_name or f"audio_{message.audio.file_unique_id}.mp3"
            elif message.voice:
                file_id = message.voice.file_id
                file_name = f"voice_{message.voice.file_unique_id}.ogg"
            
            if not file_id:
                return
            
            status_msg = bot.reply_to(message, "⚡ Быстрая проверка...")
            
            # Скачиваем
            group_folder = get_group_folder(chat_id)
            info = bot.get_file(file_id)
            data = bot.download_file(info.file_path)
            save_path = os.path.join(group_folder, file_name)
            
            with open(save_path, "wb") as f:
                f.write(data)
            
            # Только статический анализ
            # Только статический анализ
            static_result = static_analyzer.run(save_path)
            
            verdict = static_result.get("verdict", "UNKNOWN")
            score = static_result.get("score", 0)
            emoji_map = {
                "CLEAN": "✅",
                "SUSPICIOUS": "⚠️",
                "MALICIOUS": "🚨",
                "UNKNOWN": "❓"
            }
            
            emoji = emoji_map.get(verdict, "❓")
            
            # Экранируем имя файла для Markdown
            safe_filename = escape_markdown(file_name)
            
            report = f"{emoji} **Файл:** {safe_filename}\n\n"
            report += f"**Вердикт:** `{verdict}`\n"
            report += f"**Score:** {score}\n\n"
            
            if static_result.get("yara_matches"):
                yara_list = ', '.join(static_result['yara_matches'][:2])
                report += f"**YARA:** {escape_markdown(yara_list)}\n"
            
            if static_result.get("clamav", {}).get("infected"):
                sig = static_result['clamav']['signature']
                report += f"**ClamAV:** {escape_markdown(sig)}\n"
            
            # Кнопка для динамики
            markup = InlineKeyboardMarkup()
            if DYNAMIC_ENABLED:
                markup.row(InlineKeyboardButton(
                    "🔬 Полный анализ",
                    callback_data=f"group_dynamic:{os.path.basename(save_path)}"
                ))
            
            bot.edit_message_text(
                report,
                chat_id=chat_id,
                message_id=status_msg.message_id,
                parse_mode="Markdown",
                reply_markup=markup
            )

        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Group Telegram API error: {e}", exc_info=True)
            if "file is too big" in str(e):
                bot.reply_to(message, "❌ Файл слишком большой для Telegram API (лимит 20 MB)\n\n💡 Попробуйте сжать файл или разбить на части")
            else:
                bot.reply_to(message, f"❌ Ошибка Telegram API: {e}")
        except Exception as e:
            logger.error(f"Group analysis error: {e}", exc_info=True)
            bot.reply_to(message, f"❌ Ошибка: {e}")
    
    else:
        if uid not in ALLOWED_USERS:
            return
        
        folder = get_user_folder(uid)
        
        try:
            file_id = None
            file_name = None
            file_size = get_file_size(message)
            
            # Проверяем размер файла
            is_size_ok, size_error = check_file_size(file_size)
            if not is_size_ok:
                bot.reply_to(message, f"❌ {size_error}\n\n💡 Попробуйте сжать файл или отправить меньшую часть для анализа")
                return
            
            if message.document:
                file_id = message.document.file_id
                file_name = message.document.file_name
            elif message.photo:
                file_id = message.photo[-1].file_id
                file_name = f"photo_{message.photo[-1].file_unique_id}.jpg"
            elif message.video:
                file_id = message.video.file_id
                file_name = message.video.file_name or f"video_{message.video.file_unique_id}.mp4"
            elif message.audio:
                file_id = message.audio.file_id
                file_name = message.audio.file_name or f"audio_{message.audio.file_unique_id}.mp3"
            elif message.voice:
                file_id = message.voice.file_id
                file_name = f"voice_{message.voice.file_unique_id}.ogg"
            
            if file_id:
                status_msg = bot.reply_to(message, "⏳ Скачиваю и проверяю...")
                
                info = bot.get_file(file_id)
                data = bot.download_file(info.file_path)
                save_path = os.path.join(folder, file_name)
                
                with open(save_path, "wb") as f:
                    f.write(data)
                
                # Статический анализ сразу
                static_result = run_static_analysis(save_path)
                
            verdict = static_result.get("verdict", "UNKNOWN")
            score = static_result.get("score", 0)
            
            # Экранируем имя файла
            safe_filename = escape_markdown(file_name)
            
            report = f"✅ **Файл сохранен:** {safe_filename}\n\n"
            report += f"**📊 Быстрая проверка**\n"
            report += f"Вердикт: `{verdict}`\n"
            report += f"Score: {score}\n\n"
            
            if static_result.get("yara_matches"):
                yara_list = ', '.join(static_result['yara_matches'][:3])
                report += f"YARA: {escape_markdown(yara_list)}\n"
            
            if static_result.get("clamav", {}).get("infected"):
                sig = static_result['clamav']['signature']
                report += f"🚨 ClamAV: {escape_markdown(sig)}\n"
            
            report += f"\n💡 Используйте 'Мои файлы' для полного анализа"
            
            all_files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            idx = all_files.index(file_name) if file_name in all_files else 0
            
            bot.edit_message_text(
                report,
                message.chat.id,
                status_msg.message_id,
                parse_mode="Markdown",
                reply_markup=file_actions_keyboard(idx, has_dynamic=False)
            )

                
        except telebot.apihelper.ApiTelegramException as e:
            logger.error(f"Telegram API error: {e}", exc_info=True)
            if "file is too big" in str(e):
                bot.reply_to(message, "❌ Файл слишком большой для Telegram API (лимит 20 MB)\n\n💡 Попробуйте сжать файл или разбить на части")
            else:
                bot.reply_to(message, f"❌ Ошибка Telegram API: {e}")
        except Exception as e:
            logger.error(f"File handling error: {e}", exc_info=True)
            bot.reply_to(message, f"❌ Ошибка: {e}")


# ==================== CALLBACK HANDLER ====================


# Callback handler
@bot.callback_query_handler(func=lambda c: True)
def on_callback(call):
    uid = call.from_user.id
    
    # Автоматически добавляем в users
    if uid not in USER_DATA["users"]:
        USER_DATA["users"].append(uid)
        ALL_USERS.append(uid)
        save_users(USER_DATA)
    
    if uid not in ALLOWED_USERS:
        bot.answer_callback_query(call.id, "Нет доступа")
        return
    
    data = call.data
    
    if data == "back_main":
        bot.edit_message_text(
            "👋 **TBMI Sandbox**\n\nОтправьте файл для быстрой проверки",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=main_menu_keyboard(uid),
            parse_mode="Markdown"
        )
    
    elif data == "files":
        bot.edit_message_text(
            "📂 **Ваши файлы:**",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=files_keyboard(uid),
            parse_mode="Markdown"
        )
    
    elif data.startswith("file_index:"):
        try:
            idx = int(data.split(":")[1])
            folder = get_user_folder(uid)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            if os.path.exists(real_path):
                size_mb = os.path.getsize(real_path) / (1024 * 1024)
                fsize = f"{size_mb:.2f} MB"
                ts = os.path.getmtime(real_path)
                dt = datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")
            else:
                fsize, dt = "Неизвестно", "Неизвестно"
            
            text = (
                f"**Файл:** `{fname}`\n"
                f"**Размер:** {fsize}\n"
                f"**Загружен:** {dt}\n"
                f"---------------------------\n"
                f"Выберите действие:"
            )
            
            bot.edit_message_text(
                text,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=file_actions_keyboard(idx, has_dynamic=False),
                parse_mode="Markdown"
            )
        except Exception as e:
            logger.error(f"file_index error: {e}")
            bot.answer_callback_query(call.id, "Ошибка")
    
    elif data.startswith("full_analyze:"):
        try:
            idx = int(data.split(":")[1])
            folder = get_user_folder(uid)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            if not DYNAMIC_ENABLED:
                bot.answer_callback_query(call.id, "Динамический анализ недоступен")
                return
            
            bot.edit_message_text(
                f"🔬 Запуск полного анализа `{fname}`\nЭто может занять до {dynamic_analyzer.timeout} секунд...",
                call.message.chat.id,
                call.message.message_id,
                parse_mode="Markdown"
            )
            
            # Сначала статический
            static_result = static_analyzer.run(real_path)
            
            # Потом динамический
            dynamic_result = dynamic_analyzer.run(real_path)
            
            # Комбинированный отчет
            # Экранируем имя файла для Markdown
            safe_fname = escape_markdown(fname)
            report = f"**📁 {safe_fname}**\n\n"
            
            # Статика
            report += f"**📊 Статический анализ:**\n"
            report += f"Вердикт: `{static_result['verdict']}`\n"
            report += f"Score: {static_result['score']}\n"
            
            if static_result.get("yara_matches"):
                yara_escaped = escape_markdown(', '.join(static_result['yara_matches'][:2]))
                report += f"YARA: {yara_escaped}\n"
            
            # Динамика
            report += f"\n**🔬 Динамический анализ:**\n"
            report += f"Вердикт: `{dynamic_result['verdict']}`\n"
            report += f"Threat Score: {dynamic_result['threat_score']}\n"
            report += f"Длительность: {dynamic_result['duration']:.2f}s\n"
            
            if dynamic_result['reasons']:
                report += f"\nПодозрительно:\n"
                for reason in dynamic_result['reasons'][:3]:
                    # Экранируем каждую причину
                    safe_reason = escape_markdown(str(reason))
                    report += f"• {safe_reason}\n"
            
            # Финальный вердикт
            final_score = static_result['score'] + dynamic_result['threat_score']
            if final_score >= 70:
                final_verdict = "🚨 MALICIOUS"
            elif final_score >= 40:
                final_verdict = "⚠️ SUSPICIOUS"
            else:
                final_verdict = "✅ CLEAN"
            
            report += f"\n**Итог:** {final_verdict} (score: {final_score})"
            
            bot.edit_message_text(
                report,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=file_actions_keyboard(idx, has_dynamic=True),
                parse_mode="Markdown"
            )
            
        except Exception as e:
            logger.error(f"Full analysis error: {e}", exc_info=True)
            bot.edit_message_text(
                f"❌ Ошибка полного анализа: {e}",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=files_keyboard(uid)
            )
    
    elif data == "admin_panel":
        if is_private_admin(uid):
            bot.edit_message_text(
                f"🔒 **Админ-панель**\n\n"
                f"Супер-админов: {len(PRIVATE_ADMINS)}\n"
                f"Пользователей: {len(ADMINS)}\n"
                f"Всего в базе: {len(ALL_USERS)}",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=admin_keyboard(),
                parse_mode="Markdown"
            )
        else:
            bot.answer_callback_query(call.id, "Только для супер-админа!")
    
    elif data == "ignore":
        bot.answer_callback_query(call.id)
    
    # ========== GROUP CALLBACKS ==========
    elif data == "group_back_main":
        bot.edit_message_text(
            "👋 **TBMI Sandbox**\n\n"
            "Отправьте файл для автоматического анализа.\n"
            "Используйте кнопку ниже для просмотра истории.",
            call.message.chat.id,
            call.message.message_id,
            reply_markup=group_menu_keyboard(),
            parse_mode="Markdown"
        )
    
    elif data == "group_files":
        chat_id = call.message.chat.id
        bot.edit_message_text(
            "📂 **Файлы группы:**",
            chat_id,
            call.message.message_id,
            reply_markup=group_files_keyboard(chat_id),
            parse_mode="Markdown"
        )
    
    elif data.startswith("group_file:"):
        try:
            idx = int(data.split(":")[1])
            chat_id = call.message.chat.id
            folder = get_group_folder(chat_id)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            if os.path.exists(real_path):
                size_mb = os.path.getsize(real_path) / (1024 * 1024)
                fsize = f"{size_mb:.2f} MB"
                ts = os.path.getmtime(real_path)
                dt = datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")
            else:
                fsize, dt = "Неизвестно", "Неизвестно"
            
            text = (
                f"**Файл:** `{fname}`\n"
                f"**Размер:** {fsize}\n"
                f"**Загружен:** {dt}\n"
                f"---------------------------\n"
                f"Выберите действие:"
            )
            
            bot.edit_message_text(
                text,
                chat_id,
                call.message.message_id,
                reply_markup=group_file_actions_keyboard(idx),
                parse_mode="Markdown"
            )
        except Exception as e:
            logger.error(f"group_file error: {e}")
            bot.answer_callback_query(call.id, "Ошибка")
    
    elif data.startswith("group_dynamic:"):
        try:
            filename = data.split(":", 1)[1]
            chat_id = call.message.chat.id
            folder = get_group_folder(chat_id)
            real_path = os.path.join(folder, filename)
            
            if not os.path.exists(real_path):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            if not DYNAMIC_ENABLED or dynamic_analyzer is None:
                bot.answer_callback_query(call.id, "Динамический анализ недоступен")
                return
            
            bot.edit_message_text(
                f"🔬 Запуск полного анализа `{filename}`\nЭто может занять до {dynamic_analyzer.timeout} секунд...",
                chat_id,
                call.message.message_id,
                parse_mode="Markdown"
            )
            
            # Статический анализ
            static_result = static_analyzer.run(real_path)
            
            # Динамический анализ
            dynamic_result = dynamic_analyzer.run(real_path)
            
            # Комбинированный отчет
            safe_filename = escape_markdown(filename)
            report = f"**📁 {safe_filename}**\n\n"
            
            report += f"**📊 Статический анализ:**\n"
            report += f"Вердикт: `{static_result.get('verdict', 'UNKNOWN')}`\n"
            report += f"Score: {static_result.get('score', 0)}\n"
            
            if static_result.get("yara_matches"):
                yara_list = ', '.join(static_result['yara_matches'][:2])
                report += f"YARA: {escape_markdown(yara_list)}\n"
            
            report += f"\n**🔬 Динамический анализ:**\n"
            report += f"Вердикт: `{dynamic_result.get('verdict', 'UNKNOWN')}`\n"
            report += f"Threat Score: {dynamic_result.get('threat_score', 0)}\n"
            report += f"Длительность: {dynamic_result.get('duration', 0):.2f}s\n"
            
            if dynamic_result.get('reasons'):
                report += f"\nПодозрительно:\n"
                for reason in dynamic_result['reasons'][:3]:
                    # Экранируем каждую причину
                    safe_reason = escape_markdown(str(reason))
                    report += f"• {safe_reason}\n"
            
            # Финальный вердикт
            final_score = static_result.get('score', 0) + dynamic_result.get('threat_score', 0)
            if final_score >= 70:
                final_verdict = "🚨 MALICIOUS"
            elif final_score >= 40:
                final_verdict = "⚠️ SUSPICIOUS"
            else:
                final_verdict = "✅ CLEAN"
            
            report += f"\n**Итог:** {final_verdict} \\(score: {final_score}\\)"
            
            bot.edit_message_text(
                report,
                chat_id,
                call.message.message_id,
                parse_mode="MarkdownV2" if any(c in report for c in ['(', ')']) else "Markdown"
            )
            
        except Exception as e:
            logger.error(f"Group dynamic analysis error: {e}", exc_info=True)
            bot.edit_message_text(
                f"❌ Ошибка полного анализа: {e}",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=group_menu_keyboard()
            )
    
    elif data.startswith("group_analyze:"):
        try:
            idx = int(data.split(":")[1])
            chat_id = call.message.chat.id
            folder = get_group_folder(chat_id)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            bot.edit_message_text(
                f"🔍 Анализ `{fname}`...",
                chat_id,
                call.message.message_id,
                parse_mode="Markdown"
            )
            
            static_result = static_analyzer.run(real_path)
            
            safe_filename = escape_markdown(fname)
            verdict = static_result.get("verdict", "UNKNOWN")
            score = static_result.get("score", 0)
            
            emoji_map = {
                "CLEAN": "✅",
                "SUSPICIOUS": "⚠️",
                "MALICIOUS": "🚨",
                "UNKNOWN": "❓"
            }
            emoji = emoji_map.get(verdict, "❓")
            
            report = f"{emoji} **Файл:** {safe_filename}\n\n"
            report += f"**Вердикт:** `{verdict}`\n"
            report += f"**Score:** {score}\n\n"
            
            if static_result.get("yara_matches"):
                yara_list = ', '.join(static_result['yara_matches'][:3])
                report += f"**YARA:** {escape_markdown(yara_list)}\n"
            
            if static_result.get("clamav", {}).get("infected"):
                sig = static_result['clamav']['signature']
                report += f"**ClamAV:** {escape_markdown(sig)}\n"
            
            markup = InlineKeyboardMarkup()
            if DYNAMIC_ENABLED:
                markup.row(InlineKeyboardButton(
                    "🔬 Полный анализ",
                    callback_data=f"group_dynamic:{fname}"
                ))
            markup.row(InlineKeyboardButton("К списку", callback_data="group_files"))
            
            bot.edit_message_text(
                report,
                chat_id,
                call.message.message_id,
                parse_mode="Markdown",
                reply_markup=markup
            )
            
        except Exception as e:
            logger.error(f"Group analyze error: {e}", exc_info=True)
            bot.answer_callback_query(call.id, f"Ошибка: {e}")
    
    elif data.startswith("group_delete:"):
        try:
            idx = int(data.split(":")[1])
            chat_id = call.message.chat.id
            folder = get_group_folder(chat_id)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            if os.path.exists(real_path):
                os.remove(real_path)
                bot.answer_callback_query(call.id, f"🗑 Удален: {fname}")
            
            bot.edit_message_text(
                "📂 **Файлы группы:**",
                chat_id,
                call.message.message_id,
                reply_markup=group_files_keyboard(chat_id),
                parse_mode="Markdown"
            )
            
        except Exception as e:
            logger.error(f"Group delete error: {e}", exc_info=True)
            bot.answer_callback_query(call.id, f"Ошибка: {e}")
    
    # ========== ADMIN CALLBACKS ==========
    elif data == "add_admin_user":
        if not is_private_admin(uid):
            bot.answer_callback_query(call.id, "Только для супер-админа")
            return
        msg = bot.send_message(call.message.chat.id, "Введите ID пользователя для добавления:")
        bot.register_next_step_handler(msg, process_add_admin_user)
    
    elif data == "add_private_admin":
        if not is_private_admin(uid):
            bot.answer_callback_query(call.id, "Только для супер-админа")
            return
        msg = bot.send_message(call.message.chat.id, "Введите ID нового супер-админа:")
        bot.register_next_step_handler(msg, process_add_private_admin)
    
    elif data == "block_user":
        if not is_private_admin(uid):
            bot.answer_callback_query(call.id, "Только для супер-админа")
            return
        msg = bot.send_message(call.message.chat.id, "Введите ID для блокировки:")
        bot.register_next_step_handler(msg, process_block_user)
    
    elif data == "add_group":
        if not is_private_admin(uid):
            bot.answer_callback_query(call.id, "Только для супер-админа")
            return
        msg = bot.send_message(call.message.chat.id, "Введите ID группы (отрицательное число):")
        bot.register_next_step_handler(msg, process_add_group)
    
    elif data == "remove_group":
        if not is_private_admin(uid):
            bot.answer_callback_query(call.id, "Только для супер-админа")
            return
        msg = bot.send_message(call.message.chat.id, "Введите ID группы для удаления:")
        bot.register_next_step_handler(msg, process_remove_group)
    
    elif data == "list_users":
        if not is_private_admin(uid):
            bot.answer_callback_query(call.id, "Только для супер-админа")
            return
        
        text = "📜 **Список доступа:**\n\n"
        text += f"**👑 Супер-админы ({len(PRIVATE_ADMINS)}):**\n"
        for pid in PRIVATE_ADMINS[:10]:
            text += f"  • `{pid}`\n"
        
        text += f"\n**👤 Пользователи ({len(ADMINS)}):**\n"
        for aid in ADMINS[:10]:
            text += f"  • `{aid}`\n"
        
        text += f"\n**👥 Группы ({len(ALLOWED_GROUPS)}):**\n"
        for gid in ALLOWED_GROUPS[:10]:
            text += f"  • `{gid}`\n"
        
        bot.edit_message_text(
            text,
            call.message.chat.id,
            call.message.message_id,
            reply_markup=admin_keyboard(),
            parse_mode="Markdown"
        )
    
    elif data.startswith("analyze:"):
        try:
            idx = int(data.split(":")[1])
            folder = get_user_folder(uid)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            bot.edit_message_text(
                f"🔍 Анализ `{fname}`...",
                call.message.chat.id,
                call.message.message_id,
                parse_mode="Markdown"
            )
            
            static_result = static_analyzer.run(real_path)
            report = format_analysis_report(static_result, filename=fname)
            
            bot.edit_message_text(
                report,
                call.message.chat.id,
                call.message.message_id,
                reply_markup=file_actions_keyboard(idx, has_dynamic=False),
                parse_mode="Markdown"
            )
            
        except Exception as e:
            logger.error(f"Analyze error: {e}", exc_info=True)
            bot.answer_callback_query(call.id, f"Ошибка: {e}")
    
    elif data.startswith("delete_file:"):
        try:
            idx = int(data.split(":")[1])
            folder = get_user_folder(uid)
            files = sorted([f for f in os.listdir(folder) if not f.startswith(".")])
            
            if not (0 <= idx < len(files)):
                bot.answer_callback_query(call.id, "Файл не найден")
                return
            
            fname = files[idx]
            real_path = os.path.join(folder, fname)
            
            if os.path.exists(real_path):
                os.remove(real_path)
                bot.answer_callback_query(call.id, f"🗑 Удален: {fname}")
            
            bot.edit_message_text(
                "📂 **Ваши файлы:**",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=files_keyboard(uid),
                parse_mode="Markdown"
            )
            
        except Exception as e:
            logger.error(f"Delete file error: {e}", exc_info=True)
            bot.answer_callback_query(call.id, f"Ошибка: {e}")

if __name__ == "__main__":
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    print("TBMI Sandbox Bot запущен")
    logger.info("Bot started")
    bot.infinity_polling()
