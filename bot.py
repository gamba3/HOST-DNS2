import os
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web
from silent_ghost_module import shadow_scan

BOT_TOKEN = os.environ.get("BOT_TOKEN")
RENDER_EXTERNAL_URL = os.environ.get("RENDER_EXTERNAL_URL")  # ستوفره Render تلقائياً

if not BOT_TOKEN or not RENDER_EXTERNAL_URL:
    raise ValueError("BOT_TOKEN and RENDER_EXTERNAL_URL must be set")

WEBHOOK_PATH = f"/webhook/{BOT_TOKEN}"
WEBHOOK_URL = f"{RENDER_EXTERNAL_URL}{WEBHOOK_PATH}"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# --- Handlers ---
@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    await message.answer("👑 SILENT♕GHOST – Webhook Mode Active\nأرسل الهدف بصيغة domain.com أو ip:port أو http://host:port")

@dp.message()
async def handle_target(message: types.Message):
    target = message.text.strip()
    if not target:
        await message.reply("الرجاء إرسال هدف صالح.")
        return
    status_msg = await message.reply("⏳ جاري فحص الهدف... ستصلك النتائج خلال لحظات.")
    try:
        # تشغيل الفحص في thread منفصل
        result = await asyncio.to_thread(shadow_scan, target)
    except Exception as e:
        result = f"❌ خطأ: {e}"
    # التعامل مع الرسائل الطويلة
    if len(result) <= 4000:
        await status_msg.edit_text(result)
    else:
        await status_msg.edit_text("النتائج طويلة، جاري الإرسال على أجزاء...")
        for i in range(0, len(result), 4000):
            await message.answer(result[i:i+4000])

# --- إعداد تطبيق aiohttp ---
async def on_startup(bot: Bot):
    # تعيين Webhook عند بدء التشغيل
    await bot.set_webhook(WEBHOOK_URL, drop_pending_updates=True)
    logging.info(f"Webhook set to {WEBHOOK_URL}")

async def on_shutdown(bot: Bot):
    await bot.delete_webhook()
    logging.info("Webhook removed")

def main():
    app = web.Application()
    webhook_handler = SimpleRequestHandler(dispatcher=dp, bot=bot)
    webhook_handler.register(app, path=WEBHOOK_PATH)
    setup_application(app, dp, bot=bot)

    # إضافة route أساسي للـ healthcheck (يمنع السبات)
    async def healthcheck(request):
        return web.Response(text="ALIVE")
    app.router.add_get("/", healthcheck)

    app.on_startup.append(lambda app: on_startup(bot))
    app.on_shutdown.append(lambda app: on_shutdown(bot))

    web.run_app(app, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
