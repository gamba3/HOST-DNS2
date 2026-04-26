import os, sys, logging
import asyncio
from aiohttp import web
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from silent_ghost_module import shadow_scan

logging.basicConfig(level=logging.INFO)

BOT_TOKEN = os.environ["BOT_TOKEN"]
RENDER_EXTERNAL_URL = os.environ["RENDER_EXTERNAL_URL"]

WEBHOOK_PATH = f"/webhook/{BOT_TOKEN}"
WEBHOOK_URL = f"{RENDER_EXTERNAL_URL}{WEBHOOK_PATH}"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    await message.answer("👑 جاهز. أرسل الهدف.")

@dp.message()
async def handle_target(message: types.Message):
    target = message.text.strip()
    if not target:
        await message.reply("أرسل هدفاً.")
        return
    status = await message.reply("⏳ جاري الفحص...")
    try:
        result = await asyncio.to_thread(shadow_scan, target)
    except Exception as e:
        # تسجيل الـ traceback الكامل في سجلات Render
        logging.exception("فشل shadow_scan")
        result = f"خطأ: {e}"
    if len(result) <= 4000:
        await status.edit_text(result)
    else:
        await status.edit_text("النتائج طويلة، جاري التقسيم...")
        for i in range(0, len(result), 4000):
            await message.answer(result[i:i+4000])

async def on_startup(bot: Bot):
    await bot.set_webhook(WEBHOOK_URL, drop_pending_updates=True)
    logging.info(f"Webhook set to {WEBHOOK_URL}")

async def on_shutdown(bot: Bot):
    await bot.delete_webhook()

def main():
    app = web.Application()

    async def startup_callback(srv):
        await on_startup(bot)
    async def shutdown_callback(srv):
        await on_shutdown(bot)

    app.on_startup.append(startup_callback)
    app.on_shutdown.append(shutdown_callback)

    webhook_handler = SimpleRequestHandler(dispatcher=dp, bot=bot)
    webhook_handler.register(app, path=WEBHOOK_PATH)
    setup_application(app, dp, bot=bot)

    async def healthcheck(request):
        return web.Response(text="ALIVE")
    app.router.add_get("/", healthcheck)

    web.run_app(app, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))

if __name__ == "__main__":
    main()
