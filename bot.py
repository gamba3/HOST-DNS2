import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from silent_ghost_module import shadow_scan

logging.basicConfig(level=logging.INFO)

BOT_TOKEN = "YOUR_BOT_TOKEN"  # سيأتي من متغير البيئة لاحقًا
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    await message.answer("👑 SILENT♕GHOST BOT – أرسل الهدف بصيغة domain.com أو ip:port أو http://host:port")

@dp.message()
async def handle_target(message: types.Message):
    target = message.text.strip()
    if not target:
        await message.reply("الرجاء إرسال هدف صالح.")
        return
    # إعلام المستخدم ببدء المسح
    status_msg = await message.reply("⏳ جاري فحص الهدف... ستصلك النتائج خلال لحظات.")
    try:
        # تشغيل المسح في Thread منفصل لكي لا يتجمد البوت
        result = await asyncio.to_thread(shadow_scan, target)
    except Exception as e:
        result = f"❌ خطأ أثناء الفحص: {e}"
    # تحرير الرسالة إلى النتائج
    # لكن التقرير قد يكون طويلاً، لذا نرسل رسالة جديدة أو عدة رسائل
    # إذا تجاوز الحد 4096، نقسمه
    if len(result) <= 4000:
        await status_msg.edit_text(result)
    else:
        await status_msg.edit_text("النتائج طويلة، يتم إرسالها على أجزاء...")
        # تقسيم وإرسال
        for i in range(0, len(result), 4000):
            await message.answer(result[i:i+4000])

async def main():
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())