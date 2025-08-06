import os
import re
from telethon.sync import TelegramClient

# ----------------- تنظیمات اولیه -----------------
# دریافت اطلاعات از متغیرهای محیطی (Secrets در گیت‌هاب)
api_id = os.environ.get("API_ID")
api_hash = os.environ.get("API_HASH")
session_string = os.environ.get("SESSION_STRING")
channels_str = os.environ.get("CHANNELS")

# تبدیل رشته کانال‌ها به لیست
# کانال‌ها باید با کاما (,) از هم جدا شده باشند
channels = [channel.strip() for channel in channels_str.split(',')]

# تعریف مسیر فایل‌های خروجی
config_file_path = "Config_jo.txt"
clash_file_path = "Config-jo.yaml"

# لیست برای نگهداری تمام کانفیگ‌های پیدا شده
all_configs = []

# ----------------- شروع ارتباط با تلگرام -----------------
try:
    with TelegramClient(session_string, int(api_id), api_hash) as client:
        print("✅ Client successfully connected to Telegram.")
        
        # حلقه برای بررسی هر کانال
        for channel in channels:
            print(f"\n🔄 Processing channel: {channel}")
            try:
                # دریافت entity کانال
                entity = client.get_entity(channel)
                
                # حلقه برای خواندن پیام‌های کانال
                # می‌توانید limit را برای خواندن پیام‌های بیشتر یا کمتر تغییر دهید
                for message in client.iter_messages(entity, limit=200):
                    if message.text:
                        # --- بخش دیباگ: چاپ متن خام پیام برای بررسی دقیق ---
                        # از repr() استفاده می‌کنیم تا کاراکترهای نامرئی مثل \n هم دیده شوند
                        print("DEBUG: Raw message received -> " + repr(message.text)[:100] + "...") # چاپ ۱۰۰ کاراکتر اول برای خوانایی
                        
                        # پردازش خط به خط برای دقت بالاتر
                        for line in message.text.splitlines():
                            # جستجو برای پیدا کردن الگوی کانفیگ در هر خط
                            match = re.search("(vless|vmess|trojan|ss|ssr|hysteria|hysteria2)://.+", line)
                            if match:
                                config_found = match.group(0).strip()
                                # جلوگیری از اضافه شدن کانفیگ‌های تکراری
                                if config_found not in all_configs:
                                    all_configs.append(config_found)
                                    # --- بخش دیباگ: چاپ کانفیگ پیدا شده ---
                                    print(f"SUCCESS: Found config -> {config_found[:70]}...") # چاپ ۷۰ کاراکتر اول
                                    
            except Exception as e:
                print(f"❌ Error processing channel {channel}: {e}")

except Exception as e:
    print(f"❌ Failed to connect to Telegram: {e}")

# ----------------- نوشتن کانفیگ‌ها در فایل‌ها -----------------
if all_configs:
    print(f"\n✅ Found a total of {len(all_configs)} unique configs.")
    
    # نوشتن در فایل متنی (برای v2rayNG و ...)
    try:
        with open(config_file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(all_configs))
        print(f"✅ Successfully wrote configs to {config_file_path}")
    except Exception as e:
        print(f"❌ Error writing to {config_file_path}: {e}")
        
    # نوشتن در فایل YAML (برای Clash)
    # این بخش یک ساختار ساده برای Clash ایجاد می‌کند. شاید نیاز به تنظیمات بیشتری داشته باشد.
    try:
        with open(clash_file_path, "w", encoding="utf-8") as f:
            f.write("proxies:\n")
            for config in all_configs:
                # این یک مثال ساده است و شاید برای همه انواع کانفیگ کار نکند
                f.write(f"- name: auto-proxy-{all_configs.index(config)}\n")
                f.write(f"  type: vmess # نوع را باید بر اساس نوع کانفیگ تغییر داد\n")
                f.write(f"  server: # آدرس سرور\n")
                f.write(f"  port: # پورت\n")
                f.write(f"  uuid: # UUID\n")
                f.write(f"  # ... سایر پارامترها\n")
                f.write(f"  # نکته: تبدیل خودکار به فرمت Clash پیچیده است.\n")
                f.write(f"  # در حال حاضر فقط لینک‌ها در فایل متنی ذخیره می‌شوند.\n")

        # به دلیل پیچیدگی تبدیل انواع کانفیگ به فرمت Clash YAML،
        # فعلا بخش Clash را ساده نگه می‌داریم و تمرکز روی فایل متنی است.
        # برای تبدیل دقیق، باید هر لینک را جداگانه تجزیه و تحلیل کرد.
        print(f"ℹ️ Note: Clash YAML file creation is basic. Main output is {config_file_path}")
        
    except Exception as e:
        print(f"❌ Error writing to {clash_file_path}: {e}")
        
else:
    print("\n🤷 No configs were found in the specified channels.")
