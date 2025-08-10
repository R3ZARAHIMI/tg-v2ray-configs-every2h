# -*- coding: utf-8 -*-

import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait

# =================================================================================
# بخش تنظیمات و خواندن سکرت‌ها از محیط
# =================================================================================

# --- خواندن سکرت‌های اصلی پایروگرام ---
# اگر این سکرت‌ها تعریف نشده باشند، برنامه با خطا متوقف می‌شود.
try:
    API_ID = int(os.environ.get("API_ID"))
except (ValueError, TypeError):
    print("❌ خطا: سکرت API_ID تعریف نشده یا مقدار آن عدد صحیح نیست.")
    exit(1)

API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")

# --- خواندن لیست کانال‌ها و گروه‌ها از سکرت‌ها ---
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')

# --- متغیرهای جستجو و نام فایل‌های خروجی ---
CHANNEL_SEARCH_LIMIT = 50   # تعداد پیام‌های آخر برای جستجو در کانال‌ها
GROUP_SEARCH_LIMIT = 600    # تعداد پیام‌های آخر برای جستجو در گروه‌ها
OUTPUT_YAML = "configs.yaml" # نام فایل خروجی YAML برای Clash
OUTPUT_TXT = "configs.txt"     # نام فایل خروجی متنی با لینک‌های خام

# =================================================================================
# توابع و کلاس‌های اصلی برنامه
# =================================================================================

def process_lists():
    """رشته‌های خوانده شده از سکرت‌ها را به لیست‌های پایتون تبدیل می‌کند."""
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if channels:
        print(f"✅ {len(channels)} کانال از سکرت‌ها خوانده شد.")
    else:
        print("⚠️ هشدار: سکرت CHANNELS_LIST پیدا نشد یا خالی است.")
    
    groups = []
    if GROUPS_STR:
        try:
            # آیدی گروه‌ها باید عددی باشد
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
            print(f"✅ {len(groups)} گروه از سکرت‌ها خوانده شد.")
        except ValueError:
            print("❌ خطا: سکرت GROUPS_LIST باید فقط شامل آیدی‌های عددی باشد.")
    else:
        print("⚠️ هشدار: سکرت GROUPS_LIST خالی است.")
        
    return channels, groups

CHANNELS, GROUPS = process_lists()

# الگوهای Regex برای پیدا کردن انواع کانفیگ‌ها
V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'),
    # re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'), # Shadowsocks فعلا غیرفعال است
    re.compile(r"(hy2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]

# الگوی Regex برای پیدا کردن رشته‌های طولانی Base64
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)


class V2RayExtractor:
    """کلاس اصلی برای استخراج و پردازش کانفیگ‌های V2Ray."""
    def __init__(self):
        self.raw_configs = set()
        self.client = Client(
            "my_account",
            api_id=API_ID,
            api_hash=API_HASH,
            session_string=SESSION_STRING
        )

    @staticmethod
    def _generate_unique_name(original_name, prefix="config"):
        """یک نام منحصر به فرد برای هر کانفیگ تولید می‌کند."""
        # اگر نام اصلی وجود نداشت، یک نام کاملا تصادفی بساز
        if not original_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        
        # حذف کاراکترهای غیرمجاز و جایگزینی فاصله با آندرلاین
        # پشتیبانی از حروف فارسی در نام
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name).replace(' ', '_').strip('_-')
        
        # اگر بعد از پاکسازی چیزی باقی نماند، یک نام تصادفی بده
        if not cleaned_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
            
        return f"{cleaned_name}-{str(uuid.uuid4())[:4]}" # اضافه کردن بخش تصادفی کوچک برای جلوگیری از تکرار

    def parse_config_for_clash(self, config_url):
        """کانفیگ‌ها را برای فرمت Clash پردازش می‌کند."""
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            if config_url.startswith('vless://'): return self.parse_vless(config_url)
            if config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            return None
        except Exception:
            # در صورت بروز هرگونه خطا در پردازش یک کانفیگ، آن را نادیده می‌گیرد
            return None

    def parse_vmess(self, vmess_url):
        """پردازش کانفیگ‌های Vmess."""
        parts = vmess_url.split("://")
        encoded_data = parts[1]
        
        try:
            # اطمینان از اینکه طول رشته برای base64 معتبر است
            decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
            config = json.loads(decoded_str)
        except (json.JSONDecodeError, base64.binascii.Error):
            return None

        original_name = config.get('ps', '')
        
        # ساخت ws-opts فقط در صورتی که network از نوع ws باشد
        ws_opts = None
        if config.get('net') == 'ws':
            host_header = config.get('host', '').strip() or config.get('add', '').strip()
            if host_header:
                ws_opts = {
                    'path': config.get('path', '/'),
                    'headers': {'Host': host_header}
                }

        return {
            'name': self._generate_unique_name(original_name, "vmess"), 'type': 'vmess',
            'server': config.get('add'), 'port': int(config.get('port', 443)),
            'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls',
            'network': config.get('net', 'tcp'), 'udp': True,
            'ws-opts': ws_opts
        }

    def parse_vless(self, vless_url):
        """پردازش کانفیگ‌های Vless."""
        parsed = urlparse(vless_url)
        query = parse_qs(parsed.query)
        original_name = unquote(parsed.fragment) if parsed.fragment else ''
        
        # ساخت ws-opts فقط در صورتی که network از نوع ws باشد
        ws_opts = None
        if query.get('type', [''])[0] == 'ws':
            host_header = query.get('host', [''])[0].strip() or query.get('sni', [''])[0].strip() or parsed.hostname
            if host_header:
                ws_opts = {
                    'path': query.get('path', ['/'])[0],
                    'headers': {'Host': host_header}
                }

        # ساخت reality-opts فقط در صورتی که security از نوع reality باشد
        reality_opts = None
        if query.get('security', [''])[0] == 'reality':
            pbk = query.get('pbk', [None])[0]
            if pbk:
                reality_opts = {'public-key': pbk, 'short-id': query.get('sid', [''])[0]}

        return {
            'name': self._generate_unique_name(original_name, "vless"), 'type': 'vless',
            'server': parsed.hostname, 'port': parsed.port or 443,
            'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality'],
            'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0],
            'ws-opts': ws_opts,
            'reality-opts': reality_opts
        }

    def parse_trojan(self, trojan_url):
        """پردازش کانفیگ‌های Trojan."""
        parsed = urlparse(trojan_url)
        query = parse_qs(parsed.query)
        original_name = unquote(parsed.fragment) if parsed.fragment else ''
        
        # برای تروجان، sni از پارامتر peer یا sni خوانده می‌شود
        sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname
        
        return {
            'name': self._generate_unique_name(original_name, "trojan"), 'type': 'trojan',
            'server': parsed.hostname, 'port': parsed.port or 443,
            'password': parsed.username, 'udp': True, 'sni': sni
        }

    async def find_raw_configs_from_chat(self, chat_id, limit):
        """کانفیگ‌ها را از یک چت مشخص استخراج می‌کند."""
        try:
            print(f"🔍 جستجو در چت {chat_id} (محدودیت: {limit} پیام)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not message.text: continue
                
                texts_to_scan = [message.text]
                # تلاش برای دیکد کردن رشته‌های Base64 برای پیدا کردن کانفیگ‌های مخفی
                potential_b64 = BASE64_PATTERN.findall(message.text)
                for b64_str in potential_b64:
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception:
                        continue
                
                # جستجوی الگوهای V2Ray در متن اصلی و متن‌های دیکد شده
                for text in texts_to_scan:
                    for pattern in V2RAY_PATTERNS:
                        found_configs = pattern.findall(text)
                        # استفاده از set برای جلوگیری از ذخیره کانفیگ تکراری
                        self.raw_configs.update(m.strip() for m in found_configs)
                        
        except FloodWait as e:
            print(f"⏳ به دلیل محدودیت تلگرام، برای چت {chat_id} به مدت {e.value} ثانیه صبر می‌کنیم.")
            await asyncio.sleep(e.value)
            await self.find_raw_configs_from_chat(chat_id, limit) # تلاش مجدد
        except Exception as e:
            print(f"❌ خطا در زمان اسکن چت {chat_id}: {e}")

    def save_files(self):
        """فایل‌های خروجی را ذخیره می‌کند."""
        print("\n" + "="*40)
        print(f"📝 ذخیره {len(self.raw_configs)} کانفیگ خام در فایل {OUTPUT_TXT}...")
        if self.raw_configs:
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                # کانفیگ‌ها را مرتب کرده و در فایل می‌نویسد
                f.write("\n".join(sorted(list(self.raw_configs))))
            print("✅ فایل متنی با موفقیت ذخیره شد.")
        else:
            print("⚠️ هیچ کانفیگ خامی برای ذخیره پیدا نشد.")

        print(f"\n⚙️ پردازش کانفیگ‌ها برای فایل کلش ({OUTPUT_YAML})...")
        # پردازش تمام کانفیگ‌های خام و تبدیل آن‌ها به فرمت Clash
        clash_proxies = [p for p in (self.parse_config_for_clash(url) for url in self.raw_configs) if p is not None]

        if not clash_proxies:
            print(f"⚠️ هیچ کانفیگ معتبری برای Clash پیدا نشد. فایل {OUTPUT_YAML} خالی خواهد بود.")
            open(OUTPUT_YAML, "w").close() # یک فایل خالی ایجاد می‌کند
            return
            
        print(f"👍 {len(clash_proxies)} کانفیگ معتبر برای Clash پیدا شد.")
        
        proxy_names = [p['name'] for p in clash_proxies]
        
        # ساختار پایه فایل YAML برای Clash
        clash_config_base = {
            'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule',
            'log-level': 'info', 'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True, 'listen': '0.0.0.0:53',
                'default-nameserver': ['8.8.8.8', '1.1.1.1'],
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'fallback': ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'],
                'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4']}
            },
            'proxies': clash_proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'DIRECT', *proxy_names]},
                {'name': 'AUTO', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
            ],
            'rules': [
                'DOMAIN-SUFFIX,local,DIRECT', 'IP-CIDR,127.0.0.0/8,DIRECT',
                'IP-CIDR,192.168.0.0/16,DIRECT', 'IP-CIDR,172.16.0.0/12,DIRECT',
                'IP-CIDR,10.0.0.0/8,DIRECT', 'GEOIP,IR,DIRECT', 'MATCH,PROXY'
            ]
        }
        
        # ذخیره فایل YAML با فرمت خوانا
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config_base, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
        print(f"✅ فایل {OUTPUT_YAML} با موفقیت ذخیره شد.")


async def main():
    """تابع اصلی برای اجرای کل فرآیند."""
    print("🚀 شروع برنامه استخراج کانفیگ...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        
        if tasks:
            # اجرای همزمان تمام وظایف جستجو
            await asyncio.gather(*tasks)
        else:
            print("❌ هیچ کانال یا گروهی برای جستجو تعریف نشده است.")
    
    # پس از اتمام جستجو، فایل‌ها را ذخیره کن
    extractor.save_files()
    print("\n✨ تمام عملیات با موفقیت به پایان رسید!")


if __name__ == "__main__":
    # قبل از اجرا، بررسی می‌کند که آیا سکرت‌های اصلی تنظیم شده‌اند یا خیر
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ خطا: یک یا چند مورد از سکرت‌های ضروری (API_ID, API_HASH, SESSION_STRING) تنظیم نشده است.")
    else:
        # اجرای برنامه به صورت آسنکرون
        asyncio.run(main())
