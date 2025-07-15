import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote
import requests
import socket
from collections import defaultdict

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait

# --- تنظیمات اصلی ---
# این مقادیر باید در بخش Secrets ریپازیتوری GitHub شما تنظیم شوند
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")

# --- لیست کانال‌ها و گروه‌ها ---
CHANNEL_SEARCH_LIMIT = 5   # تعداد پیام‌هایی که در هر کانال جستجو می‌شود
GROUP_SEARCH_LIMIT = 500   # تعداد پیام‌هایی که در هر گروه جستجو می‌شود

CHANNELS = [
    "@SRCVPN", "@net0n3", "@ZibaNabz", "@vpns", "@Capoit",
    "@sezar_sec", "@Fr33C0nfig", "@v2ra_config", "@v2rayww3", "@gheychiamoozesh"
]
GROUPS = [
    -1001287072009, -1001275030629, -1002026806005
]

# --- خروجی‌ها ---
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"

# --- الگوهای Regex ---
V2RAY_PATTERNS = [
    re.compile(r"(vless://[^\s'\"<>`]+)"),
    re.compile(r"(vmess://[^\s'\"<>`]+)"),
    re.compile(r"(trojan://[^\s'\"<>`]+)"),
    re.compile(r"(ss://[^\s'\"<>`]+)"),
    re.compile(r"(hy2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

# --- کلاس اصلی ---
class V2RayExtractor:
    def __init__(self):
        self.raw_configs = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)
        # شمارنده برای نام‌های تکراری بر اساس پرچم
        self.flag_counters = defaultdict(int)

    def get_country_flag(self, hostname):
        """آدرس سرور را به ایموجی پرچم کشور تبدیل می‌کند."""
        # اگر هاست یک آی‌پی بود، نیازی به رزولوشن نیست
        try:
            # بررسی می‌کنیم که آیا هاست یک دامنه معتبر است یا خیر
            if hostname:
                ip_address = socket.gethostbyname(hostname)
            else:
                return "🌍" # اگر هاست‌نیم وجود نداشت
        except socket.gaierror:
            # اگر دامنه قابل ترجمه به IP نبود
            return "❔"
            
        try:
            # ارسال درخواست به سرویس Geolocation
            response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,countryCode", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country_code = data.get('countryCode')
                    if country_code:
                        # تبدیل کد کشور به ایموجی پرچم
                        return "".join(chr(ord(c) + 127397) for c in country_code.upper())
        except requests.RequestException:
            # در صورت بروز خطای شبکه
            return "🌐"
        # اگر هیچکدام از شرایط بالا برقرار نبود
        return "🌍"

    def _generate_unique_name(self, flag):
        """بر اساس پرچم و شمارنده، یک نام منحصر به فرد تولید می‌کند."""
        self.flag_counters[flag] += 1
        return f"{flag} | {self.flag_counters[flag]}"

    # --- توابع پارس کردن (تغییر یافته) ---
    def parse_config_for_clash(self, config_url):
        try:
            if config_url.startswith('vmess://'):
                return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'):
                return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'):
                return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'):
                return self.parse_shadowsocks(config_url)
            return None
        except Exception:
            return None

    def parse_vmess(self, vmess_url):
        try:
            encoded_data = vmess_url.replace('vmess://', '').split('#')[0]
            encoded_data += '=' * (4 - len(encoded_data) % 4)
            config = json.loads(base64.b64decode(encoded_data).decode('utf-8'))
            
            flag = self.get_country_flag(config.get('add'))
            new_name = self._generate_unique_name(flag)
            
            return {
                'name': new_name, 'type': 'vmess',
                'server': config.get('add'), 'port': int(config.get('port', 443)),
                'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)),
                'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls',
                'network': config.get('net', 'tcp'), 'udp': True,
                'ws-opts': {'path': config.get('path', '/'), 'headers': {'Host': config.get('host', '')}} if config.get('net') == 'ws' else None
            }
        except Exception:
            return None

    def parse_vless(self, vless_url):
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            
            flag = self.get_country_flag(parsed.hostname)
            new_name = self._generate_unique_name(flag)

            return {
                'name': new_name, 'type': 'vless',
                'server': parsed.hostname, 'port': parsed.port or 443,
                'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] == 'tls',
                'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0],
                'ws-opts': {'path': query.get('path', ['/'])[0], 'headers': {'Host': query.get('host', [None])[0]}} if query.get('type', [''])[0] == 'ws' else None,
                'reality-opts': {'public-key': query.get('pbk', [None])[0], 'short-id': query.get('sid', [None])[0]} if query.get('security', [''])[0] == 'reality' else None
            }
        except Exception:
            return None

    def parse_trojan(self, trojan_url):
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            
            flag = self.get_country_flag(parsed.hostname)
            new_name = self._generate_unique_name(flag)

            return {
                'name': new_name, 'type': 'trojan',
                'server': parsed.hostname, 'port': parsed.port or 443,
                'password': parsed.username, 'udp': True, 'sni': query.get('peer', [None])[0] or query.get('sni', [None])[0]
            }
        except Exception:
            return None

    def parse_shadowsocks(self, ss_url):
        try:
            parsed = urlparse(ss_url)
            user_info = ''
            if '@' in parsed.netloc:
                user_info_part = parsed.netloc.split('@')[0]
                try:
                    user_info = base64.b64decode(user_info_part + '=' * (4 - len(user_info_part) % 4)).decode('utf-8')
                except:
                    user_info = unquote(user_info_part)
            
            cipher, password = user_info.split(':', 1) if ':' in user_info else (None, None)
            if not (cipher and password): return None

            flag = self.get_country_flag(parsed.hostname)
            new_name = self._generate_unique_name(flag)

            return {
                'name': new_name, 'type': 'ss',
                'server': parsed.hostname, 'port': parsed.port,
                'cipher': cipher, 'password': password, 'udp': True
            }
        except Exception:
            return None
    
    # --- تابع اصلی جستجو (بدون تغییر) ---
    async def find_raw_configs_from_chat(self, chat_id, limit):
        """کانفیگ‌ها را از یک چت (کانال یا گروه) با لیمیت مشخص پیدا می‌کند"""
        try:
            print(f"🔍 Searching for raw configs in chat {chat_id} (limit: {limit})...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not message.text:
                    continue
                
                texts_to_scan = [message.text]
                potential_b64 = BASE64_PATTERN.findall(message.text)
                for b64_str in potential_b64:
                    try:
                        decoded = base64.b64decode(b64_str + '=' * (4 - len(b64_str) % 4)).decode('utf-8')
                        texts_to_scan.append(decoded)
                    except:
                        continue

                for text in texts_to_scan:
                    for pattern in V2RAY_PATTERNS:
                        matches = pattern.findall(text)
                        for config_url in matches:
                            self.raw_configs.add(config_url.strip())
        except FloodWait as e:
            print(f"⏳ Waiting {e.value}s for {chat_id} due to flood limit.")
            await asyncio.sleep(e.value)
            await self.find_raw_configs_from_chat(chat_id, limit) # تلاش مجدد
        except Exception as e:
            print(f"❌ Error scanning chat {chat_id}: {e}")

    # --- تابع ذخیره‌سازی فایل‌ها (بدون تغییر) ---
    def save_files(self):
        print("\n" + "="*30)
        # 1. ذخیره فایل متنی خام
        print(f"📝 Saving {len(self.raw_configs)} raw configs to {OUTPUT_TXT}...")
        if self.raw_configs:
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(sorted(list(self.raw_configs))))
            print(f"✅ Raw text file saved successfully.")
        else:
            print("⚠️ No raw configs found to save.")

        # 2. پردازش و ذخیره فایل YAML برای Clash
        print(f"\n⚙️ Processing configs for {OUTPUT_YAML}...")
        clash_proxies = []
        for config_url in self.raw_configs:
            parsed = self.parse_config_for_clash(config_url)
            if parsed:
                clash_proxies.append({k: v for k, v in parsed.items() if v is not None})

        if not clash_proxies:
            print("⚠️ No valid configs could be parsed for Clash. YAML file will be empty.")
            # ایجاد یک فایل خالی
            with open(OUTPUT_YAML, 'w') as f:
                yaml.dump({'proxies': []}, f)
            return
            
        print(f"👍 Found {len(clash_proxies)} valid configs for Clash.")
        
        proxy_names = [p['name'] for p in clash_proxies]
        clash_config_base = {
            'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'proxies': clash_proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'DIRECT', *proxy_names]},
                {'name': 'AUTO', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
            ],
            'rules': ['MATCH,PROXY']
        }
        
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config_base, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
        print(f"✅ Clash YAML file saved successfully.")


async def main():
    print("🚀 Starting V2Ray config extractor...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = []
        for channel in CHANNELS:
            tasks.append(extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT))
        for group in GROUPS:
            tasks.append(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT))
        
        await asyncio.gather(*tasks)
    
    # تابع save_files نیازی به async ندارد چون requests به صورت 동기 (synchronous) کار می‌کند
    extractor.save_files()
    print("\n✨ All tasks completed!")

if __name__ == "__main__":
    # اگر در ویندوز با خطا مواجه شدید این خط را کامنت‌زدایی کنید
    # asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())