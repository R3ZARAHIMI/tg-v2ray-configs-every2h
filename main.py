# -*- coding: utf-8 -*-

import re
import asyncio
import base64
import json
import yaml
import os
import uuid
import socket
import requests
from urllib.parse import urlparse, parse_qs, unquote, urlunparse

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait

# =================================================================================
# بخش تنظیمات و خواندن سکرت‌ها از محیط
# =================================================================================

# --- خواندن سکرت‌های اصلی پایروگرام ---
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
CHANNEL_SEARCH_LIMIT = 5
GROUP_SEARCH_LIMIT = 500
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"


# =================================================================================
# توابع و کلاس‌های اصلی برنامه
# =================================================================================

def process_lists():
    """رشته‌های خوانده شده از سکرت‌ها را به لیست‌های پایتون تبدیل می‌کند."""
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if CHANNELS_STR: print(f"✅ {len(channels)} کانال از سکرت‌ها خوانده شد.")
    else: print("⚠️ هشدار: سکرت CHANNELS_LIST پیدا نشد یا خالی است.")
    
    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
            print(f"✅ {len(groups)} گروه از سکرت‌ها خوانده شد.")
        except ValueError:
            print("❌ خطا: سکرت GROUPS_LIST باید فقط شامل آیدی‌های عددی باشد.")
    else: print("⚠️ هشدار: سکرت GROUPS_LIST خالی است.")
        
    return channels, groups

def get_flag(iso_code):
    """کد دو حرفی کشور را به ایموجی پرچم تبدیل می‌کند."""
    if not iso_code or len(iso_code) != 2: return '🏁'
    return "".join(chr(ord(c) - ord('A') + 0x1F1E6) for c in iso_code.upper())

def get_country_from_ip(session, ip_address):
    """کشور را با استفاده از API سرویس ipinfo.io پیدا می‌کند."""
    try:
        ip = socket.gethostbyname(ip_address)
        response = session.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get('country')
    except (socket.gaierror, requests.exceptions.RequestException):
        return None

CHANNELS, GROUPS = process_lists()

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
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
        if not original_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name).replace(' ', '_').strip('_-')
        return f"{cleaned_name}-{str(uuid.uuid4())[:8]}" if cleaned_name else f"{prefix}-{str(uuid.uuid4())[:8]}"

    def parse_config_for_clash(self, config_url):
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            return None
        except Exception:
            return None

    def parse_vmess(self, vmess_url):
        encoded_data = vmess_url.replace('vmess://', '').split('#')[0]
        encoded_data += '=' * (4 - len(encoded_data) % 4)
        config = json.loads(base64.b64decode(encoded_data).decode('utf-8'))
        original_name = config.get('ps', '')
        
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
        parsed = urlparse(vless_url)
        query = parse_qs(parsed.query)
        original_name = unquote(parsed.fragment) if parsed.fragment else ''
        
        ws_opts = None
        if query.get('type', [''])[0] == 'ws':
            host_header = query.get('host', [''])[0].strip() or query.get('sni', [''])[0].strip() or parsed.hostname
            if host_header:
                ws_opts = {
                    'path': query.get('path', ['/'])[0],
                    'headers': {'Host': host_header}
                }

        return {
            'name': self._generate_unique_name(original_name, "vless"), 'type': 'vless',
            'server': parsed.hostname, 'port': parsed.port or 443,
            'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] == 'tls',
            'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0],
            'ws-opts': ws_opts,
            'reality-opts': {'public-key': query.get('pbk', [None])[0], 'short-id': query.get('sid', [None])[0]} if query.get('security', [''])[0] == 'reality' else None
        }

    def parse_trojan(self, trojan_url):
        parsed = urlparse(trojan_url)
        query = parse_qs(parsed.query)
        original_name = unquote(parsed.fragment) if parsed.fragment else ''
        return {'name': self._generate_unique_name(original_name, "trojan"), 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': query.get('peer', [None])[0] or query.get('sni', [None])[0]}

    def parse_shadowsocks(self, ss_url):
        parsed = urlparse(ss_url)
        original_name = unquote(parsed.fragment) if parsed.fragment else ''
        user_info = ''
        if '@' in parsed.netloc:
            user_info_part = parsed.netloc.split('@')[0]
            try:
                user_info = base64.b64decode(user_info_part + '=' * (4 - len(user_info_part) % 4)).decode('utf-8')
            except:
                user_info = unquote(user_info_part)
        cipher, password = user_info.split(':', 1) if ':' in user_info else (None, None)
        return {'name': self._generate_unique_name(original_name, 'ss'), 'type': 'ss', 'server': parsed.hostname, 'port': parsed.port, 'cipher': cipher, 'password': password, 'udp': True} if cipher and password else None

    async def find_raw_configs_from_chat(self, chat_id, limit):
        try:
            print(f"🔍 Searching for raw configs in chat {chat_id} (limit: {limit})...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not message.text: continue
                texts_to_scan = [message.text]
                potential_b64 = BASE64_PATTERN.findall(message.text)
                for b64_str in potential_b64:
                    try:
                        texts_to_scan.append(base64.b64decode(b64_str + '=' * (4 - len(b64_str) % 4)).decode('utf-8'))
                    except: continue
                for text in texts_to_scan:
                    for pattern in V2RAY_PATTERNS:
                        self.raw_configs.update(m.strip() for m in pattern.findall(text))
        except FloodWait as e:
            print(f"⏳ Waiting {e.value}s for {chat_id} due to flood limit.")
            await asyncio.sleep(e.value)
            await self.find_raw_configs_from_chat(chat_id, limit)
        except Exception as e:
            print(f"❌ Error scanning chat {chat_id}: {e}")

    def save_files(self):
        # --- START: بخش جدید برای تغییر نام و افزودن پرچم ---
        FIXED_NAME = "Proxy-by-R3ZARAHIMI"
        print("\n" + "="*30)
        if not self.raw_configs:
            print("⚠️ No raw configs found."); return

        print(f"⚙️ Processing {len(self.raw_configs)} configs to add country flags...")
        
        modified_txt_configs = []
        clash_proxies_renamed = []
        
        with requests.Session() as session:
            # مرتب‌سازی کانفیگ‌ها برای داشتن یک ترتیب ثابت
            sorted_configs = sorted(list(self.raw_configs))
            
            for i, config_url in enumerate(sorted_configs):
                # ابتدا کانفیگ را برای به دست آوردن آدرس سرور، پردازش می‌کنیم
                parsed_proxy = self.parse_config_for_clash(config_url)
                if not parsed_proxy: continue

                # پیدا کردن کشور و ساختن نام جدید
                country_code = get_country_from_ip(session, parsed_proxy.get('server'))
                flag = get_flag(country_code)
                new_name = f"{flag} {FIXED_NAME}-{i+1}"

                # به‌روزرسانی نام در دیکشنری پراکسی برای فایل YAML
                parsed_proxy['name'] = new_name
                clash_proxies_renamed.append(parsed_proxy)

                # بازسازی لینک با نام جدید برای فایل TXT
                try:
                    parts = list(urlparse(config_url))
                    parts[5] = new_name  # index 5 همان fragment یا نام کانفیگ است
                    modified_url = urlunparse(parts)
                    modified_txt_configs.append(modified_url)
                except Exception:
                    modified_txt_configs.append(config_url) # در صورت خطا، لینک اصلی را نگه دار

        # --- ذخیره فایل TXT با نام‌های جدید ---
        if modified_txt_configs:
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(modified_txt_configs))
            print(f"📝 {len(modified_txt_configs)} configs with flags saved to {OUTPUT_TXT}.")

        # --- ذخیره فایل YAML با نام‌های جدید ---
        if clash_proxies_renamed:
            print(f"👍 Found {len(clash_proxies_renamed)} valid configs for Clash. Generating YAML file...")
            proxy_names = [p['name'] for p in clash_proxies_renamed]
            
            clash_config_base = {
                'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule',
                'log-level': 'info', 'external-controller': '127.0.0.1:9090', 'dns': {
                    'enable': True, 'listen': '0.0.0.0:53', 'default-nameserver': ['8.8.8.8', '1.1.1.1', '208.67.222.222'],
                    'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                    'fallback': ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'],
                    'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4']}
                },
                'proxies': clash_proxies_renamed,
                'proxy-groups': [
                    {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'DIRECT', *proxy_names]},
                    {'name': 'AUTO', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
                ], 'rules': [
                    'DOMAIN-SUFFIX,local,DIRECT', 'IP-CIDR,127.0.0.0/8,DIRECT',
                    'IP-CIDR,192.168.0.0/16,DIRECT', 'IP-CIDR,172.16.0.0/12,DIRECT',
                    'IP-CIDR,10.0.0.0/8,DIRECT', 'GEOIP,IR,DIRECT', 'MATCH,PROXY'
                ]
            }
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config_base, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
            print(f"✅ Clash YAML file with country flags saved successfully.")
        else:
            print(f"⚠️ No valid configs to save in {OUTPUT_YAML}.")
            open(OUTPUT_YAML, "w").close()
        # --- END: پایان بخش جدید ---


async def main():
    print("🚀 Starting V2Ray config extractor...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks: await asyncio.gather(*tasks)
        else: print("No channels or groups to process.")
    
    extractor.save_files()
    print("\n✨ All tasks completed!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ خطا: یکی از سکرت‌های ضروری (API_ID, API_HASH, SESSION_STRING) تنظیم نشده است.")
    else:
        asyncio.run(main())
