# -*- coding: utf-8 -*-

import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress # کتابخانه جدید برای کار با آدرس‌های IP

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait

# =================================================================================
# بخش تنظیمات و ثابت‌ها
# =================================================================================

# --- لیست محدوده‌های IP کلادفلر (IPv4) ---
# منبع: https://www.cloudflare.com/ips/
CLOUDFLARE_IPV4_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '172.64.0.0/13', '131.0.72.0/22'
]

# --- خواندن سکرت‌ها از محیط ---
try:
    API_ID = int(os.environ.get("API_ID"))
except (ValueError, TypeError):
    print("❌ خطا: سکرت API_ID تعریف نشده یا مقدار آن عدد صحیح نیست.")
    exit(1)

API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = 5
GROUP_SEARCH_LIMIT = 600
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_ORIGINAL_TXT = "Original-Configs.txt" # <-- فایل کانفیگ اصلی اضافه شد

# =================================================================================
# توابع و کلاس‌های اصلی برنامه
# =================================================================================

def process_lists():
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if channels: print(f"✅ {len(channels)} کانال از سکرت‌ها خوانده شد.")
    else: print("⚠️ هشدار: سکرت CHANNELS_LIST پیدا نشد یا خالی است.")
    
    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
            print(f"✅ {len(groups)} گروه از سکرت‌ها خوانده شد.")
        except ValueError: print("❌ خطا: سکرت GROUPS_LIST باید فقط شامل آیدی‌های عددی باشد.")
    else: print("⚠️ هشدار: سکرت GROUPS_LIST خالی است.")
    return channels, groups

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

def rename_raw_config(config_url, new_name):
    """کانفیگ خام را می‌گیرد و نام آن را تغییر می‌دهد."""
    new_name_encoded = new_name.replace(" ", "%20")
    if config_url.startswith('vmess://'):
        try:
            b64_data = config_url.split("://")[1]
            # Padding for base64 decoding
            decoded_str = base64.b64decode(b64_data + '=' * (-len(b64_data) % 4)).decode('utf-8')
            config_json = json.loads(decoded_str)
            config_json['ps'] = new_name
            # Use separators=(',', ':') to remove whitespace for a more compact URL
            new_b64_data = base64.b64encode(json.dumps(config_json, separators=(',', ':')).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64_data}"
        except Exception:
            # Fallback if vmess parsing fails
            return f"{config_url.split('#')[0]}#{new_name_encoded}"
    else:
        base_url = config_url.split('#')[0]
        return f"{base_url}#{new_name_encoded}"

class V2RayExtractor:
    def __init__(self):
        self.raw_configs = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)
        self.cf_networks = [ipaddress.ip_network(r) for r in CLOUDFLARE_IPV4_RANGES]

    def _is_cloudflare_ip(self, ip_str):
        """بررسی می‌کند آیا یک IP در محدوده کلادفلر است یا خیر."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_global or ip.version != 4: return False
            for network in self.cf_networks:
                if ip in network: return True
            return False
        except ValueError:
            return False

    def _is_unwanted_config(self, config_url):
        """فیلتر کردن کانفیگ‌های ناخواسته."""
        try:
            hostname = ''
            if config_url.startswith('vmess://'):
                b64_data = config_url.split("://")[1]
                decoded_str = base64.b64decode(b64_data + '=' * (-len(b64_data) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                hostname = config.get('add', '')
            else:
                hostname = urlparse(config_url).hostname
            
            if not hostname: return False
            if 'speedtest.net' in hostname.lower(): return True
            if self._is_cloudflare_ip(hostname): return True
            return False
        except Exception:
            return False

    def parse_config_for_clash(self, config_url):
        """پارس کردن کانفیگ برای تبدیل به فرمت کلش."""
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            return None
        except Exception:
            return None

    def parse_vmess(self, vmess_url):
        try:
            b64_data = vmess_url.split("://")[1]
            decoded_str = base64.b64decode(b64_data + '=' * (-len(b64_data) % 4)).decode('utf-8')
            config = json.loads(decoded_str)
            name = config.get('ps', '')
            ws_opts = {'path': config.get('path', '/'), 'headers': {'Host': config.get('host', '')}} if config.get('net') == 'ws' else None
            return {'name': name, 'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port', 443)), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)), 'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls', 'network': config.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts}
        except Exception: return None

    def parse_vless(self, vless_url):
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            name = unquote(parsed.fragment) if parsed.fragment else ''
            ws_opts = {'path': query.get('path', ['/'])[0], 'headers': {'Host': query.get('host', [''])[0]}} if query.get('type', [''])[0] == 'ws' else None
            reality_opts = {'public-key': query.get('pbk', [None])[0], 'short-id': query.get('sid', [''])[0]} if query.get('security', [''])[0] == 'reality' else None
            return {'name': name, 'type': 'vless', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality'], 'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}
        except Exception: return None

    def parse_trojan(self, trojan_url):
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': name, 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': query.get('sni', [parsed.hostname])[0]}
        except Exception: return None

    def parse_shadowsocks(self, ss_url):
        try:
            parsed = urlparse(ss_url)
            name = unquote(parsed.fragment) if parsed.fragment else ''
            user_info_part = (ss_url.split("://")[1]).split("@")[0]
            user_info = base64.b64decode(user_info_part + '=' * (-len(user_info_part) % 4)).decode('utf-8')
            cipher, password = user_info.split(':', 1)
            return {'name': name, 'type': 'ss', 'server': parsed.hostname, 'port': parsed.port, 'cipher': cipher, 'password': password, 'udp': True}
        except Exception: return None

    def extract_configs_from_text(self, text):
        """استخراج کانفیگ‌ها از متن."""
        for pattern in V2RAY_PATTERNS:
            self.raw_configs.update(match.strip() for match in pattern.findall(text))
        
        potential_b64 = BASE64_PATTERN.findall(text)
        for b64_str in potential_b64:
            try:
                # Add padding for base64 decoding
                decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                for pattern in V2RAY_PATTERNS:
                    self.raw_configs.update(match.strip() for match in pattern.findall(decoded_text))
            except Exception: continue

    async def find_raw_configs_from_chat(self, chat_id, limit):
        try:
            print(f"🔍 جستجو در چت {chat_id} (محدودیت: {limit} پیام)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if message.text:
                    self.extract_configs_from_text(message.text)
        except FloodWait as e:
            print(f"⏳ به دلیل محدودیت تلگرام، برای چت {chat_id} به مدت {e.value} ثانیه صبر می‌کنیم.")
            await asyncio.sleep(e.value)
            await self.find_raw_configs_from_chat(chat_id, limit)
        except Exception as e: 
            print(f"❌ خطا در زمان اسکن چت {chat_id}: {e}")

    def save_files(self):
        print("\n" + "="*40)
        
        print(f"⚙️ فیلتر کردن کانفیگ‌های ناخواسته از مجموع {len(self.raw_configs)} کانفیگ...")
        filtered_configs = {config for config in self.raw_configs if not self._is_unwanted_config(config)}
        removed_count = len(self.raw_configs) - len(filtered_configs)
        if removed_count > 0: print(f"👍 {removed_count} کانفیگ ناخواسته حذف شد.")
        
        # --- مرحله ۱: ذخیره کانفیگ‌ها با نام اصلی ---
        print(f"📝 ذخیره {len(filtered_configs)} کانفیگ با نام اصلی در فایل {OUTPUT_ORIGINAL_TXT}...")
        if filtered_configs:
            with open(OUTPUT_ORIGINAL_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(sorted(list(filtered_configs))))
            print(f"✅ فایل {OUTPUT_ORIGINAL_TXT} با موفقیت ذخیره شد.")

        # --- مرحله ۲: تغییر نام کانفیگ‌ها ---
        print("✏️ تغییر نام تمام کانفیگ‌ها...")
        sorted_configs = sorted(list(filtered_configs))
        final_renamed_configs = [rename_raw_config(conf, f"R3za-@v2rayww3-{i:03}") for i, conf in enumerate(sorted_configs, 1)]
        
        # --- مرحله ۳: ذخیره فایل متنی با نام‌های جدید ---
        print(f"📝 ذخیره {len(final_renamed_configs)} کانفیگ در فایل {OUTPUT_TXT}...")
        if final_renamed_configs:
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(final_renamed_configs))
            print("✅ فایل متنی با موفقیت ذخیره شد.")
        else:
            print("⚠️ هیچ کانفیگ خامی برای ذخیره باقی نماند.")

        # --- مرحله ۴: پردازش برای کلش با استفاده از کانفیگ‌های تغییرنام‌داده‌شده ---
        print(f"\n⚙️ پردازش کانفیگ‌ها برای فایل کلش ({OUTPUT_YAML})...")
        clash_proxies = [proxy for url in final_renamed_configs if (proxy := self.parse_config_for_clash(url)) is not None]

        if not clash_proxies:
            print(f"⚠️ هیچ کانفیگ معتبری برای Clash پیدا نشد. فایل {OUTPUT_YAML} خالی خواهد بود.")
            open(OUTPUT_YAML, "w").close()
            return
            
        print(f"👍 {len(clash_proxies)} کانفیگ معتبر برای Clash پیدا شد.")
        proxy_names = [p['name'] for p in clash_proxies]
        
        clash_config_base = {
            'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090',
            'dns': {'enable': True, 'listen': '0.0.0.0:53', 'default-nameserver': ['8.8.8.8', '1.1.1.1'], 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'fallback': ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'], 'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4']}},
            'proxies': clash_proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'DIRECT', *proxy_names]},
                {'name': 'AUTO', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
            ],
            'rules': ['DOMAIN-SUFFIX,local,DIRECT', 'IP-CIDR,127.0.0.0/8,DIRECT', 'IP-CIDR,192.168.0.0/16,DIRECT', 'IP-CIDR,172.16.0.0/12,DIRECT', 'IP-CIDR,10.0.0.0/8,DIRECT', 'GEOIP,IR,DIRECT', 'MATCH,PROXY']
        }
        
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config_base, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
        print(f"✅ فایل {OUTPUT_YAML} با موفقیت ذخیره شد.")

async def main():
    print("🚀 شروع برنامه استخراج کانفیگ...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks: await asyncio.gather(*tasks)
        else: print("❌ هیچ کانال یا گروهی برای جستجو تعریف نشده است.")
    extractor.save_files()
    print("\n✨ تمام عملیات با موفقیت به پایان رسید!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ خطا: یک یا چند مورد از سکرت‌های ضروری (API_ID, API_HASH, SESSION_STRING) تنظیم نشده است.")
    else:
        asyncio.run(main())
