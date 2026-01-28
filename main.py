import re
import asyncio
import base64
import json
import yaml
import os
import datetime
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List
import socket
import geoip2.database

# =================================================================================
# Settings and Constants
# =================================================================================

API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 5))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 100))

OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"

WEEKLY_FILE = "conf-week.txt"
HISTORY_FILE = "conf-week-history.json"
GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'
CHANNEL_MAX_INACTIVE_DAYS = 4

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'), re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'), re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"), re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

COUNTRY_FLAGS = {'US': '🇺🇸', 'DE': '🇩🇪', 'NL': '🇳🇱', 'GB': '🇬🇬', 'FR': '🇫🇷', 'IR': '🇮🇷'}

GEOIP_READER = None

def load_ip_data():
    global GEOIP_READER
    try: GEOIP_READER = geoip2.database.Reader(GEOIP_DATABASE_PATH)
    except: pass

def process_lists():
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    groups = []
    if GROUPS_STR:
        try: groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except: pass
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    def get_country_iso_code(self, hostname: str) -> str:
        if not hostname or not GEOIP_READER: return "N/A"
        try:
            ip = hostname if re.match(r"^\d", hostname) else socket.gethostbyname(hostname)
            return GEOIP_READER.country(ip).country.iso_code or "N/A"
        except: return "N/A"

    def parse_config_for_clash(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            if url.startswith('vmess://'):
                c = json.loads(base64.b64decode(url[8:] + '='*4).decode('utf-8'))
                return {'name': c.get('ps', 'vmess'), 'type': 'vmess', 'server': c.get('add'), 'port': int(c.get('port', 443)), 'uuid': c.get('id'), 'alterId': int(c.get('aid', 0)), 'cipher': 'auto', 'tls': c.get('tls')=='tls', 'network': c.get('net', 'tcp'), 'udp': True}
            p = urlparse(url)
            if url.startswith(('vless://', 'trojan://')):
                return {'name': unquote(p.fragment or 'cfg'), 'type': p.scheme, 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': p.username, 'tls': True, 'udp': True}
        except: return None
        return None

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found = set()
        if not text: return found
        for pattern in V2RAY_PATTERNS:
            found.update(pattern.findall(text))
        return {f.strip() for f in found}

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int):
        try:
            # چک کردن فعالیت کانال
            async for last_msg in self.client.get_chat_history(chat_id, limit=1):
                if last_msg.date < (datetime.datetime.now() - datetime.timedelta(days=CHANNEL_MAX_INACTIVE_DAYS)):
                    return
                break

            async for message in self.client.get_chat_history(chat_id, limit=limit):
                # لایه اول: گرفتن متن به صورت HTML برای استخراج محتوای تگ‌ها
                html_text = getattr(message, "html", "") or ""
                # لایه دوم: متن معمولی
                plain_text = message.text or message.caption or ""
                
                texts_to_scan = [plain_text, html_text]
                
                # لایه سوم: اسکن دستی انتیتی‌ها برای اطمینان ۱۰۰٪
                if message.entities:
                    for ent in message.entities:
                        if ent.type in [enums.MessageEntityType.CODE, enums.MessageEntityType.PRE, enums.MessageEntityType.BLOCKQUOTE]:
                            try:
                                # استفاده از اسلایس مستقیم روی متن پیام
                                content = plain_text[ent.offset : ent.offset + ent.length]
                                if content:
                                    texts_to_scan.append(content)
                                    # حذف اینترها برای لینک‌های شکسته
                                    texts_to_scan.append(content.replace('\n', '').replace(' ', ''))
                            except: continue

                for text in texts_to_scan:
                    if text:
                        # پیدا کردن لینک‌های مستقیم
                        self.raw_configs.update(self.extract_configs_from_text(text))
                        # پیدا کردن بیس۶۴ ها
                        for b64 in BASE64_PATTERN.findall(text):
                            try:
                                decoded = base64.b64decode(b64 + '='*4).decode('utf-8', errors='ignore')
                                self.raw_configs.update(self.extract_configs_from_text(decoded))
                            except: continue
        except FloodWait as e:
            await asyncio.sleep(e.value + 1)
            await self.find_raw_configs_from_chat(chat_id, limit)
        except: pass

    def save_files(self):
        if not self.raw_configs:
            print("❌ هنوز هیچی پیدا نشده. تنظیمات کانال‌ها یا SESSION رو چک کن.")
            return
        
        final_configs = sorted(list(self.raw_configs))
        proxies_clash = []
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            for i, url in enumerate(final_configs, 1):
                proxy = self.parse_config_for_clash(url)
                if proxy:
                    code = self.get_country_iso_code(proxy['server'])
                    flag = COUNTRY_FLAGS.get(code, '🏳️')
                    f.write(f"{url.split('#')[0]}#{flag} Config_jo-{i:02d}\n")
                    proxy['name'] = f"{code}-{i:02d}"
                    proxies_clash.append(proxy)

        # ذخیره فایل کلش با فیلتر UUID
        clash_data = {
            'proxies': [p for p in proxies_clash if p.get('uuid') or p.get('password')],
            'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT'] + [p['name'] for p in proxies_clash]}]
        }
        with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
            yaml.dump(clash_data, f, allow_unicode=True)
        
        print(f"✅ موفقیت‌آمیز: {len(final_configs)} کانفیگ ذخیره شد.")

async def main():
    load_ip_data()
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(c, CHANNEL_SEARCH_LIMIT) for c in CHANNELS]
        await asyncio.gather(*tasks)
    extractor.save_files()

if __name__ == "__main__":
    asyncio.run(main())
