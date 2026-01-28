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

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try: return '@' in ss_url
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        if config_url.startswith('ss://') and 'v=2' in config_url: return config_url.replace('ss://', 'vmess://', 1)
        return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        try:
            if config_url.startswith(('vless://', 'trojan://')): return True
            if config_url.startswith('vmess://'):
                c = json.loads(base64.b64decode(config_url[8:] + '=' * 4).decode('utf-8'))
                return bool(c.get('add') and c.get('id'))
            return True
        except: return False

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found = set()
        for pattern in V2RAY_PATTERNS:
            found.update(pattern.findall(text))
        return {corrected for url in found if (corrected := self._correct_config_type(url.strip())) and self._validate_config_type(corrected)}

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int):
        local_configs = set()
        try:
            print(f"🔍 Scanning: {chat_id}")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                texts_to_scan = []
                main_text = message.text or message.caption or ""
                
                # DEBUG LOG
                print(f"--- Raw Message Start ({chat_id}) ---")
                print(main_text)
                print(f"--- Raw Message End ---")

                if main_text: texts_to_scan.append(main_text)
                
                if message.entities:
                    for entity in message.entities:
                        try:
                            valid_types = [enums.MessageEntityType.CODE, enums.MessageEntityType.PRE]
                            try: valid_types.append(enums.MessageEntityType.QUOTE)
                            except: pass
                            try: valid_types.append(enums.MessageEntityType.BLOCKQUOTE)
                            except: pass
                            
                            if entity.type in valid_types:
                                seg = main_text[entity.offset : entity.offset + entity.length]
                                texts_to_scan.append(seg)
                                texts_to_scan.append(seg.replace('\n', '').replace(' ', ''))
                        except: continue

                for text in texts_to_scan:
                    if text: local_configs.update(self.extract_configs_from_text(text))
            
            print(f"✅ Found {len(local_configs)} configs in {chat_id}")
            self.raw_configs.update(local_configs)
        except Exception as e:
            print(f"❌ Error with {chat_id}: {e}")

    def save_files(self):
        final_list = sorted(list(self.raw_configs))
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(final_list))
        print(f"💾 Total Saved: {len(final_list)}")

async def main():
    load_ip_data()
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(c, CHANNEL_SEARCH_LIMIT) for c in CHANNELS]
        await asyncio.gather(*tasks)
    extractor.save_files()

if __name__ == "__main__":
    asyncio.run(main())
