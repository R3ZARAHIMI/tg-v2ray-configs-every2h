import re
import asyncio
import base64
import json
import yaml
import os
import requests
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait, ChannelInvalid, ChannelPrivate
from typing import Optional, Dict, Any, Set, List
import socket
import geoip2.database

# =================================================================================
# IP Geolocation Section
# =================================================================================

GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'
GEOIP_READER = None

def load_ip_data():
    global GEOIP_READER
    print("Attempting to load GeoIP database...")
    try:
        GEOIP_READER = geoip2.database.Reader(GEOIP_DATABASE_PATH)
        print(f"✅ Successfully loaded GeoIP database.")
    except FileNotFoundError:
        print(f"⚠️ GeoIP database not found. Flags will be disabled.")
    except Exception as e:
        print(f"⚠️ Failed to load GeoIP database: {e}")

def get_country_iso_code(hostname: str) -> str:
    if not hostname or not GEOIP_READER: return "N/A"
    try:
        ip_address = hostname
        try: socket.inet_aton(hostname)
        except: ip_address = socket.gethostbyname(hostname)
        return GEOIP_READER.country(ip_address).country.iso_code or "N/A"
    except: return "N/A"

COUNTRY_FLAGS = {
    'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇧', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'
}

# =================================================================================
# Settings
# =================================================================================

API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
# Increase limit significantly to find old messages
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 200))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 50))

OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'), re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'), re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"), re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
URL_PATTERN = re.compile(r'(https?://[^\s]+)')
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

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

    # ---[ Parsing Helpers ]---
    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try:
            parsed = urlparse(ss_url)
            if not parsed.hostname: return False
            try: base64.b64decode(parsed.netloc.split('@')[0] + '=' * 4); return True
            except: return ':' in parsed.netloc.split('@')[0]
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        if config_url.startswith('ss://') and 'v=2' in config_url: return config_url.replace('ss://', 'vmess://', 1)
        return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        return any(config_url.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://', 'tuic://'])

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        parsers = {'vmess://': self.parse_vmess, 'vless://': self.parse_vless, 'trojan://': self.parse_trojan, 'ss://': self.parse_shadowsocks, 'hysteria2://': self.parse_hysteria2, 'hy2://': self.parse_hysteria2, 'tuic://': self.parse_tuic}
        for prefix, parser in parsers.items():
            if config_url.startswith(prefix):
                try: return parser(config_url)
                except: return None
        return None

    # --- Parsers ---
    def parse_vmess(self, u: str) -> Optional[Dict[str, Any]]:
        try:
            b64 = u[8:]; decoded = base64.b64decode(b64 + '=' * (-len(b64) % 4)).decode('utf-8')
            c = json.loads(decoded)
            return {'name': c.get('ps', ''), 'type': 'vmess', 'server': c.get('add'), 'port': int(c.get('port')), 'uuid': c.get('id'), 'alterId': int(c.get('aid', 0)), 'cipher': c.get('scy', 'auto'), 'tls': c.get('tls')=='tls', 'network': c.get('net', 'tcp'), 'ws-opts': {'path': c.get('path', '/'), 'headers': {'Host': c.get('host', '')}} if c.get('net')=='ws' else None, 'servername': c.get('sni', c.get('host'))}
        except: return None

    def parse_vless(self, u: str) -> Optional[Dict[str, Any]]:
        try:
            p = urlparse(u); q = parse_qs(p.query)
            return {'name': unquote(p.fragment), 'type': 'vless', 'server': p.hostname, 'port': p.port, 'uuid': p.username, 'tls': q.get('security',[''])[0] in ['tls','reality'], 'network': q.get('type',['tcp'])[0], 'servername': q.get('sni',[''])[0], 'flow': q.get('flow',[''])[0], 'reality-opts': {'public-key': q.get('pbk',[''])[0], 'short-id': q.get('sid',[''])[0]} if q.get('security',[''])[0]=='reality' else None, 'ws-opts': {'path': q.get('path',['/'])[0], 'headers': {'Host': q.get('host',[''])[0]}} if q.get('type',[''])[0]=='ws' else None}
        except: return None

    def parse_trojan(self, u: str) -> Optional[Dict[str, Any]]:
        try:
            p = urlparse(u); q = parse_qs(p.query)
            return {'name': unquote(p.fragment), 'type': 'trojan', 'server': p.hostname, 'port': p.port, 'password': p.username, 'sni': q.get('sni',[''])[0] or p.hostname}
        except: return None

    def parse_shadowsocks(self, u: str) -> Optional[Dict[str, Any]]:
        try:
            p = urlparse(u)
            if '@' in p.netloc:
                user = base64.b64decode(p.netloc.split('@')[0] + '='*4).decode()
                cipher, pw = user.split(':')
                return {'name': unquote(p.fragment), 'type': 'ss', 'server': p.hostname, 'port': p.port, 'cipher': cipher, 'password': pw}
        except: return None

    def parse_hysteria2(self, u: str) -> Optional[Dict[str, Any]]:
        try:
            p = urlparse(u); q = parse_qs(p.query)
            return {'name': unquote(p.fragment), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port, 'auth': p.username, 'up': q.get('up',[''])[0], 'down': q.get('down',[''])[0], 'sni': q.get('sni',[''])[0], 'skip-cert-verify': q.get('insecure',['0'])[0]=='1', 'obfs': q.get('obfs',[''])[0], 'obfs-password': q.get('obfs-password',[''])[0]}
        except: return None

    def parse_tuic(self, u: str) -> Optional[Dict[str, Any]]:
        try:
             p = urlparse(u); q = parse_qs(p.query)
             return {'name': unquote(p.fragment), 'type': 'tuic', 'server': p.hostname, 'port': p.port, 'uuid': p.username, 'password': q.get('password',[''])[0], 'sni': q.get('sni',[''])[0], 'skip-cert-verify': q.get('allow_insecure',['0'])[0]=='1'}
        except: return None

    def convert_to_singbox_outbound(self, p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not p: return None
        t = p['type']; out = {'type': t if t!='ss' else 'shadowsocks', 'tag': p['name'], 'server': p['server'], 'server_port': p['port']}
        if t=='vmess': out.update({'uuid': p['uuid'], 'alter_id': p['alterId'], 'security': p['cipher'], 'tls': {'enabled': True, 'server_name': p['servername']} if p.get('tls') else None})
        if t=='vless': out.update({'uuid': p['uuid'], 'flow': p.get('flow'), 'tls': {'enabled': True, 'server_name': p['servername'], 'reality': {'enabled': True, 'public_key': p['reality-opts']['public-key'], 'short_id': p['reality-opts']['short-id']} if p.get('reality-opts') else None} if p.get('tls') else None})
        if t=='trojan': out.update({'password': p['password'], 'tls': {'enabled': True, 'server_name': p['sni']}})
        if t=='ss': out.update({'method': p['cipher'], 'password': p['password']})
        if t in ['hysteria2','tuic']: out.update({'password': p.get('auth') or p.get('password'), 'tls': {'enabled': True, 'server_name': p['sni'], 'insecure': p.get('skip-cert-verify')}})
        if p.get('ws-opts'): out['transport'] = {'type': 'ws', 'path': p['ws-opts']['path'], 'headers': p['ws-opts']['headers']}
        return out

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found = set()
        for pattern in V2RAY_PATTERNS:
            found.update(pattern.findall(text))
        return {self._correct_config_type(u) for u in found if self._validate_config_type(u)}

    def fetch_subscription_content(self, url: str) -> str:
        try:
            if any(x in url for x in ['google.com', 't.me', 'instagram.com', 'youtube.com']): return ""
            print(f"      🌍 Fetching sub: {url[:40]}...")
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                content = resp.text
                try: content = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8', errors='ignore')
                except: pass
                return content
        except: pass
        return ""

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        try:
            print(f"🔍 Searching in chat {chat_id} (limit: {limit})...")
            count = 0
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                count += 1
                text_to_check = message.text or message.caption or ""
                
                # DEBUG PRINT: Show exactly what is being scanned
                if count <= 5: # Only show first 5 to avoid spam, but proves access
                    snippet = text_to_check[:50].replace('\n', ' ')
                    print(f"   🔹 Msg {message.id}: {snippet}...")

                texts_to_scan = [text_to_check]

                # -------------------------------------------------------------
                # ☢️ NUCLEAR FIX: ALWAYS CLEAN THE WHOLE TEXT
                # -------------------------------------------------------------
                # This ignores entities/formatting and blindly forces links together.
                # It fixes broken lines in quotes, code blocks, or normal text.
                if text_to_check:
                    nuclear_clean = text_to_check.replace('\n', '').replace(' ', '')
                    texts_to_scan.append(nuclear_clean)
                # -------------------------------------------------------------

                # Text Links
                found_urls = URL_PATTERN.findall(text_to_check)
                if message.entities:
                    for entity in message.entities:
                         if entity.type == enums.MessageEntityType.TEXT_LINK and entity.url: found_urls.append(entity.url)
                for url in found_urls:
                    if sub := self.fetch_subscription_content(url): texts_to_scan.append(sub)

                # Base64
                for b64_str in BASE64_PATTERN.findall(text_to_check):
                    try: texts_to_scan.append(base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore'))
                    except: continue

                # Extract
                initial = len(self.raw_configs)
                for txt in texts_to_scan:
                    if txt: self.raw_configs.update(self.extract_configs_from_text(txt))
                
                if len(self.raw_configs) > initial:
                    print(f"      🎉 Found {len(self.raw_configs) - initial} configs in Msg {message.id}!")

            if count == 0:
                print(f"❌ ERROR: No messages found in {chat_id}. Check permissions/ID!")

        except (ChannelInvalid, ChannelPrivate): print(f"❌ Error: Chat {chat_id} is INVALID/PRIVATE.")
        except FloodWait as e:
            await asyncio.sleep(e.value + 5)
            await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e: print(f"❌ Error scanning chat {chat_id}: {e}")

    def save_files(self):
        print(f"\n⚙️ Saving {len(self.raw_configs)} configs...")
        if not self.raw_configs: return
        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f: f.write("\n".join(self.raw_configs))
        
        valid = []
        for u in self.raw_configs:
            if p := self.parse_config_for_clash(u):
                host = p.get('servername') or p.get('sni') or p.get('server')
                cc = get_country_iso_code(host)
                flag = COUNTRY_FLAGS.get(cc, '🏳️')
                p['name'] = f"{cc} Config_jo-{len(valid)+1:02d}"
                valid.append(p)
        
        print(f"👍 Processed {len(valid)} valid configs.")
        
        try:
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f: yaml.dump({'proxies': valid}, f, allow_unicode=True)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f: json.dump({'outbounds': [self.convert_to_singbox_outbound(v) for v in valid]}, f, indent=4)
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join([v['name'] for v in valid]))
            print("✅ Files saved.")
        except Exception as e: print(f"❌ Save error: {e}")

async def main():
    print("🚀 Starting config extractor (NUCLEAR MODE)...")
    load_ip_data()
    extractor = V2RayExtractor()
    async with extractor.client:
        for c in CHANNELS: await extractor.find_raw_configs_from_chat(c, CHANNEL_SEARCH_LIMIT)
        for g in GROUPS: await extractor.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT)
    extractor.save_files()

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]): print("❌ Secrets missing.")
    else: asyncio.run(main())
