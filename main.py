import re
import asyncio
import base64
import json
import yaml
import os
import uuid
import requests
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait
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
        print(f"❌ CRITICAL: GeoIP database not found at '{GEOIP_DATABASE_PATH}'. Flags will be disabled.")
    except Exception as e:
        print(f"❌ CRITICAL: Failed to load GeoIP database: {e}")

COUNTRY_FLAGS = {
    'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇧', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'
}

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
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
        except ValueError: pass
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    def get_country_iso_code(self, hostname: str) -> str:
        if not hostname: return "N/A"
        if not GEOIP_READER: return "N/A"
        try:
            ip_address = hostname
            try: socket.inet_aton(hostname)
            except: ip_address = socket.gethostbyname(hostname)
            response = GEOIP_READER.country(ip_address)
            return response.country.iso_code or "N/A"
        except: return "N/A"

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try:
            parsed = urlparse(ss_url)
            if not parsed.hostname: return False
            try:
                base64.b64decode(parsed.netloc.split('@')[0] + '=' * 4)
                return True
            except: return ':' in parsed.netloc.split('@')[0]
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        if config_url.startswith('ss://') and 'v=2' in config_url: return config_url.replace('ss://', 'vmess://', 1)
        return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        try:
            if config_url.startswith('vless://'): return True
            elif config_url.startswith('vmess://'):
                decoded_str = base64.b64decode(config_url[8:] + '=' * 4).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))
            elif config_url.startswith('trojan://'): return True
            elif config_url.startswith('ss://'): return self._is_valid_shadowsocks(config_url)
            return True
        except: return False

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        parsers = {'vmess://': self.parse_vmess, 'vless://': self.parse_vless, 'trojan://': self.parse_trojan, 'ss://': self.parse_shadowsocks, 'hysteria2://': self.parse_hysteria2, 'hy2://': self.parse_hysteria2, 'tuic://': self.parse_tuic}
        for prefix, parser in parsers.items():
            if config_url.startswith(prefix):
                try: return parser(config_url)
                except: return None
        return None

    def parse_vmess(self, vmess_url: str) -> Optional[Dict[str, Any]]:
        decoded_str = base64.b64decode(vmess_url[8:] + '=' * 4).decode('utf-8')
        c = json.loads(decoded_str)
        ws_opts = None
        if c.get('net') == 'ws':
            ws_opts = {'path': c.get('path', '/'), 'headers': {'Host': c.get('host', '')}}
        return {'name': c.get('ps', ''), 'type': 'vmess', 'server': c.get('add'), 'port': int(c.get('port', 443)), 'uuid': c.get('id'), 'alterId': int(c.get('aid', 0)), 'cipher': c.get('scy', 'auto'), 'tls': c.get('tls')=='tls', 'network': c.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'servername': c.get('sni', c.get('host'))}

    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(vless_url), parse_qs(urlparse(vless_url).query)
        ws_opts, reality_opts = None, None
        if q.get('type', [''])[0] == 'ws':
            ws_opts = {'path': q.get('path', ['/'])[0], 'headers': {'Host': q.get('host', [''])[0]}}
        if q.get('security', [''])[0] == 'reality':
            reality_opts = {'public-key': q.get('pbk', [''])[0], 'short-id': q.get('sid', [''])[0]}
        return {'name': unquote(p.fragment or ''), 'type': 'vless', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'udp': True, 'tls': q.get('security', [''])[0] in ['tls', 'reality'], 'network': q.get('type', ['tcp'])[0], 'servername': q.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(trojan_url), parse_qs(urlparse(trojan_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443, 'password': p.username, 'udp': True, 'sni': q.get('sni', [p.hostname])[0]}

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        p = urlparse(ss_url)
        if '@' in p.netloc:
            u = base64.b64decode(p.netloc.split('@')[0] + '='*4).decode('utf-8')
            c, pw = u.split(':')
            return {'name': unquote(p.fragment or ''), 'type': 'ss', 'server': p.hostname, 'port': int(p.port), 'cipher': c, 'password': pw, 'udp': True}
        return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(hy2_url), parse_qs(urlparse(hy2_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port or 443, 'auth': p.username, 'up': q.get('up', [''])[0], 'down': q.get('down', [''])[0], 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('insecure', ['0'])[0]=='1'}

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(tuic_url), parse_qs(urlparse(tuic_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'tuic', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': q.get('password', [''])[0], 'udp': True, 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('allow_insecure', ['0'])[0]=='1'}

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not proxy: return None
        t = proxy['type']
        out = {'type': t if t!='ss' else 'shadowsocks', 'tag': proxy['name'], 'server': proxy['server'], 'server_port': proxy['port']}
        if t=='vmess': out.update({'uuid': proxy['uuid'], 'alter_id': proxy['alterId'], 'security': proxy['cipher'], 'tls': {'enabled': True, 'server_name': proxy['servername']} if proxy.get('tls') else None})
        if t=='vless': out.update({'uuid': proxy['uuid'], 'flow': proxy.get('flow',''), 'tls': {'enabled': True, 'server_name': proxy['servername'], 'reality': {'enabled': True, 'public_key': proxy.get('reality-opts',{}).get('public-key'), 'short_id': proxy.get('reality-opts',{}).get('short-id')} if proxy.get('reality-opts') else None} if proxy.get('tls') else None})
        if t=='trojan': out.update({'password': proxy['password'], 'tls': {'enabled': True, 'server_name': proxy.get('sni')}})
        if t=='ss': out.update({'method': proxy['cipher'], 'password': proxy['password']})
        if t in ['hysteria2','tuic']: out.update({'password': proxy.get('auth') or proxy.get('password'), 'tls': {'enabled': True, 'server_name': proxy['sni'], 'insecure': proxy.get('skip-cert-verify')}})
        if proxy.get('ws-opts'): out['transport'] = {'type': 'ws', 'path': proxy['ws-opts']['path'], 'headers': proxy['ws-opts']['headers']}
        return out

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found = set()
        for pattern in V2RAY_PATTERNS:
            found.update(pattern.findall(text))
        return {corrected for url in found if (corrected := self._correct_config_type(url.strip())) and self._validate_config_type(corrected)}

    def fetch_subscription_content(self, url: str) -> str:
        # === [RE-ADDED FOR GO/SUB LINKS] ===
        try:
            if any(x in url for x in ['google.com', 't.me', 'instagram.com', 'youtube.com']): return ""
            print(f"      🌍 Fetching sub link: {url[:50]}...")
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                content = resp.text
                try: content = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8', errors='ignore')
                except: pass
                return content
        except: pass
        return ""

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        chat_title = str(chat_id)
        chat_found_count = 0
        
        try:
            try:
                chat_obj = await self.client.get_chat(chat_id)
                chat_title = chat_obj.title or chat_obj.username or str(chat_id)
            except: pass
            
            print(f"🔍 Searching in: {chat_title} (ID: {chat_id})")
            initial_count_for_this_chat = len(self.raw_configs)

            async for message in self.client.get_chat_history(chat_id, limit=limit):
                text_to_check = message.text or message.caption or ""
                texts_to_scan = [text_to_check]
                
                # 1. URL Extraction (Re-added)
                found_urls = URL_PATTERN.findall(text_to_check)
                if message.entities:
                    for entity in message.entities:
                         if entity.type == enums.MessageEntityType.TEXT_LINK and entity.url: found_urls.append(entity.url)
                for url in found_urls:
                    if sub := self.fetch_subscription_content(url): texts_to_scan.append(sub)

                # 2. Entity Parsing (Code/Pre)
                if message.entities:
                    for entity in message.entities:
                        if entity.type in [enums.MessageEntityType.CODE, enums.MessageEntityType.PRE, getattr(enums.MessageEntityType, 'BLOCKQUOTE', 'blockquote')]:
                            raw_segment = text_to_check[entity.offset : entity.offset + entity.length]
                            # Clean newlines to fix broken configs
                            cleaned_segment = raw_segment.replace('\n', '').replace(' ', '')
                            texts_to_scan.append(cleaned_segment)

                # 3. Base64
                for b64_str in BASE64_PATTERN.findall(text_to_check):
                    try: texts_to_scan.append(base64.b64decode(b64_str + '=' * 4).decode('utf-8', errors='ignore'))
                    except: continue
                
                # 4. Extract
                for text in texts_to_scan:
                    if text: self.raw_configs.update(self.extract_configs_from_text(text))
            
            chat_found_count = len(self.raw_configs) - initial_count_for_this_chat
            print(f"   📊 Found {chat_found_count} new configs in {chat_title}")

        except FloodWait as e:
            if retries > 0:
                print(f"⏳ FloodWait {e.value}s in {chat_id}. Sleeping...")
                await asyncio.sleep(e.value + 2)
                await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e:
            print(f"❌ Error scanning {chat_id}: {e}")

    def save_files(self):
        print(f"\n⚙️ Total unique configs extracted: {len(self.raw_configs)}")
        if not self.raw_configs: return
        
        with open(OUTPUT_ORIGINAL_CONFIGS, 'w') as f: f.write("\n".join(sorted(self.raw_configs)))
        
        valid_proxies = []
        for i, url in enumerate(sorted(self.raw_configs), 1):
            if p := self.parse_config_for_clash(url):
                if 'speedtest' in (p.get('server') or ''): continue
                cc = self.get_country_iso_code(p.get('server'))
                p['name'] = f"{cc} Config-{i:03d}"
                valid_proxies.append(p)

        if valid_proxies:
            # Clash
            clash_conf = self.build_pro_config(valid_proxies, [x['name'] for x in valid_proxies])
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f: yaml.dump(clash_conf, f, allow_unicode=True)
            
            # Singbox
            sb_out = [self.convert_to_singbox_outbound(p) for p in valid_proxies]
            final_sb = self.build_sing_box_config(valid_proxies)
            final_sb['outbounds'] = [x for x in final_sb['outbounds'] if x['tag'] != 'auto'] + [o for o in sb_out if o]
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f: json.dump(final_sb, f, indent=2)

            # TXT
            with open(OUTPUT_TXT, 'w') as f: f.write("\n".join(sorted(self.raw_configs)))

    def build_pro_config(self, proxies, names):
        return {'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090', 'proxies': proxies, 'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *names]}, {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300}], 'rules': ['MATCH,PROXY']}

    def build_sing_box_config(self, proxies):
        return {"log": {"level": "warn", "timestamp": True}, "dns": {"servers": [{"tag": "dns_proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"}, {"tag": "dns_direct", "address": "1.1.1.1"}], "rules": [{"outbound": "PROXY", "server": "dns_proxy"}], "final": "dns_direct"}, "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080, "sniff": True}], "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}, {"type": "dns", "tag": "dns-out"}, {"type":"selector","tag":"PROXY","outbounds":["auto"],"default":"auto"},{"type":"urltest","tag":"auto","outbounds":[],"url":"http://www.gstatic.com/generate_204","interval":"5m"}], "route": {"rules": [{"protocol": "dns", "outbound": "dns-out"}], "final": "PROXY"}}

async def main():
    print("🚀 Starting Config Extractor (THE FIXER)...")
    load_ip_data()
    extractor = V2RayExtractor()
    async with extractor.client:
        print("🔄 Refreshing dialogs map...")
        async for d in extractor.client.get_dialogs(limit=50): pass
        
        for c in CHANNELS: await extractor.find_raw_configs_from_chat(c, CHANNEL_SEARCH_LIMIT)
        for g in GROUPS: await extractor.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT)
    
    extractor.save_files()

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]): print("❌ Secrets missing.")
    else: asyncio.run(main())
