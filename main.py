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

# فایل‌های سیستم هفتگی و تفکیک کشورها
WEEKLY_FILE = "conf-week.txt"
HISTORY_FILE = "conf-week-history.json"
GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'

# تنظیمات فیلتر زمانی کانال‌ها (کانال‌های قدیمی‌تر از این تعداد روز اسکن نمی‌شوند)
CHANNEL_MAX_INACTIVE_DAYS = 4

V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'), re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'), re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"), re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

COUNTRY_FLAGS = {
    'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷', 'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪', 'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇬', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲', 'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾', 'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺', 'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰', 'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺', 'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬', 'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪', 'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹', 'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧', 'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲', 'ZW': '🇿🇼'
}

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
            if '@' in ss_url:
                parts = ss_url.split('@')
                if len(parts) >= 2:
                    return True
            return False
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
        try:
            content = ss_url[5:]
            name = ''
            if '#' in content:
                content, name_encoded = content.split('#', 1)
                name = unquote(name_encoded)
            if '@' not in content:
                return None
            userinfo_b64, server_part = content.rsplit('@', 1)
            if ':' in server_part:
                server_host, server_port_str = server_part.rsplit(':', 1)
                port = int(server_port_str)
            else:
                return None
            userinfo_b64_padded = userinfo_b64 + '=' * (-len(userinfo_b64) % 4)
            try:
                userinfo_bytes = base64.b64decode(userinfo_b64_padded, validate=False)
                userinfo_str = userinfo_bytes.decode('utf-8')
            except:
                userinfo_bytes = base64.urlsafe_b64decode(userinfo_b64_padded)
                userinfo_str = userinfo_bytes.decode('utf-8')
            if ':' in userinfo_str:
                cipher, password = userinfo_str.split(':', 1)
                return {
                    'name': name, 'type': 'ss', 'server': server_host, 'port': port, 'cipher': cipher, 'password': password, 'udp': True
                }
            return None
        except Exception as e:
            return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(hy2_url), parse_qs(urlparse(hy2_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port or 443, 'auth': p.username, 'up': q.get('up', [''])[0], 'down': q.get('down', [''])[0], 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('insecure', ['0'])[0]=='1'}

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(tuic_url), parse_qs(urlparse(tuic_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'tuic', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': q.get('password', [''])[0], 'udp': True, 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('allow_insecure', ['0'])[0]=='1'}

    def generate_sip002_link(self, proxy: Dict[str, Any]) -> str:
        try:
            userinfo = f"{proxy['cipher']}:{proxy['password']}"
            userinfo_b64 = base64.urlsafe_b64encode(userinfo.encode('utf-8')).decode('utf-8').rstrip('=')
            name = proxy.get('name', 'Shadowsocks')
            return f"ss://{userinfo_b64}@{proxy['server']}:{proxy['port']}#{name}"
        except Exception as e:
            return None

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

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        local_configs = set()
        try:
            # ==========================================================
            # NEW LOGIC: Skip channels inactive for more than 4 days
            # ==========================================================
            is_active = False
            try:
                # Check only the latest message to see the date
                async for last_msg in self.client.get_chat_history(chat_id, limit=1):
                    # If message date is NEWER than (NOW - 4 DAYS), keep it
                    if last_msg.date > (datetime.datetime.now() - datetime.timedelta(days=CHANNEL_MAX_INACTIVE_DAYS)):
                        is_active = True
                    break # We only need to check the first (latest) message
            except Exception as e:
                # If we can't check history (e.g. private/banned), assume inactive or log error
                print(f"⚠️ Could not check activity for {chat_id}: {e}")
                pass

            if not is_active:
                print(f"💤 Skipping {chat_id}: Inactive for >{CHANNEL_MAX_INACTIVE_DAYS} days or empty.")
                return
            # ==========================================================

            async for message in self.client.get_chat_history(chat_id, limit=limit):
                text_to_check = message.text or message.caption or ""
                texts_to_scan = [text_to_check]
               if message.entities:
                    # لیست انواع مجاز شامل کد، کوت معمولی و کوت بازشو
                    valid_types = [
                        enums.MessageEntityType.CODE,
                        enums.MessageEntityType.PRE,
                    ]
                    
                    # اضافه کردن ایمن انواع کوت (چون ممکن است نام‌ها در نسخه‌های مختلف کمی متفاوت باشد)
                    for attr in ['BLOCKQUOTE', 'EXPANDABLE_BLOCKQUOTE']:
                        if hasattr(enums.MessageEntityType, attr):
                            valid_types.append(getattr(enums.MessageEntityType, attr))

                    for entity in message.entities:
                        if entity.type in valid_types:
                            raw_segment = text_to_check[entity.offset : entity.offset + entity.length]
                            cleaned_segment = raw_segment.replace('\n', '').replace(' ', '')
                            texts_to_scan.append(cleaned_segment)
                for b64_str in BASE64_PATTERN.findall(text_to_check):
                    try:
                        decoded = base64.b64decode(b64_str + '=' * 4).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded)
                    except: continue
                for text in texts_to_scan:
                    if text: local_configs.update(self.extract_configs_from_text(text))
            print(f"   ✅ Fetched {len(local_configs)} configs from {chat_id}")
            self.raw_configs.update(local_configs)
        except FloodWait as e:
            if retries > 0:
                print(f"⏳ FloodWait {e.value}s in {chat_id}. Sleeping...")
                await asyncio.sleep(e.value + 2)
                await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e:
            print(f"❌ Error scanning {chat_id}: {e}")

    # =================================================================================
    # SPLIT CONFIGS INTO TOP COUNTRIES (With IP Prioritization)
    # =================================================================================
    def split_configs_by_country(self, links: List[str]):
        target_countries = {
            'US': 'conf-US.txt', 'DE': 'conf-DE.txt', 'NL': 'conf-NL.txt', 'GB': 'conf-UK.txt', 'FR': 'conf-FR.txt'
        }
        print(f"\n🌍 Separating configs into {len(target_countries)} top countries...")
        country_buckets = {code: [] for code in target_countries}
        for link in links:
            proxy = self.parse_config_for_clash(link)
            if not proxy: continue
            # Prioritize SERVER IP over SNI/Host
            host = proxy.get('server')
            if not host: continue
            iso_code = self.get_country_iso_code(host)
            if iso_code in target_countries:
                country_buckets[iso_code].append(link)
        for code, filename in target_countries.items():
            configs = country_buckets[code]
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("\n".join(sorted(configs)))
            if configs: print(f"   ✅ Saved {len(configs)} configs to {filename}")

    # =================================================================================
    # SMART WEEKLY ROLLING WINDOW
    # =================================================================================
    def handle_weekly_file(self, new_configs: List[str]):
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(days=7)
        history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f:
                    history = json.load(f)
            except: history = {}

        new_history = {}
        kept_count = 0
        for base_cfg, meta in history.items():
            try:
                added_date = datetime.datetime.fromisoformat(meta['date'])
                if added_date > cutoff:
                    new_history[base_cfg] = meta
                    kept_count += 1
            except: pass

        added_count = 0
        for cfg in new_configs:
            base = cfg.split('#')[0]
            if base not in new_history:
                new_history[base] = {
                    "link": cfg,
                    "date": now.isoformat()
                }
                added_count += 1
        
        with open(HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=2)
        final_links = [meta['link'] for meta in new_history.values()]
        with open(WEEKLY_FILE, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(final_links)))
        
        print(f"📅 Rolling Window Update: Kept {kept_count} old, Added {added_count} new. Total: {len(final_links)}")
        self.split_configs_by_country(final_links)

    def save_files(self):
        print(f"\n⚙️ ∑ Total Unique Configs Found: {len(self.raw_configs)}")
        if not self.raw_configs:
            print("⚠️ No configs found.")
            return
        
        valid_configs = set()
        for url in self.raw_configs:
            try:
                if not url.startswith('ss://'):
                    if not urlparse(url).hostname: continue 
                if url.startswith('vless://'):
                    if parse_qs(urlparse(url).query).get('security', [''])[0] == 'none': continue 
                valid_configs.add(url)
            except: continue

        proxies_list_clash, renamed_txt_configs = [], []
        
        for i, url in enumerate(sorted(list(valid_configs)), 1):
            if not (proxy := self.parse_config_for_clash(url)): continue
            
            # Prioritize SERVER IP over SNI/Host for Main Files too
            host_to_check = proxy.get('server') or proxy.get('servername') or proxy.get('sni')
            
            country_code = self.get_country_iso_code(host_to_check)
            country_flag = COUNTRY_FLAGS.get(country_code, '🏳️')
            name_compatible = f"{country_code} Config_jo-{i:02d}"
            proxy['name'] = name_compatible
            proxies_list_clash.append(proxy)
            
            name_with_flag = f"{country_flag} Config_jo-{i:02d}"
            if proxy['type'] == 'ss':
                ss_p = proxy.copy(); ss_p['name'] = name_with_flag
                clean = self.generate_sip002_link(ss_p)
                renamed_txt_configs.append(clean if clean else f"{url.split('#')[0]}#{name_with_flag}")
            else:
                try:
                    parsed = list(urlparse(url)); parsed[5] = name_with_flag
                    renamed_txt_configs.append(urlunparse(parsed))
                except: renamed_txt_configs.append(f"{url.split('#')[0]}#{name_with_flag}")

        try:
            with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(self.raw_configs))))
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(renamed_txt_configs)))
            
            os.makedirs('rules', exist_ok=True)
            if proxies_list_clash:
                all_names = [p['name'] for p in proxies_list_clash]
                with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
                    yaml.dump(self.build_pro_config(proxies_list_clash, all_names), f, allow_unicode=True, sort_keys=False, indent=2, width=120)
                with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f:
                    json.dump(self.build_sing_box_config(proxies_list_clash), f, ensure_ascii=False, indent=4)
        except Exception as e: print(f"❌ Error saving files: {e}")

        self.handle_weekly_file(renamed_txt_configs)
        print("\n✨ All operations completed successfully!")

    def build_pro_config(self, proxies, proxy_names):
        # فیلتر کردن پروکسی‌های ناقص برای جلوگیری از ارور uuid missing در کلش
        clean_proxies = []
        clean_names = []
        for p in proxies:
            # بررسی فیلدهای حیاتی برای هر پروتکل
            if p.get('type') in ['vless', 'vmess', 'tuic']:
                if not p.get('uuid'): continue
            if p.get('type') == 'trojan' and not p.get('password'): continue
            if not p.get('server') or not p.get('port'): continue
            
            clean_proxies.append(p)
            clean_names.append(p['name'])

        return {
            'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090',
            'dns': {'enable': True, 'listen': '0.0.0.0:53', 'default-nameserver': ['8.8.8.8', '1.1.1.1'], 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'fallback': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'], 'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']}},
            'proxies': clean_proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *clean_names]},
                {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': clean_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
                {'name': '🇮🇷 Iran', 'type': 'select', 'proxies': ['DIRECT', 'PROXY']},
                {'name': '🛑 Block-Ads', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}
            ],
            'rule-providers': {
                'iran_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/iran-domains.txt", 'path': './rules/iran_domains.txt', 'interval': 86400},
                'blocked_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/blocked-domains.txt", 'path': './rules/blocked_domains.txt', 'interval': 86400},
                'ad_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/ad-domains.txt", 'path': './rules/ad_domains.txt', 'interval': 86400}
            },
            'rules': ['RULE-SET,ad_domains,🛑 Block-Ads', 'RULE-SET,blocked_domains,PROXY', 'RULE-SET,iran_domains,🇮🇷 Iran', 'GEOIP,IR,🇮🇷 Iran', 'MATCH,PROXY']
        }

    def build_sing_box_config(self, proxies_clash: List[Dict[str, Any]]) -> Dict[str, Any]:
        outbounds = [p for p in (self.convert_to_singbox_outbound(proxy) for proxy in proxies_clash) if p]
        proxy_tags = [p['tag'] for p in outbounds]
        return {"log": {"level": "warn", "timestamp": True}, "dns": {"servers": [{"tag": "dns_proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"}, {"tag": "dns_direct", "address": "1.1.1.1"}], "rules": [{"outbound": "PROXY", "server": "dns_proxy"}, {"rule_set": ["geosite-ir", "geoip-ir"], "server": "dns_direct"}, {"domain_suffix": ".ir", "server": "dns_direct"}], "final": "dns_direct", "strategy": "ipv4_only"}, "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080, "sniff": True}], "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}, {"type": "dns", "tag": "dns-out"}, *outbounds, {"type": "selector", "tag": "PROXY", "outbounds": ["auto", *proxy_tags], "default": "auto"}, {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://www.gstatic.com/generate_204", "interval": "5m"}], "route": {"rule_set": [{"tag": "geosite-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs", "download_detour": "direct"}, {"tag": "geoip-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geoip-ir.srs", "download_detour": "direct"}], "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct"}, {"ip_is_private": True, "outbound": "direct"}], "final": "PROXY"}}

async def main():
    print("🚀 Starting config extractor...")
    load_ip_data()
    extractor = V2RayExtractor()
    async with extractor.client:
        print("🔄 Refreshing dialogs...")
        async for d in extractor.client.get_dialogs(): pass
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks: await asyncio.gather(*tasks)
        else: print("❌ No channels or groups defined for searching.")
    extractor.save_files()

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ Error: One or more required secrets (API_ID, API_HASH, SESSION_STRING) are not set.")
    else:
        asyncio.run(main())
