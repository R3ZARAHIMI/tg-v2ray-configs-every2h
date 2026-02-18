import re
import asyncio
import base64
import json
import yaml
import os
import datetime
import ipaddress
import socket
import geoip2.database
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

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
OUTPUT_NO_CF = "Config_no_cf.txt"

WEEKLY_FILE = "conf-week.txt"
HISTORY_FILE = "conf-week-history.json"
GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'

NO_CF_HISTORY_FILE = "no_cf_history.json"
BLOCKED_IPS_FILE = "blocked_ips.txt"

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
BLOCKED_NETWORKS = []

def load_ip_data():
    global GEOIP_READER
    try:
        GEOIP_READER = geoip2.database.Reader(GEOIP_DATABASE_PATH)
        print(f"✅ Successfully loaded GeoIP database.")
    except Exception as e:
        print(f"❌ Failed to load GeoIP database: {e}")

def load_blocked_ips():
    global BLOCKED_NETWORKS
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            BLOCKED_NETWORKS.append(ipaddress.ip_network(line, strict=False))
                        except ValueError: pass
            print(f"🚫 Loaded {len(BLOCKED_NETWORKS)} blocked IP ranges.")
        except Exception as e: pass

def is_clean_ip(host: str) -> bool:
    """بررسی اینکه آیا آی‌پی معتبر و غیر فیلتر شده است."""
    try:
        ip = ipaddress.ip_address(host)
        # حذف آی‌پی‌های داخلی و لوکال
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False 
        return True 
    except ValueError:
        return False 

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
        self._country_cache: Dict[str, str] = {}

    def get_country_iso_code(self, hostname: str) -> str:
        if not hostname or not GEOIP_READER: return "N/A"
        if hostname in self._country_cache: return self._country_cache[hostname]
        try:
            ip_address = hostname
            try: socket.inet_aton(hostname)
            except:
                try: ip_address = socket.gethostbyname(hostname)
                except:
                    self._country_cache[hostname] = "N/A"
                    return "N/A"
            response = GEOIP_READER.country(ip_address)
            result = response.country.iso_code or "N/A"
            self._country_cache[hostname] = result
            return result
        except:
            self._country_cache[hostname] = "N/A"
            return "N/A"

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
            elif config_url.startswith('ss://'): return '@' in config_url
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
        ws_opts, grpc_opts, h2_opts = None, None, None
        if c.get('net') == 'ws':
            ws_opts = {'path': c.get('path', '/'), 'headers': {'Host': c.get('host', '')}}
        elif c.get('net') == 'grpc':
            grpc_opts = {'grpc-service-name': c.get('path', '')}
        elif c.get('net') == 'h2':
            h2_opts = {'path': c.get('path', '/'), 'host': [h.strip() for h in c.get('host', '').split(',') if h.strip()]}
        return {'name': c.get('ps', ''), 'type': 'vmess', 'server': c.get('add'), 'port': int(c.get('port', 443)), 'uuid': c.get('id'), 'alterId': int(c.get('aid', 0)), 'cipher': c.get('scy', 'auto'), 'tls': c.get('tls')=='tls', 'network': c.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'grpc-opts': grpc_opts, 'h2-opts': h2_opts, 'servername': c.get('sni', c.get('host'))}

    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(vless_url), parse_qs(urlparse(vless_url).query)
        ws_opts, reality_opts, grpc_opts = None, None, None
        network = q.get('type', ['tcp'])[0]
        if network == 'ws':
            ws_opts = {'path': q.get('path', ['/'])[0], 'headers': {'Host': q.get('host', [''])[0]}}
        elif network == 'grpc':
            grpc_opts = {'grpc-service-name': q.get('serviceName', [''])[0]}
        if q.get('security', [''])[0] == 'reality':
            reality_opts = {'public-key': q.get('pbk', [''])[0], 'short-id': q.get('sid', [''])[0]}
        return {'name': unquote(p.fragment or ''), 'type': 'vless', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'udp': True, 'tls': q.get('security', [''])[0] in ['tls', 'reality'], 'flow': q.get('flow', [None])[0], 'client-fingerprint': q.get('fp', [None])[0], 'network': network, 'servername': q.get('sni', [None])[0], 'ws-opts': ws_opts, 'grpc-opts': grpc_opts, 'reality-opts': reality_opts}

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(trojan_url), parse_qs(urlparse(trojan_url).query)
        network = q.get('type', ['tcp'])[0]
        ws_opts, grpc_opts = None, None
        if network == 'ws':
            ws_opts = {'path': q.get('path', ['/'])[0], 'headers': {'Host': q.get('host', [''])[0]}}
        elif network == 'grpc':
            grpc_opts = {'grpc-service-name': q.get('serviceName', [''])[0]}
        return {'name': unquote(p.fragment or ''), 'type': 'trojan', 'server': p.hostname, 'port': p.port or 443, 'password': p.username, 'udp': True, 'sni': q.get('sni', [None])[0], 'network': network, 'ws-opts': ws_opts, 'grpc-opts': grpc_opts, 'client-fingerprint': q.get('fp', [None])[0]}

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            content = ss_url[5:]
            name = unquote(content.split('#', 1)[1]) if '#' in content else ''
            content = content.split('#', 1)[0]
            if '@' not in content: return None
            userinfo_b64, server_part = content.rsplit('@', 1)
            server_host, server_port = server_part.rsplit(':', 1)
            userinfo = base64.b64decode(userinfo_b64 + '=' * (-len(userinfo_b64) % 4)).decode('utf-8')
            cipher, password = userinfo.split(':', 1)
            return {'name': name, 'type': 'ss', 'server': server_host, 'port': int(server_port), 'cipher': cipher, 'password': password, 'udp': True}
        except: return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(hy2_url), parse_qs(urlparse(hy2_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'hysteria2', 'server': p.hostname, 'port': p.port or 443, 'password': p.username or p.password, 'sni': q.get('sni', [p.hostname])[0], 'skip-cert-verify': q.get('insecure', ['0'])[0]=='1'}

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        p, q = urlparse(tuic_url), parse_qs(urlparse(tuic_url).query)
        return {'name': unquote(p.fragment or ''), 'type': 'tuic', 'server': p.hostname, 'port': p.port or 443, 'uuid': p.username, 'password': q.get('password', [''])[0], 'sni': q.get('sni', [p.hostname])[0]}

    def generate_sip002_link(self, proxy: Dict[str, Any]) -> str:
        try:
            userinfo = f"{proxy['cipher']}:{proxy['password']}"
            userinfo_b64 = base64.urlsafe_b64encode(userinfo.encode('utf-8')).decode('utf-8').rstrip('=')
            return f"ss://{userinfo_b64}@{proxy['server']}:{proxy['port']}#{proxy.get('name', 'Shadowsocks')}"
        except: return None

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not proxy: return None
        t = proxy['type']
        out = {'type': t if t!='ss' else 'shadowsocks', 'tag': proxy['name'], 'server': proxy['server'], 'server_port': proxy['port']}
        if t=='vmess': out.update({'uuid': proxy['uuid'], 'alter_id': proxy['alterId'], 'security': proxy['cipher'], 'tls': {'enabled': True, 'server_name': proxy['servername']} if proxy.get('tls') else None})
        if t=='vless': out.update({'uuid': proxy['uuid'], 'flow': proxy.get('flow',''), 'tls': {'enabled': True, 'server_name': proxy['servername'], 'reality': {'enabled': True, 'public_key': proxy.get('reality-opts',{}).get('public-key'), 'short_id': proxy.get('reality-opts',{}).get('short-id')} if proxy.get('reality-opts') else None} if proxy.get('tls') else None})
        if t=='trojan': out.update({'password': proxy['password'], 'tls': {'enabled': True, 'server_name': proxy.get('sni')}})
        if t=='ss': out.update({'method': proxy['cipher'], 'password': proxy['password']})
        if t in ['hysteria2','tuic']: out.update({'password': proxy.get('password'), 'tls': {'enabled': True, 'server_name': proxy.get('sni'), 'insecure': proxy.get('skip-cert-verify')}})
        if proxy.get('ws-opts'): out['transport'] = {'type': 'ws', 'path': proxy['ws-opts']['path'], 'headers': proxy['ws-opts']['headers']}
        return out

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found = set()
        for pattern in V2RAY_PATTERNS: found.update(pattern.findall(text))
        clean_configs = set()
        for url in found:
            url = url.strip()
            if not url.startswith('vmess://') and '#' in url: url = url.split('#')[0]
            if corrected := self._correct_config_type(url):
                if self._validate_config_type(corrected): clean_configs.add(corrected)
        return clean_configs

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        local_configs = set()
        MAX_CONFIGS_PER_SOURCE = 20
        try:
            is_active = False
            async for last_msg in self.client.get_chat_history(chat_id, limit=1):
                if last_msg.date > (datetime.datetime.now() - datetime.timedelta(days=CHANNEL_MAX_INACTIVE_DAYS)):
                    is_active = True
                break 
            if not is_active: return

            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if len(local_configs) >= MAX_CONFIGS_PER_SOURCE: break
                text_to_check = message.text or message.caption or ""
                texts_to_scan = [text_to_check]
                if message.entities:
                    valid_types = [enums.MessageEntityType.CODE, enums.MessageEntityType.PRE]
                    for entity in message.entities:
                        if entity.type in valid_types:
                            texts_to_scan.append(text_to_check[entity.offset : entity.offset + entity.length].replace('\n', '').replace(' ', ''))
                for b64_str in BASE64_PATTERN.findall(text_to_check):
                    try: texts_to_scan.append(base64.b64decode(b64_str + '=' * 4).decode('utf-8', errors='ignore'))
                    except: continue
                for text in texts_to_scan:
                    if text:
                        extracted = self.extract_configs_from_text(text)
                        local_configs.update(extracted)
                        if len(local_configs) >= MAX_CONFIGS_PER_SOURCE: break
            
            final_configs = list(local_configs)[:MAX_CONFIGS_PER_SOURCE]
            print(f"   ✅ Fetched {len(final_configs)} configs from {chat_id}")
            self.raw_configs.update(final_configs)
        except FloodWait as e:
            if retries > 0:
                await asyncio.sleep(e.value + 2)
                await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)

    def handle_weekly_file(self, new_configs: List[str]):
        now = datetime.datetime.now()
        history = {}
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f: history = json.load(f)
            except: pass
        new_history = {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(days=7))}
        for cfg in new_configs:
            base = cfg.split('#')[0]
            if base not in new_history: new_history[base] = {"link": cfg, "date": now.isoformat()}
        with open(HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=2)
        final_links = [v['link'] for v in new_history.values()]
        with open(WEEKLY_FILE, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(final_links)))

    def handle_no_cf_retention(self, new_configs: List[str]):
        now = datetime.datetime.now()
        history = {}
        if os.path.exists(NO_CF_HISTORY_FILE):
            try:
                with open(NO_CF_HISTORY_FILE, 'r') as f: history = json.load(f)
            except: pass
        new_history = {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v['date']) > (now - datetime.timedelta(hours=72))}
        for cfg in new_configs:
            try:
                p = self.parse_config_for_clash(cfg)
                uid = str(p.get('uuid') or p.get('password') or cfg.split('#')[0])
                if uid not in new_history: new_history[uid] = {"link": cfg, "date": now.isoformat()}
            except: pass
        with open(NO_CF_HISTORY_FILE, 'w') as f: json.dump(new_history, f, indent=2)
        with open(OUTPUT_NO_CF, 'w', encoding='utf-8') as f: f.write("\n".join(sorted([v['link'] for v in new_history.values()])))

    def save_files(self):
        if not self.raw_configs: return
        valid_configs = set()
        for url in self.raw_configs:
            try:
                parsed = urlparse(url)
                # فیلتر کردن ۱۲۷.۰.۰.۱ و لوکال‌هاست در سطح URL
                if parsed.hostname in ['127.0.0.1', 'localhost', '0.0.0.0']: continue
                valid_configs.add(url)
            except: continue

        proxies_list, renamed_txt, clean_ip_configs = [], [], []
        for i, url in enumerate(sorted(list(valid_configs)), 1):
            if not (proxy := self.parse_config_for_clash(url)): continue
            
            # فیلتر نهایی بر اساس آی‌پی سرور (جلوگیری از ۱۲۷.۰.۰.۱)
            server_host = proxy.get('server')
            if not server_host or server_host in ['127.0.0.1', 'localhost', '0.0.0.0']: continue
            
            # بررسی با ipaddress برای موارد مشابه مثل 127.0.1.1
            try:
                if ipaddress.ip_address(server_host).is_loopback: continue
            except: pass

            country_code = self.get_country_iso_code(server_host)
            country_flag = COUNTRY_FLAGS.get(country_code, '🏳️')
            proxy['name'] = f"{country_code} Config_jo-{i:02d}"
            proxies_list.append(proxy)
            name_with_flag = f"{country_flag} Config_jo-{i:02d}"
            
            if proxy['type'] == 'ss':
                p_copy = proxy.copy(); p_copy['name'] = name_with_flag
                final_link = self.generate_sip002_link(p_copy) or f"{url.split('#')[0]}#{name_with_flag}"
            else:
                try:
                    p_url = list(urlparse(url)); p_url[5] = name_with_flag
                    final_link = urlunparse(p_url)
                except: final_link = f"{url.split('#')[0]}#{name_with_flag}"
            
            renamed_txt.append(final_link)
            if is_clean_ip(server_host): clean_ip_configs.append(final_link)

        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(self.raw_configs))))
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(renamed_txt)))
        self.handle_no_cf_retention(clean_ip_configs)
        self.handle_weekly_file(renamed_txt)
        print(f"⚙️ Done. Total Valid: {len(renamed_txt)}")

async def main():
    load_ip_data()
    load_blocked_ips()
    extractor = V2RayExtractor()
    async with extractor.client:
        async for d in extractor.client.get_dialogs(): pass
        tasks = [extractor.find_raw_configs_from_chat(ch, CHANNEL_SEARCH_LIMIT) for ch in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(g, GROUP_SEARCH_LIMIT) for g in GROUPS)
        if tasks: await asyncio.gather(*tasks)
    extractor.save_files()

if __name__ == "__main__":
    if all([API_ID, API_HASH, SESSION_STRING]): asyncio.run(main())
