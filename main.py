import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client, enums
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List
import socket
import geoip2.database

# =================================================================================
# IP Geolocation Section (using GeoIP2)
# =================================================================================

GEOIP_DATABASE_PATH = 'dbip-country-lite.mmdb'
GEOIP_READER = None

def load_ip_data():
    """Loads the GeoIP database into a global reader."""
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

def get_country_iso_code(hostname: str) -> str:
    """Gets the country ISO code for a given hostname."""
    if not GEOIP_READER:
        return "N/A"
    try:
        ip_address = hostname
        try:
            socket.inet_aton(hostname)
        except socket.error:
            ip_address = socket.gethostbyname(hostname)
        
        response = GEOIP_READER.country(ip_address)
        return response.country.iso_code or "N/A"
    except (geoip2.errors.AddressNotFoundError, socket.gaierror):
        return "N/A"
    except Exception:
        return "N/A"

# =================================================================================
# Settings and Constants Section
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
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

def process_lists():
    """Read and process the list of channels and groups from environment variables"""
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if channels: print(f"✅ {len(channels)} channels read from secrets.")
    else: print("⚠️ Warning: CHANNELS_LIST secret not found or is empty.")
    
    groups = []
    if GROUPS_STR:
        # [اصلاح شده] خواندن مطمئن لیست گروه‌ها
        raw_groups = GROUPS_STR.split(',')
        for g in raw_groups:
            g_clean = g.strip()
            if not g_clean: continue
            try:
                # تلاش برای تبدیل به عدد (آیدی عددی)
                groups.append(int(g_clean))
            except ValueError:
                # اگر عدد نبود (مثلا یوزرنیم)، به صورت متن ذخیره کن
                print(f"⚠️ Note: '{g_clean}' interpreted as username/string ID.")
                groups.append(g_clean)
        
        if groups:
            print(f"✅ {len(groups)} groups read from secrets.")
        else:
            print("⚠️ Warning: GROUPS_LIST provided but no valid IDs parsed.")
    else:
        print("⚠️ Warning: GROUPS_LIST secret is empty.")
    
    return channels, groups

CHANNELS, GROUPS = process_lists()

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try:
            parsed = urlparse(ss_url)
            if not parsed.hostname: return False
            try:
                _ = base64.b64decode(parsed.netloc.split('@')[0] + '=' * (-len(parsed.netloc.split('@')[0]) % 4)).decode('utf-8')
                return True
            except Exception: return ':' in parsed.netloc.split('@')[0]
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        try:
            if config_url.startswith('ss://'):
                parsed = urlparse(config_url)
                if parsed.username and re.match(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', parsed.username):
                    return config_url.replace('ss://', 'vless://', 1)
                if data_part := parsed.netloc:
                    try:
                        decoded = base64.b64decode(data_part + '=' * (-len(data_part) % 4)).decode('utf-8')
                        if json.loads(decoded).get('v') == '2': return config_url.replace('ss://', 'vmess://', 1)
                    except Exception: pass
            return config_url
        except: return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        try:
            parsed = urlparse(config_url)
            if config_url.startswith('vless://'): return bool(parsed.hostname and parsed.username)
            elif config_url.startswith('vmess://'):
                decoded_str = base64.b64decode(config_url[8:] + '=' * (-len(config_url[8:]) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))
            elif config_url.startswith('trojan://'): return bool(parsed.hostname and parsed.username)
            elif config_url.startswith('ss://'): return self._is_valid_shadowsocks(config_url)
            return True
        except: return False

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        parsers = {
            'vmess://': self.parse_vmess, 'vless://': self.parse_vless,
            'trojan://': self.parse_trojan, 'ss://': self.parse_shadowsocks,
            'hysteria2://': self.parse_hysteria2, 'hy2://': self.parse_hysteria2,
            'tuic://': self.parse_tuic
        }
        for prefix, parser in parsers.items():
            if config_url.startswith(prefix):
                try: return parser(config_url)
                except Exception as e:
                    return None
        return None

    def parse_vmess(self, vmess_url: str) -> Optional[Dict[str, Any]]:
        decoded_str = base64.b64decode(vmess_url[8:] + '=' * (-len(vmess_url[8:]) % 4)).decode('utf-8')
        config = json.loads(decoded_str)
        if not all(k in config for k in ['add', 'port', 'id', 'ps']): return None
        ws_opts = None
        if config.get('net') == 'ws':
            host_header = config.get('host', '').strip() or config.get('add', '').strip()
            if host_header: ws_opts = {'path': config.get('path', '/'), 'headers': {'Host': host_header}}
        return {'name': config.get('ps', ''), 'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port', 443)), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)), 'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls', 'network': config.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'servername': config.get('sni', config.get('host'))}

    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        parsed, query = urlparse(vless_url), parse_qs(urlparse(vless_url).query)
        if not parsed.hostname or not parsed.username: return None
        ws_opts, reality_opts = None, None
        if query.get('type', [''])[0] == 'ws':
            host_header = (query.get('host', [''])[0] or query.get('sni', [''])[0] or parsed.hostname).strip()
            if host_header: ws_opts = {'path': query.get('path', ['/'])[0], 'headers': {'Host': host_header}}
        if query.get('security', [''])[0] == 'reality' and (pbk := query.get('pbk', [None])[0]):
            reality_opts = {'public-key': pbk, 'short-id': query.get('sid', [''])[0]}
        return {'name': unquote(parsed.fragment or ''), 'type': 'vless', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality'], 'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        parsed, query = urlparse(trojan_url), parse_qs(urlparse(trojan_url).query)
        if not parsed.hostname or not parsed.username: return None
        sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname
        return {'name': unquote(parsed.fragment or ''), 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': sni}

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            content_part = ss_url.split("://")[1].split("#")[0]
            base64.b64decode(content_part + '=' * (-len(content_part) % 4)).decode('utf-8')
            return None
        except Exception: pass
        parsed = urlparse(ss_url)
        user_info, host, port = '', parsed.hostname, parsed.port
        if '@' in parsed.netloc:
            user_info_part = parsed.netloc.split('@')[0]
            try: user_info = base64.b64decode(user_info_part + '=' * (-len(user_info_part) % 4)).decode('utf-8')
            except Exception: user_info = unquote(user_info_part)
        if not user_info or ':' not in user_info or not host or not port: return None
        cipher, password = user_info.split(':', 1)
        return {'name': unquote(parsed.fragment or ''), 'type': 'ss', 'server': host, 'port': int(port), 'cipher': cipher, 'password': password, 'udp': True}

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        parsed, query = urlparse(hy2_url), parse_qs(urlparse(hy2_url).query)
        if not parsed.hostname or not parsed.username: return None
        config = {'name': unquote(parsed.fragment or ''), 'type': 'hysteria2', 'server': parsed.hostname, 'port': parsed.port or 443, 'auth': parsed.username, 'up': query.get('up', ['100 Mbps'])[0], 'down': query.get('down', ['100 Mbps'])[0], 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('insecure', ['false'])[0].lower() == 'true'}
        if obfs_mode := query.get('obfs', [None])[0]:
            config['obfs'] = obfs_mode
            if obfs_password := query.get('obfs-password', [None])[0]: config['obfs-password'] = obfs_password
        return config

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        parsed, query = urlparse(tuic_url), parse_qs(urlparse(tuic_url).query)
        if not parsed.hostname or not parsed.username or not query.get('password'): return None
        return {'name': unquote(parsed.fragment or ''), 'type': 'tuic', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'password': query.get('password', [''])[0], 'udp': True, 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('allow_insecure', ['false'])[0].lower() == 'true'}

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ptype = proxy.get('type')
        if not ptype: return None
        sb_type = 'shadowsocks' if ptype == 'ss' else ptype
        server = proxy.get('server')
        if not server: return None
        try: port = int(proxy.get('port') or 443)
        except Exception: port = 443
        tag = proxy.get('name') or f"{ptype}-{server}:{port}"
        out: Dict[str, Any] = {"type": sb_type, "tag": tag, "server": server, "server_port": port}
        uuid_re = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

        if ptype == 'vless':
            if not (uid := proxy.get('uuid')) or not uuid_re.match(uid): return None
            out.update({"uuid": uid, "flow": proxy.get('flow', '')})
            if proxy.get('tls'):
                out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                if ro := proxy.get('reality-opts'):
                    out['tls'].setdefault('utls', {"enabled": True, "fingerprint": "chrome"})
                    out['tls']['reality'] = {"enabled": True, "public_key": ro.get('public-key'), "short_id": ro.get('short-id')}
            if proxy.get('network') == 'ws' and (ws := proxy.get('ws-opts')):
                headers = {'Host': h} if (h := (ws.get('headers') or {}).get('Host')) else {}
                out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": headers}
        elif ptype == 'vmess':
            if not (uid := proxy.get('uuid')) or not uuid_re.match(uid): return None
            security = (proxy.get('cipher') or 'auto').lower()
            out.update({"uuid": uid, "alter_id": int(proxy.get('alterId', 0)), "security": security if security in ('auto', 'none', 'aes-128-gcm', 'chacha20-poly1305') else 'auto'})
            if proxy.get('tls'): out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
            if proxy.get('network') == 'ws' and (ws := proxy.get('ws-opts')):
                headers = {'Host': h} if (h := (ws.get('headers') or {}).get('Host')) else {}
                out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": headers}
        elif ptype == 'trojan':
            if not (pw := proxy.get('password')): return None
            out.update({"password": pw})
            if proxy.get('tls') is not False:
                out['tls'] = {"enabled": True, "server_name": proxy.get('sni') or proxy.get('servername')}
        elif ptype == 'ss':
            if not (method := proxy.get('cipher')) or not (pw := proxy.get('password')): return None
            out.update({"method": method, "password": pw})
        elif ptype == 'hysteria2':
            if not (auth := proxy.get('auth')): return None
            out.update({"password": auth})
            out['tls'] = {"enabled": True, "server_name": proxy.get('sni') or proxy.get('server'), "insecure": bool(proxy.get('skip-cert-verify'))}
        elif ptype == 'tuic':
            if not (uid := proxy.get('uuid')) or not uuid_re.match(uid) or not (pw := proxy.get('password')): return None
            out.update({"uuid": uid, "password": pw})
            out['tls'] = {"enabled": True, "server_name": proxy.get('sni') or proxy.get('server'), "insecure": bool(proxy.get('skip-cert-verify'))}
        else: return None
        return out

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found_configs = set()
        for pattern in V2RAY_PATTERNS:
            found_configs.update(pattern.findall(text))
        return {corrected for url in found_configs if (corrected := self._correct_config_type(url.strip())) and self._validate_config_type(corrected)}

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        try:
            print(f"🔍 Searching in chat {chat_id} (limit: {limit} messages)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not (text_to_check := message.text or message.caption): continue
                
                # [اصلاح شده] اضافه کردن نسخه بدون فاصله برای حل مشکل لینک شکسته
                # این کار لینک‌ها را به هم می‌چسباند تا Regex بتواند پیدایشان کند
                texts_to_scan = [
                    text_to_check, 
                    text_to_check.replace('\n', '').replace(' ', '')
                ]

                for b64_str in BASE64_PATTERN.findall(text_to_check):
                    try:
                        decoded = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded)
                    except Exception: continue
                
                for text in texts_to_scan: self.raw_configs.update(self.extract_configs_from_text(text))
        
        except FloodWait as e:
            if retries <= 0: return print(f"❌ Max retries reached for chat {chat_id}.")
            wait_time = min(e.value + 5, 300)
            print(f"⏳ FloodWait: Waiting for {wait_time} seconds...")
            await asyncio.sleep(wait_time)
            await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e: print(f"❌ Error scanning chat {chat_id}: {e}")

    def save_files(self):
        print("\n" + "="*40 + "\n⚙️ Starting to process and build config files...")
        
        # مرحله ۱: ذخیره تمام کانفیگ‌های خام (شامل کانفیگ‌های بدون TLS)
        if not self.raw_configs:
            print("⚠️ No configs found. Output files will be empty.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO, OUTPUT_ORIGINAL_CONFIGS]: 
                open(f, "w").close()
            return
        else:
            try:
                # ذخیره تمام کانفیگ‌های خام پیدا شده در Original-Configs.txt
                with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f:
                    f.write("\n".join(sorted(list(self.raw_configs))))
                print(f"✅ Original configs file {OUTPUT_ORIGINAL_CONFIGS} saved with {len(self.raw_configs)} raw configs.")
            except Exception as e:
                print(f"❌ Error saving original configs file: {e}")

        # مرحله ۲: فیلتر کردن کانفیگ‌ها (حذف VLESS بدون TLS) برای فایل‌های دیگر
        valid_configs = set()
        for url in self.raw_configs:
            try:
                hostname = urlparse(url).hostname
                if hostname and 'speedtest' in hostname.lower(): continue
                if url.startswith('vless://'):
                    query = parse_qs(urlparse(url).query)
                    security = query.get('security', [''])[0]
                    if not security or security == 'none':
                        continue # حذف Vless ناامن
                valid_configs.add(url)
            except Exception:
                continue

        print(f"⚙️ Processing {len(valid_configs)} valid configs (after filtering) from {len(self.raw_configs)} raw configs...")
        
        proxies_list_clash, renamed_txt_configs = [], []
        parse_errors = 0
        
        # مرحله ۳: پردازش کانفیگ‌های معتبر (فیلتر شده) برای فایل‌های Clash, Sing-box و TXT
        for i, url in enumerate(sorted(list(valid_configs)), 1):
            if not (proxy := self.parse_config_for_clash(url)):
                parse_errors += 1
                continue

            host_to_check = proxy.get('servername') or proxy.get('sni') or proxy.get('server', '')
            
            country_code = get_country_iso_code(host_to_check)
            country_flag = COUNTRY_FLAGS.get(country_code, '🏳️')

            # نام‌گذاری برای YAML/JSON
            name_compatible = f"{country_code} Config_jo-{i:02d}"
            proxy['name'] = name_compatible
            proxies_list_clash.append(proxy)
            
            # نام‌گذاری برای TXT (با ایموجی)
            name_with_flag = f"{country_flag} Config_jo-{i:02d}"
            try:
                parsed_url = list(urlparse(url)); parsed_url[5] = name_with_flag
                renamed_txt_configs.append(urlunparse(parsed_url))
            except Exception: 
                renamed_txt_configs.append(f"{url.split('#')[0]}#{name_with_flag}")

        if parse_errors > 0: print(f"⚠️ {parse_errors} configs were ignored due to parsing errors.")
        
        # اگر هیچ کانفیگ معتبری (پس از فیلتر) وجود نداشت، فایل‌های دیگر را خالی ایجاد کن
        if not proxies_list_clash:
            print("⚠️ No valid configs to build Clash/Sing-box/Txt files (Original-Configs.txt was already saved).")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO]: 
                open(f, "w").close()
            return
            
        print(f"👍 {len(proxies_list_clash)} configs prepared for output files.")
        all_proxy_names = [p['name'] for p in proxies_list_clash]

        # مرحله ۴: ساخت و ذخیره فایل‌های YAML, JSON و TXT
        try:
            os.makedirs('rules', exist_ok=True)
            pro_config = self.build_pro_config(proxies_list_clash, all_proxy_names)
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
                yaml.dump(pro_config, f, allow_unicode=True, sort_keys=False, indent=2, width=120)
            print(f"✅ Pro file {OUTPUT_YAML_PRO} created.")
        except Exception as e: print(f"❌ Error creating pro file: {e}")

        try:
            singbox_config = self.build_sing_box_config(proxies_list_clash)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f: json.dump(singbox_config, f, ensure_ascii=False, indent=4)
            print(f"✅ Sing-box file {OUTPUT_JSON_CONFIG_JO} created.")
        except Exception as e: print(f"❌ Error creating Sing-box file: {e}")
        
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(renamed_txt_configs)))
        print(f"✅ Text file {OUTPUT_TXT} saved.")
        # فایل Original-Configs.txt قبلاً در مرحله ۱ ذخیره شده است

    def build_pro_config(self, proxies, proxy_names):
        return {
            'port': 7890,
            'socks-port': 7891,
            'allow-lan': True,
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True,
                'listen': '0.0.0.0:53',
                'default-nameserver': ['8.8.8.8', '1.1.1.1'],
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.1/16',
                'fallback': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'],
                'fallback-filter': {
                    'geoip': True,
                    'ipcidr': [
                        '240.0.0.0/4',
                        '0.0.0.0/32',
                        '178.22.122.100/32', # Shecan DNS
                        '185.51.200.2/32'     # Shecan DNS
                    ]
                }
            },
            'proxies': proxies,
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['⚡ Auto-Select', 'DIRECT', *proxy_names]},
                {'name': '⚡ Auto-Select', 'type': 'url-test', 'proxies': proxy_names, 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
                {'name': '🇮🇷 Iran', 'type': 'select', 'proxies': ['DIRECT', 'PROXY']},
                {'name': '🛑 Block-Ads', 'type': 'select', 'proxies': ['REJECT', 'DIRECT']}
            ],
            'rule-providers': {
                'iran_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/iran-domains.txt", 'path': './rules/iran_domains.txt', 'interval': 86400},
                'blocked_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/blocked-domains.txt", 'path': './rules/blocked_domains.txt', 'interval': 86400},
                'ad_domains': {'type': 'http', 'behavior': 'domain', 'url': "https://raw.githubusercontent.com/bootmortis/iran-clash-rules/main/ad-domains.txt", 'path': './rules/ad_domains.txt', 'interval': 86400}
            },
            'rules': [
                'RULE-SET,ad_domains,🛑 Block-Ads',
                'RULE-SET,blocked_domains,PROXY',
                'RULE-SET,iran_domains,🇮🇷 Iran',
                'GEOIP,IR,🇮🇷 Iran',
                'MATCH,PROXY'
            ]
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
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks:
            await asyncio.gather(*tasks)
        else:
            print("❌ No channels or groups defined for searching.")
    extractor.save_files()
    print("\n✨ All operations completed successfully!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ Error: One or more required secrets (API_ID, API_HASH, SESSION_STRING) are not set.")
    else:
        asyncio.run(main())
