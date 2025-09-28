import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote, urlunparse
from pyrogram import Client
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List
import geoip2.database
import socket

# =================================================================================
# GeoIP and Flag Section
# =================================================================================

# Path to the GeoIP database
GEOIP_DATABASE = 'dbip-country-lite.mmdb'

# Dictionary to map country codes to flag emojis
COUNTRY_FLAGS = {
    'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷',
    'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪',
    'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯', 'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BR': '🇧🇷',
    'BS': '🇧🇸', 'BT': '🇧🇹', 'BW': '🇧🇼', 'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩', 'CF': '🇨🇫', 'CG': '🇨🇬',
    'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰', 'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷', 'CU': '🇨🇺', 'CV': '🇨🇻',
    'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲', 'DO': '🇩🇴', 'DZ': '🇩🇿',
    'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰',
    'FM': '🇫🇲', 'FO': '🇫🇴', 'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇧', 'GD': '🇬🇩', 'GE': '🇬🇪', 'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭',
    'GI': '🇬🇮', 'GL': '🇬🇱', 'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼',
    'GY': '🇬🇾', 'HK': '🇭🇰', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲',
    'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵',
    'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲', 'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾',
    'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺',
    'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰',
    'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵', 'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺',
    'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬',
    'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷', 'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪',
    'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹',
    'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧',
    'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲', 'SN': '🇸🇳',
    'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹', 'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨', 'TD': '🇹🇩',
    'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯', 'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴', 'TR': '🇹🇷', 'TT': '🇹🇹',
    'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸', 'UY': '🇺🇾', 'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨',
    'VE': '🇻🇪', 'VG': '🇻🇬', 'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦',
    'ZM': '🇿🇲', 'ZW': '🇿🇼',
}

def get_country_flag(hostname):
    """Gets the country flag emoji for a given hostname or IP address."""
    try:
        with geoip2.database.Reader(GEOIP_DATABASE) as reader:
            ip_address = hostname
            try:
                # Check if it's an IP address, if not, resolve it
                socket.inet_aton(hostname)
            except socket.error:
                ip_address = socket.gethostbyname(hostname)

            response = reader.country(ip_address)
            country_code = response.country.iso_code
            return COUNTRY_FLAGS.get(country_code, "🏳️") # Default flag
    except Exception:
        return "🏳️" # Return a default flag on error

# =================================================================================
# Settings and Constants Section
# =================================================================================

# Reading environment variables
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 5))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 100))

# Defining output file names
OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"
OUTPUT_ORIGINAL_CONFIGS = "Original-Configs.txt"

# Regex patterns for finding various config types
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

def process_lists():
    """Read and process the list of channels and groups from environment variables"""
    channels = [ch.strip() for ch in CHANNELS_STR.split(',')] if CHANNELS_STR else []
    if channels: print(f"✅ {len(channels)} channels read from secrets.")
    else: print("⚠️ Warning: CHANNELS_LIST secret not found or is empty.")

    groups = []
    if GROUPS_STR:
        try:
            groups = [int(g.strip()) for g in GROUPS_STR.split(',')]
            print(f"✅ {len(groups)} groups read from secrets.")
        except ValueError: print("❌ Error: GROUPS_LIST secret must only contain numeric IDs.")
    else: print("⚠️ Warning: GROUPS_LIST secret is empty.")
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
                user_part = parsed.netloc.split('@')[0]
                _ = base64.b64decode(user_part + '=' * (-len(user_part) % 4)).decode('utf-8')
                return True
            except Exception:
                if ':' in parsed.netloc.split('@')[0]:
                    return True
            return False
        except:
            return False

    def _correct_config_type(self, config_url: str) -> str:
        try:
            if config_url.startswith('ss://'):
                parsed = urlparse(config_url)
                uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
                if parsed.username and re.match(uuid_pattern, parsed.username):
                    return config_url.replace('ss://', 'vless://', 1)

                data_part = parsed.netloc
                if data_part:
                    try:
                        decoded = base64.b64decode(data_part + '=' * (-len(data_part) % 4)).decode('utf-8')
                        json_data = json.loads(decoded)
                        if 'v' in json_data and json_data.get('v') == '2':
                            return config_url.replace('ss://', 'vmess://', 1)
                    except (ValueError, TypeError, Exception):
                        pass
            return config_url
        except:
            return config_url

    def _validate_config_type(self, config_url: str) -> bool:
        try:
            if config_url.startswith('vless://'):
                return bool(urlparse(config_url).hostname and urlparse(config_url).username)
            elif config_url.startswith('vmess://'):
                encoded_data = config_url.split("://")[1]
                decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
                config = json.loads(decoded_str)
                return bool(config.get('add') and config.get('id'))
            elif config_url.startswith('trojan://'):
                return bool(urlparse(config_url).hostname and urlparse(config_url).username)
            elif config_url.startswith('ss://'):
                return self._is_valid_shadowsocks(config_url)
            return True
        except: return False

    def parse_config_for_clash(self, config_url: str) -> Optional[Dict[str, Any]]:
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            elif config_url.startswith(('hysteria2://', 'hy2://')): return self.parse_hysteria2(config_url)
            elif config_url.startswith('tuic://'): return self.parse_tuic(config_url)
            return None
        except Exception as e:
            print(f"❌ Error parsing config {config_url[:50]}...: {e}")
            return None

    def parse_vmess(self, vmess_url: str) -> Optional[Dict[str, Any]]:
        try:
            encoded_data = vmess_url.split("://")[1]
            decoded_str = base64.b64decode(encoded_data + '=' * (-len(encoded_data) % 4)).decode('utf-8')
            config = json.loads(decoded_str)
            original_name = config.get('ps', '')
            ws_opts = None
            if config.get('net') == 'ws':
                host_header = config.get('host', '').strip() or config.get('add', '').strip()
                if host_header: ws_opts = {'path': config.get('path', '/'), 'headers': {'Host': host_header}}
            return {'name': original_name, 'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port', 443)), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)), 'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls', 'network': config.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'servername': config.get('sni')}
        except Exception as e:
            print(f"❌ Error parsing vmess: {e}")
            return None

    def parse_vless(self, vless_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            ws_opts, reality_opts = None, None
            if query.get('type', [''])[0] == 'ws':
                host_header = query.get('host', [''])[0].strip() or query.get('sni', [''])[0].strip() or parsed.hostname
                if host_header: ws_opts = {'path': query.get('path', ['/'])[0], 'headers': {'Host': host_header}}
            if query.get('security', [''])[0] == 'reality':
                pbk = query.get('pbk', [None])[0]
                if pbk: reality_opts = {'public-key': pbk, 'short-id': query.get('sid', [''])[0]}
            return {'name': original_name, 'type': 'vless', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality'], 'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0], 'ws-opts': ws_opts, 'reality-opts': reality_opts}
        except Exception as e:
            print(f"❌ Error parsing vless: {e}")
            return None

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname
            return {'name': original_name, 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': sni}
        except Exception as e:
            print(f"❌ Error parsing trojan: {e}")
            return None

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            try:
                content_part = ss_url.split("://")[1].split("#")[0]
                decoded_test = base64.b64decode(content_part + '=' * (-len(content_part) % 4)).decode('utf-8')
                json.loads(decoded_test)
                print(f"⚠️ Skipping ss:// link that appears to be a JSON-based config (e.g., vmess): {ss_url[:40]}...")
                return None
            except (json.JSONDecodeError, ValueError, TypeError, Exception):
                pass

            parsed = urlparse(ss_url)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            user_info = ''
            host = parsed.hostname
            port = parsed.port

            if '@' in parsed.netloc:
                user_info_part = parsed.netloc.split('@')[0]
                try:
                    user_info = base64.b64decode(user_info_part + '=' * (-len(user_info_part) % 4)).decode('utf-8')
                except Exception:
                    user_info = unquote(user_info_part)
            else:
                content = ss_url[5:].split('#')[0].split('?')[0]
                try:
                    decoded = base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8')
                    if '@' in decoded and decoded.count(':') >= 2:
                        user_info, host_port = decoded.rsplit('@', 1)
                        host, port_str = host_port.rsplit(':', 1)
                        port = int(port_str)
                except Exception:
                    pass

            if not user_info or ':' not in user_info or not host or not port:
                return None

            cipher, password = user_info.split(':', 1)
            return {'name': original_name, 'type': 'ss', 'server': host, 'port': int(port), 'cipher': cipher, 'password': password, 'udp': True}
        except Exception as e:
            print(f"❌ Error parsing shadowsocks: {e}")
            return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(hy2_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            
            config = {
                'name': original_name, 'type': 'hysteria2', 'server': parsed.hostname,
                'port': parsed.port or 443, 'auth': parsed.username,
                'up': query.get('up', ['100 Mbps'])[0], 'down': query.get('down', ['100 Mbps'])[0],
                'sni': query.get('sni', [parsed.hostname])[0],
                'skip-cert-verify': query.get('insecure', ['false'])[0].lower() == 'true'
            }

            if obfs_mode := query.get('obfs', [None])[0]:
                config['obfs'] = obfs_mode
                if obfs_password := query.get('obfs-password', [None])[0]:
                    config['obfs-password'] = obfs_password
            return config
        except Exception as e:
            print(f"❌ Error parsing hysteria2: {e}")
            return None

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': original_name, 'type': 'tuic', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'password': query.get('password', [''])[0], 'udp': True, 'sni': query.get('sni', [parsed.hostname])[0], 'skip-cert-verify': query.get('allow_insecure', ['false'])[0].lower() == 'true'}
        except Exception as e:
            print(f"❌ Error parsing tuic: {e}")
            return None

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
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
                uid = proxy.get('uuid')
                if not uid or not uuid_re.match(uid): return None
                out.update({"uuid": uid, "flow": proxy.get('flow', '')})

                if proxy.get('tls'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                    if ro := proxy.get('reality-opts'):
                        out['tls'].setdefault('utls', {"enabled": True, "fingerprint": "chrome"})
                        out['tls']['reality'] = {"enabled": True, "public_key": ro.get('public-key'), "short_id": ro.get('short-id')}

                if proxy.get('network') == 'ws' and (ws := proxy.get('ws-opts')):
                    headers = {}
                    if host := (ws.get('headers') or {}).get('Host'): headers['Host'] = host
                    out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": headers}

            elif ptype == 'vmess':
                uid = proxy.get('uuid')
                if not uid or not uuid_re.match(uid): return None
                try: alter_id = int(proxy.get('alterId') or 0)
                except Exception: alter_id = 0
                security = (proxy.get('cipher') or 'auto').lower()
                if security not in ('auto', 'none', 'aes-128-gcm', 'chacha20-poly1305'): security = 'auto'
                out.update({"uuid": uid, "alter_id": alter_id, "security": security})

                if proxy.get('tls'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                if proxy.get('network') == 'ws' and (ws := proxy.get('ws-opts')):
                    headers = {}
                    if host := (ws.get('headers') or {}).get('Host'): headers['Host'] = host
                    out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": headers}

            elif ptype == 'trojan':
                if not (pw := proxy.get('password')): return None
                out.update({"password": pw})
                sni = proxy.get('sni') or proxy.get('servername') or None
                if proxy.get('tls') is not False:
                    out['tls'] = {"enabled": True, "server_name": sni}

            elif ptype == 'ss':
                method = proxy.get('cipher')
                pw = proxy.get('password')
                if not method or not pw: return None
                out.update({"method": method, "password": pw})

            elif ptype == 'hysteria2':
                if not (auth := proxy.get('auth')): return None
                out.update({"password": auth})
                out['tls'] = {"enabled": True, "server_name": proxy.get('sni') or proxy.get('server'), "insecure": bool(proxy.get('skip-cert-verify'))}

            elif ptype == 'tuic':
                uid = proxy.get('uuid')
                pw = proxy.get('password')
                if not uid or not uuid_re.match(uid) or not pw: return None
                out.update({"uuid": uid, "password": pw})
                out['tls'] = {"enabled": True, "server_name": proxy.get('sni') or proxy.get('server'), "insecure": bool(proxy.get('skip-cert-verify'))}

            else: return None
            return out
        except Exception as e:
            print(f"❌ Error converting to Sing-box format for {proxy.get('name')}: {e}")
            return None

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found_configs = set()
        for pattern in V2RAY_PATTERNS:
            found_configs.update(pattern.findall(text))
        
        corrected_configs = set()
        for config_url in found_configs:
            corrected_config = self._correct_config_type(config_url.strip())
            if corrected_config and self._validate_config_type(corrected_config):
                corrected_configs.add(corrected_config)
        return corrected_configs

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        try:
            print(f"🔍 Searching in chat {chat_id} (limit: {limit} messages)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not (text_to_check := message.text or message.caption): continue
                
                texts_to_scan = [text_to_check]
                for b64_str in BASE64_PATTERN.findall(text_to_check):
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception: continue
                
                for text in texts_to_scan:
                    self.raw_configs.update(self.extract_configs_from_text(text))
        except FloodWait as e:
            if retries <= 0:
                print(f"❌ Max retries reached for chat {chat_id}.")
                return
            wait_time = min(e.value * (4 - retries), 300)
            print(f"⏳ Waiting for {wait_time} seconds (attempt {4 - retries} of 3)...")
            await asyncio.sleep(wait_time)
            await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e:
            print(f"❌ Error while scanning chat {chat_id}: {e}")

    def save_files(self):
        print("\n" + "="*40)
        print("⚙️ Starting to process and build config files...")

        if not self.raw_configs:
            print("⚠️ No configs found in chats. Output files will be empty.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO, OUTPUT_ORIGINAL_CONFIGS]: open(f, "w").close()
            return

        print(f"⚙️ Processing {len(self.raw_configs)} found configs...")
        proxies_list_clash, parse_errors = [], 0
        
        valid_configs = set()
        for url in self.raw_configs:
            try:
                hostname = urlparse(url).hostname
                if hostname and 'speedtest' in hostname.lower(): continue
                if url.startswith('vless://') and parse_qs(urlparse(url).query).get('security', ['none'])[0] == 'none': continue
                valid_configs.add(url)
            except Exception: pass

        original_configs_to_save = []
        renamed_txt_configs = []
        config_counter = 1
        for url in sorted(list(valid_configs)):
            if not (proxy := self.parse_config_for_clash(url)):
                parse_errors += 1
                continue

            original_configs_to_save.append(url)
            
            # Intelligent Host Selection for GeoIP
            server_address = proxy.get('server', '')
            sni_address = proxy.get('servername')
            host_to_check = server_address
            if sni_address and sni_address != server_address:
                try:
                    socket.inet_aton(server_address)
                    host_to_check = sni_address
                except socket.error: pass
            
            flag = get_country_flag(host_to_check) if host_to_check else "🏳️"
            new_name = f"{flag} Config_jo-{config_counter:02d}"
            proxy['name'] = new_name
            proxies_list_clash.append(proxy)
            
            try:
                parsed_url = list(urlparse(url))
                parsed_url[5] = new_name
                renamed_txt_configs.append(urlunparse(parsed_url))
            except Exception:
                renamed_txt_configs.append(f"{url.split('#')[0]}#{new_name}")
            config_counter += 1

        if parse_errors > 0: print(f"⚠️ {parse_errors} configs were ignored due to parsing errors.")
        if not proxies_list_clash:
            print("⚠️ No valid configs found to build files.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO, OUTPUT_ORIGINAL_CONFIGS]: open(f, "w").close()
            return
            
        print(f"👍 {len(proxies_list_clash)} valid configs found for the final file.")
        all_proxy_names = [p['name'] for p in proxies_list_clash]

        try:
            os.makedirs('rules', exist_ok=True)
            pro_config = self.build_pro_config(proxies_list_clash, all_proxy_names)
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
                yaml.dump(pro_config, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
            print(f"✅ Pro file {OUTPUT_YAML_PRO} created successfully.")
        except Exception as e: print(f"❌ Error creating pro file: {e}")

        try:
            singbox_config = self.build_sing_box_config(proxies_list_clash)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f:
                json.dump(singbox_config, f, ensure_ascii=False, indent=4)
            print(f"✅ Sing-box file {OUTPUT_JSON_CONFIG_JO} created successfully.")
        except Exception as e: print(f"❌ Error creating Sing-box file: {e}")
        
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(renamed_txt_configs)))
        print(f"✅ Text file {OUTPUT_TXT} saved successfully.")

        with open(OUTPUT_ORIGINAL_CONFIGS, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(original_configs_to_save)))
        print(f"✅ Original configs file {OUTPUT_ORIGINAL_CONFIGS} saved successfully.")

    def build_pro_config(self, proxies, proxy_names):
        return {
            'port': int(os.environ.get('CLASH_PORT', 7890)),
            'socks-port': int(os.environ.get('CLASH_SOCKS_PORT', 7891)),
            'allow-lan': os.environ.get('CLASH_ALLOW_LAN', 'true').lower() == 'true',
            'mode': 'rule', 'log-level': 'info', 'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True, 'listen': '0.0.0.0:53',
                'default-nameserver': ['8.8.8.8', '1.1.1.1'],
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'fallback': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'],
                'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']}
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
                'RULE-SET,ad_domains,🛑 Block-Ads', 'RULE-SET,blocked_domains,PROXY',
                'RULE-SET,iran_domains,🇮🇷 Iran', 'GEOIP,IR,🇮🇷 Iran', 'MATCH,PROXY'
            ]
        }

    def build_sing_box_config(self, proxies_clash: List[Dict[str, Any]]) -> Dict[str, Any]:
        outbounds = [p for p in (self.convert_to_singbox_outbound(proxy) for proxy in proxies_clash) if p]
        proxy_tags = [p['tag'] for p in outbounds]
        return {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "dns_proxy", "address": "https://dns.google/dns-query", "detour": "PROXY"},
                    {"tag": "dns_direct", "address": "1.1.1.1"}
                ],
                "rules": [
                    {"outbound": "PROXY", "server": "dns_proxy"},
                    {"rule_set": ["geosite-ir", "geoip-ir"], "server": "dns_direct"},
                    {"domain_suffix": ".ir", "server": "dns_direct"}
                ],
                "final": "dns_direct", "strategy": "ipv4_only"
            },
            "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080, "sniff": True}],
            "outbounds": [
                {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"}, *outbounds,
                {"type": "selector", "tag": "PROXY", "outbounds": ["auto", *proxy_tags], "default": "auto"},
                {"type": "urltest", "tag": "auto", "outbounds": proxy_tags, "url": "http://www.gstatic.com/generate_204", "interval": "5m"}
            ],
            "route": {
                "rule_set": [
                    {"tag": "geosite-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs", "download_detour": "direct"},
                    {"tag": "geoip-ir", "type": "remote", "format": "binary", "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geoip-ir.srs", "download_detour": "direct"}
                ],
                "rules": [
                    {"protocol": "dns", "outbound": "dns-out"},
                    {"rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct"},
                    {"ip_is_private": True, "outbound": "direct"}
                ],
                "final": "PROXY"
            }
        }

async def main():
    print("🚀 Starting config extractor...")
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
