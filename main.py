import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote
from pyrogram import Client
from pyrogram.errors import FloodWait
from typing import Optional, Dict, Any, Set, List

# =================================================================================
# بخش تنظیمات و ثابت‌ها
# =================================================================================

# خواندن متغیرهای محیطی
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
SESSION_STRING = os.environ.get("SESSION_STRING")
CHANNELS_STR = os.environ.get('CHANNELS_LIST')
GROUPS_STR = os.environ.get('GROUPS_LIST')
CHANNEL_SEARCH_LIMIT = int(os.environ.get('CHANNEL_SEARCH_LIMIT', 5))
GROUP_SEARCH_LIMIT = int(os.environ.get('GROUP_SEARCH_LIMIT', 600))

# تعریف نام فایل‌های خروجی
OUTPUT_YAML_PRO = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"
OUTPUT_JSON_CONFIG_JO = "Config_jo.json"

# الگوهای Regex برای یافتن انواع کانفیگ
V2RAY_PATTERNS = [
    re.compile(r'(vless:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(vmess:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(trojan:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(ss:\/\/[^\s\'\"<>`]+)'),
    re.compile(r'(ssr:\/\/[^\s\'\"<>`]+)'),
    re.compile(r"(hy2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria2://[^\s'\"<>`]+)"),
    re.compile(r"(hysteria://[^\s'\"<>`]+)"),
    re.compile(r"(tuic://[^\s'\"<>`]+)")
]

BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

def process_lists():
    """خواندن و پردازش لیست کانال‌ها و گروه‌ها از متغیرهای محیطی"""
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

class V2RayExtractor:
    def __init__(self):
        self.raw_configs: Set[str] = set()
        self.client = Client("my_account", api_id=API_ID, api_hash=API_HASH, session_string=SESSION_STRING)

    @staticmethod
    def _generate_unique_name(original_name: str, prefix: str = "config") -> str:
        if not original_name: return f"{prefix}-{str(uuid.uuid4())[:8]}"
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name).replace(' ', '_').strip('_-')
        if not cleaned_name: return f"{prefix}-{str(uuid.uuid4())[:8]}"
        return f"{cleaned_name}-{str(uuid.uuid4())[:4]}"

    def _is_valid_shadowsocks(self, ss_url: str) -> bool:
        try:
            parsed = urlparse(ss_url)
            if not parsed.hostname or not parsed.username: return False
            uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
            if re.search(uuid_pattern, parsed.username): return False
            try:
                decoded_user = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                if ':' not in decoded_user: return False
            except:
                if ':' not in parsed.username: return False
            return True
        except: return False

    def _correct_config_type(self, config_url: str) -> str:
        try:
            if config_url.startswith('ss://'):
                parsed = urlparse(config_url)
                uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
                if parsed.username and re.match(uuid_pattern, parsed.username):
                    return config_url.replace('ss://', 'vless://', 1)
                if parsed.username:
                    try:
                        decoded = base64.b64decode(parsed.username + '=' * (-len(parsed.username) % 4)).decode('utf-8')
                        json_data = json.loads(decoded)
                        if 'v' in json_data and json_data.get('v') == '2':
                            return config_url.replace('ss://', 'vmess://', 1)
                    except: pass
            return config_url
        except: return config_url

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
            elif config_url.startswith(('ssr://', 'hysteria://', 'hysteria2://', 'hy2://', 'tuic://')):
                return True # اعتبارسنجی ساده‌تر برای این پروتکل‌ها
            return False
        except: return False

    def parse_config(self, config_url: str) -> Optional[Dict[str, Any]]:
        try:
            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            elif config_url.startswith('ssr://'): return self.parse_ssr(config_url)
            elif config_url.startswith(('hysteria2://', 'hy2://')): return self.parse_hysteria2(config_url)
            elif config_url.startswith('hysteria://'): return self.parse_hysteria(config_url)
            elif config_url.startswith('tuic://'): return self.parse_tuic(config_url)
            return None
        except Exception as e:
            print(f"❌ خطا در پارس کردن کانفیگ {config_url[:50]}...: {e}")
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
            return {'name': self._generate_unique_name(original_name, "vmess"), 'type': 'vmess', 'server': config.get('add'), 'port': int(config.get('port', 443)), 'uuid': config.get('id'), 'alterId': int(config.get('aid', 0)), 'cipher': config.get('scy', 'auto'), 'tls': config.get('tls') == 'tls', 'network': config.get('net', 'tcp'), 'udp': True, 'ws-opts': ws_opts, 'servername': config.get('sni')}
        except: return None

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
            
            grpc_opts = None
            if query.get('type', [''])[0] == 'grpc':
                grpc_opts = {'grpc-service-name': query.get('serviceName', [''])[0]}

            return {'name': self._generate_unique_name(original_name, "vless"), 'type': 'vless', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'udp': True, 'tls': query.get('security', [''])[0] in ['tls', 'reality'], 'network': query.get('type', ['tcp'])[0], 'servername': query.get('sni', [None])[0], 'flow': query.get('flow', [None])[0], 'ws-opts': ws_opts, 'grpc-opts': grpc_opts, 'reality-opts': reality_opts}
        except: return None

    def parse_trojan(self, trojan_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            sni = query.get('peer', [None])[0] or query.get('sni', [None])[0] or parsed.hostname
            return {'name': self._generate_unique_name(original_name, "trojan"), 'type': 'trojan', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'udp': True, 'sni': sni}
        except: return None

    def parse_shadowsocks(self, ss_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(ss_url)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            user_info_part = parsed.netloc.split('@')[0]
            user_info = base64.b64decode(user_info_part + '=' * (-len(user_info_part) % 4)).decode('utf-8')
            cipher, password = user_info.split(':', 1)
            return {'name': self._generate_unique_name(original_name, 'ss'), 'type': 'ss', 'server': parsed.hostname, 'port': parsed.port, 'cipher': cipher, 'password': password, 'udp': True}
        except: return None

    def parse_ssr(self, ssr_url: str) -> Optional[Dict[str, Any]]:
        try:
            decoded_url = base64.urlsafe_b64decode(ssr_url.split('://')[1] + '==').decode('utf-8')
            parts = decoded_url.split(':')
            server = parts[0]
            port = int(parts[1])
            protocol = parts[2]
            cipher = parts[3]
            obfs = parts[4]
            password_encoded = parts[5].split('/?')[0]
            password = base64.urlsafe_b64decode(password_encoded + '==').decode('utf-8')
            
            params_str = decoded_url.split('/?')[1]
            params = parse_qs(params_str)
            
            obfs_param_encoded = params.get('obfsparam', [''])[0]
            obfs_param = base64.urlsafe_b64decode(obfs_param_encoded + '==').decode('utf-8')
            
            protocol_param_encoded = params.get('protoparam', [''])[0]
            protocol_param = base64.urlsafe_b64decode(protocol_param_encoded + '==').decode('utf-8')

            original_name = unquote(params.get('remarks', [''])[0])

            return {'name': self._generate_unique_name(original_name, "ssr"), 'type': 'ssr', 'server': server, 'port': port, 'password': password, 'cipher': cipher, 'obfs': obfs, 'protocol': protocol, 'obfs-param': obfs_param, 'protocol-param': protocol_param, 'udp': True}
        except: return None

    def parse_hysteria2(self, hy2_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(hy2_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': self._generate_unique_name(original_name, "hysteria2"), 'type': 'hysteria2', 'server': parsed.hostname, 'port': parsed.port or 443, 'password': parsed.username, 'sni': query.get('sni', [parsed.hostname])[0], 'insecure': query.get('insecure', ['0'])[0] == '1', 'obfs': query.get('obfs', [None])[0], 'obfs-password': query.get('obfs-password', [None])[0]}
        except: return None
        
    def parse_hysteria(self, hy_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(hy_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': self._generate_unique_name(original_name, "hysteria"), 'type': 'hysteria', 'server': parsed.hostname, 'port': parsed.port or 443, 'auth': query.get('auth', [None])[0], 'protocol': query.get('protocol', ['udp'])[0], 'up': query.get('upmbps', [None])[0], 'down': query.get('downmbps', [None])[0], 'insecure': query.get('insecure', ['0'])[0] == '1', 'sni': query.get('peer', [None])[0] or query.get('sni', [None])[0], 'obfs': query.get('obfs', [None])[0]}
        except: return None

    def parse_tuic(self, tuic_url: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            original_name = unquote(parsed.fragment) if parsed.fragment else ''
            return {'name': self._generate_unique_name(original_name, "tuic"), 'type': 'tuic', 'server': parsed.hostname, 'port': parsed.port or 443, 'uuid': parsed.username, 'password': query.get('password', [''])[0], 'udp': True, 'sni': query.get('sni', [parsed.hostname])[0], 'insecure': query.get('allow_insecure', ['0'])[0] == '1', 'congestion-controller': query.get('congestion_control', ['bbr'])[0], 'udp-relay-mode': query.get('udp_relay_mode', ['native'])[0], 'alpn': query.get('alpn', [None])[0]}
        except: return None

    def convert_to_singbox_outbound(self, proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            ptype = proxy.get('type')
            if not ptype: return None
            
            sb_type = {'ss': 'shadowsocks', 'ssr': 'shadowsocksr', 'hy2': 'hysteria2'}.get(ptype, ptype)
            server, port, tag = proxy.get('server'), proxy.get('port'), proxy.get('name')
            if not server or not port: return None

            out: Dict[str, Any] = {"type": sb_type, "tag": tag, "server": server, "server_port": port}

            if ptype == 'vless':
                out.update({"uuid": proxy.get('uuid'), "flow": proxy.get('flow', '')})
                if proxy.get('tls'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                    ro = proxy.get('reality-opts')
                    if ro and ro.get('public-key'):
                        out['tls'].setdefault('utls', {"enabled": True, "fingerprint": "chrome"})
                        out['tls']['reality'] = {"enabled": True, "public_key": ro.get('public-key'), "short_id": ro.get('short-id')}
                
                network = proxy.get('network')
                if network == 'ws' and proxy.get('ws-opts'):
                    ws = proxy.get('ws-opts') or {}
                    headers = (ws.get('headers') or {}).get('Host')
                    out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": {"Host": headers} if headers else {}}
                elif network == 'grpc' and proxy.get('grpc-opts'):
                    grpc = proxy.get('grpc-opts') or {}
                    out['transport'] = {"type": "grpc", "service_name": grpc.get('grpc-service-name')}

            elif ptype == 'vmess':
                out.update({"uuid": proxy.get('uuid'), "alter_id": proxy.get('alterId', 0), "security": proxy.get('cipher', 'auto')})
                if proxy.get('tls'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('servername')}
                if proxy.get('network') == 'ws' and proxy.get('ws-opts'):
                    ws = proxy.get('ws-opts') or {}
                    headers = (ws.get('headers') or {}).get('Host')
                    out['transport'] = {"type": "ws", "path": ws.get('path', '/'), "headers": {"Host": headers} if headers else {}}

            elif ptype == 'trojan':
                out.update({"password": proxy.get('password')})
                if proxy.get('sni'):
                    out['tls'] = {"enabled": True, "server_name": proxy.get('sni')}
            
            elif ptype in ['ss', 'ssr']:
                out.update({"method": proxy.get('cipher'), "password": proxy.get('password')})
                if ptype == 'ssr':
                    out.update({"obfs": proxy.get('obfs'), "obfs_param": proxy.get('obfs-param'), "protocol": proxy.get('protocol'), "protocol_param": proxy.get('protocol-param')})

            elif ptype == 'hysteria2':
                 out.update({"password": proxy.get('password')})
                 out['tls'] = {"enabled": True, "server_name": proxy.get('sni'), "insecure": proxy.get('insecure', False)}
                 if proxy.get('obfs'):
                     out['obfs'] = {"type": proxy.get('obfs'), "password": proxy.get('obfs-password')}

            elif ptype == 'hysteria':
                out.update({"auth": proxy.get('auth'), "up_mbps": int(proxy.get('up') or 10), "down_mbps": int(proxy.get('down') or 50)})
                out['tls'] = {"enabled": True, "server_name": proxy.get('sni'), "insecure": proxy.get('insecure', False), "alpn": [proxy.get('alpn')] if proxy.get('alpn') else []}
                if proxy.get('obfs'):
                    out['obfs'] = {"type": "salamander", "password": proxy.get('obfs')}

            elif ptype == 'tuic':
                out.update({"uuid": proxy.get('uuid'), "password": proxy.get('password'), "congestion_control": proxy.get('congestion-controller'), "udp_relay_mode": proxy.get('udp-relay-mode')})
                out['tls'] = {"enabled": True, "server_name": proxy.get('sni'), "insecure": proxy.get('insecure'), "alpn": [proxy.get('alpn')] if proxy.get('alpn') else []}
            
            else: return None
            return out
        except Exception as e:
            print(f"❌ خطا در تبدیل به فرمت Sing-box برای {proxy.get('name')}: {e}")
            return None

    def extract_configs_from_text(self, text: str) -> Set[str]:
        found_configs = set()
        potential_configs = set()
        for pattern in V2RAY_PATTERNS:
            potential_configs.update(pattern.findall(text))
        for config_url in potential_configs:
            corrected_config = self._correct_config_type(config_url.strip())
            if corrected_config and self._validate_config_type(corrected_config):
                found_configs.add(corrected_config)
        return found_configs

    async def find_raw_configs_from_chat(self, chat_id: int, limit: int, retries: int = 3):
        try:
            print(f"🔍 جستجو در چت {chat_id} (محدودیت: {limit} پیام)...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                text_to_check = message.text or message.caption
                if not text_to_check: continue
                texts_to_scan = [text_to_check]
                potential_b64 = BASE64_PATTERN.findall(text_to_check)
                for b64_str in potential_b64:
                    try:
                        decoded_text = base64.b64decode(b64_str + '=' * (-len(b64_str) % 4)).decode('utf-8', errors='ignore')
                        texts_to_scan.append(decoded_text)
                    except Exception: continue
                for text in texts_to_scan:
                    found_configs = self.extract_configs_from_text(text)
                    self.raw_configs.update(found_configs)
        except FloodWait as e:
            if retries <= 0:
                print(f"❌ حداکثر تعداد تلاش‌ها برای چت {chat_id} به پایان رسید.")
                return
            wait_time = min(e.value * (4 - retries), 300)
            print(f"⏳ صبر برای {wait_time} ثانیه (تلاش {4 - retries} از ۳)...")
            await asyncio.sleep(wait_time)
            await self.find_raw_configs_from_chat(chat_id, limit, retries - 1)
        except Exception as e:
            print(f"❌ خطا در زمان اسکن چت {chat_id}: {e}")

    def save_files(self):
        print("\n" + "="*40)
        print("⚙️ شروع پردازش و ساخت فایل‌های کانفیگ...")

        if not self.raw_configs:
            print("⚠️ هیچ کانفیگی در چت‌ها یافت نشد. فایل‌های خروجی خالی خواهند بود.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO]: open(f, "w").close()
            return

        print(f"⚙️ پردازش {len(self.raw_configs)} کانفیگ یافت شده...")
        proxies_list, parse_errors = [], 0
        
        valid_configs = set()
        for url in self.raw_configs:
            try:
                hostname = urlparse(url).hostname
                if hostname and 'speedtest' in hostname.lower(): continue
                if url.startswith('vless://'):
                    query = parse_qs(urlparse(url).query)
                    if query.get('security', ['none'])[0] == 'none': continue
                valid_configs.add(url)
            except Exception: pass

        for url in valid_configs:
            proxy = self.parse_config(url)
            if proxy:
                proxies_list.append(proxy)
            else:
                parse_errors += 1

        if parse_errors > 0:
            print(f"⚠️ {parse_errors} کانفیگ به دلیل خطا در پارسینگ نادیده گرفته شد.")

        if not proxies_list:
            print("⚠️ هیچ کانفیگ معتبری برای ساخت فایل‌ها پیدا نشد.")
            for f in [OUTPUT_YAML_PRO, OUTPUT_TXT, OUTPUT_JSON_CONFIG_JO]: open(f, "w").close()
            return
            
        print(f"👍 {len(proxies_list)} کانفیگ معتبر برای فایل نهایی یافت شد.")
        all_proxy_names = [p['name'] for p in proxies_list]

        try:
            os.makedirs('rules', exist_ok=True)
            pro_config = self.build_pro_config(proxies_list, all_proxy_names)
            with open(OUTPUT_YAML_PRO, 'w', encoding='utf-8') as f:
                yaml.dump(pro_config, f, allow_unicode=True, sort_keys=False, indent=2, width=1000)
            print(f"✅ فایل Clash {OUTPUT_YAML_PRO} با موفقیت ساخته شد.")
        except Exception as e:
            print(f"❌ خطا در ساخت فایل Clash: {e}")

        try:
            singbox_config = self.build_sing_box_config(proxies_list)
            with open(OUTPUT_JSON_CONFIG_JO, 'w', encoding='utf-8') as f:
                json.dump(singbox_config, f, ensure_ascii=False, indent=4)
            print(f"✅ فایل Sing-box {OUTPUT_JSON_CONFIG_JO} با موفقیت ساخته شد.")
        except Exception as e:
            print(f"❌ خطا در ساخت فایل Sing-box: {e}")
        
        with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(list(valid_configs))))
        print(f"✅ فایل متنی {OUTPUT_TXT} با موفقیت ذخیره شد.")

    def build_pro_config(self, proxies, proxy_names):
        return {
            'port': int(os.environ.get('CLASH_PORT', 7890)),
            'socks-port': int(os.environ.get('CLASH_SOCKS_PORT', 7891)),
            'allow-lan': os.environ.get('CLASH_ALLOW_LAN', 'true').lower() == 'true',
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'dns': { 'enable': True, 'listen': '0.0.0.0:53', 'default-nameserver': ['8.8.8.8', '1.1.1.1'], 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'fallback': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'], 'fallback-filter': {'geoip': True, 'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']} },
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
            'rules': ['RULE-SET,ad_domains,🛑 Block-Ads', 'RULE-SET,blocked_domains,PROXY', 'RULE-SET,iran_domains,🇮🇷 Iran', 'GEOIP,IR,🇮🇷 Iran', 'MATCH,PROXY']
        }

    def build_sing_box_config(self, proxies_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        outbounds = [self.convert_to_singbox_outbound(p) for p in proxies_list]
        outbounds = [o for o in outbounds if o is not None] # حذف کانفیگ‌های ناموفق
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
                "final": "dns_direct",
                "strategy": "ipv4_only"
            },
            "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "listen_port": 2080, "sniff": True}],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"},
                *outbounds,
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
    print("🚀 شروع برنامه استخراج کانفیگ...")
    extractor = V2RayExtractor()
    async with extractor.client:
        tasks = [extractor.find_raw_configs_from_chat(channel, CHANNEL_SEARCH_LIMIT) for channel in CHANNELS]
        tasks.extend(extractor.find_raw_configs_from_chat(group, GROUP_SEARCH_LIMIT) for group in GROUPS)
        if tasks:
            await asyncio.gather(*tasks)
        else:
            print("❌ هیچ کانال یا گروهی برای جستجو تعریف نشده است.")
    extractor.save_files()
    print("\n✨ تمام عملیات با موفقیت به پایان رسید!")

if __name__ == "__main__":
    if not all([API_ID, API_HASH, SESSION_STRING]):
        print("❌ خطا: یک یا چند مورد از سکرت‌های ضروری (API_ID, API_HASH, SESSION_STRING) تنظیم نشده است.")
    else:
        asyncio.run(main())
