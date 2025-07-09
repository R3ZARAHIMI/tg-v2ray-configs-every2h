import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs, unquote

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait, RPCError

# --- تنظیمات عمومی ---

# اطلاعات API تلگرام (از GitHub Secrets خوانده می‌شود)
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")

# نام فایل سشن برای Pyrogram
SESSION_NAME = "my_account"

# --- لیست کانال‌ها ---
NORMAL_CHANNELS = [
    "@SRCVPN", "@net0n3", "@xzjinx", "@vpns",
    "@Capoit", "@mrsoulh", "@sezar_sec", "@Fr33C0nfig",
]
BASE64_ENCODED_CHANNELS = ["@v2ra_config"]
ALL_CHANNELS = NORMAL_CHANNELS + BASE64_ENCODED_CHANNELS

# --- لیست گروه‌ها ---
TARGET_GROUPS = [-1001287072009]

# خروجی‌ها
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"

# الگوهای شناسایی کانفیگ
V2RAY_PATTERNS = [
    re.compile(r"(vless://[^\s\"'<>`]+)"),
    re.compile(r"(vmess://[^\s\"'<>`]+)"),
    re.compile(r"(trojan://[^\s\"'<>`]+)"),
    re.compile(r"(ss://[^\s\"'<>`]+)"),
    re.compile(r"(hy2://[^\s\"'<>`]+)"),
    re.compile(r"(hysteria://[^\s\"'<>`]+)"),
    re.compile(r"(tuic://[^\s\"'<>`]+)")
]
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

class V2RayExtractor:
    def __init__(self):
        self.found_configs = set()
        self.parsed_clash_configs = []
        self.client = Client(SESSION_NAME, api_id=API_ID, api_hash=API_HASH)

    def _generate_unique_name(self, original_name, prefix="config"):
        if not original_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name)
        cleaned_name = cleaned_name.replace(' ', '_').strip('_-')
        if not cleaned_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        return f"{cleaned_name}-{str(uuid.uuid4())[:8]}"

    def is_valid_config(self, config):
        if not isinstance(config, dict): return False
        required = ['name', 'type', 'server', 'port']
        if not all(k in config and config[k] for k in required): return False
        
        proxy_type = config.get('type')
        if proxy_type in ['vless', 'vmess']:
            return 'uuid' in config and config.get('uuid')
        if proxy_type == 'trojan':
            return 'password' in config and config.get('password')
        if proxy_type == 'ss':
            return 'password' in config and 'cipher' in config and config.get('password') and config.get('cipher')
        if proxy_type in ['hysteria', 'tuic']:
            return True
        return False

    def parse_config(self, config_url):
        """
        تابع اصلی تجزیه کانفیگ با پیش-بررسی برای لینک های معیوب.
        """
        try:
            # بهبود: پیش-بررسی برای رد کردن لینک‌های ss:// که مشخصا معیوب هستند
            if config_url.startswith('ss://') and ('security=' in config_url or 'type=' in config_url or 'flow=' in config_url):
                return None # اینها پارامترهای VLESS هستند و لینک SS را نامعتبر می‌کنند. بصورت خاموش رد می‌شود.

            # بررسی برای vmess که به اشتباه با ss:// شروع شده
            if config_url.startswith('ss://') and len(config_url) > 10:
                possible_b64 = config_url[5:].split('#', 1)[0]
                if len(possible_b64) % 4 != 0:
                    possible_b64 += '=' * (4 - (len(possible_b64) % 4))
                try:
                    decoded_check = base64.b64decode(possible_b64).decode('utf-8', errors='ignore')
                    if decoded_check.strip().startswith('{') and '"add":' in decoded_check and '"id":' in decoded_check:
                        config_url = 'vmess://' + possible_b64 + (('#' + config_url.split('#', 1)[1]) if '#' in config_url else '')
                except: pass

            if config_url.startswith('vmess://'): return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'): return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'): return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'): return self.parse_shadowsocks(config_url)
            elif config_url.startswith('hy2://') or config_url.startswith('hysteria://'): return self.parse_hysteria(config_url)
            elif config_url.startswith('tuic://'): return self.parse_tuic(config_url)
            return None
        except Exception: return None

    def parse_vmess(self, vmess_url):
        try:
            encoded_data = vmess_url.replace('vmess://', '')
            padding = len(encoded_data) % 4
            if padding: encoded_data += '=' * (4 - padding)
            config = json.loads(base64.b64decode(encoded_data).decode('utf-8'))
            unique_name = self._generate_unique_name(config.get('ps', ''), "vmess")
            clash_cipher = config.get('scy', 'auto')
            if clash_cipher.lower() not in ['aes-128-gcm', 'chacha20-poly1305', 'aes-256-gcm', 'none']:
                clash_cipher = 'auto'
            
            clash_config = {
                'name': unique_name, 'type': 'vmess', 'server': config.get('add'),
                'port': int(config.get('port', 443)), 'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)), 'cipher': clash_cipher,
                'tls': config.get('tls') == 'tls', 'skip-cert-verify': False,
                'network': config.get('net', 'tcp'), 'udp': True
            }
            if clash_config['network'] == 'ws':
                clash_config['ws-opts'] = {'path': config.get('path', '/'), 'headers': {'Host': config.get('host', '')} if config.get('host') else {}}
            return clash_config if self.is_valid_config(clash_config) else None
        except Exception: return None

    def parse_vless(self, vless_url):
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username: return None

            original_name = unquote(parsed.fragment) if parsed.fragment else query.get('ps', [''])[0]
            unique_name = self._generate_unique_name(original_name, "vless")

            clash_config = {
                'name': unique_name,
                'type': 'vless',
                'server': parsed.hostname,
                'port': int(parsed.port or 443),
                'uuid': parsed.username,
                'udp': True,
                'network': query.get('type', ['tcp'])[0]
            }

            if 'flow' in query:
                clash_config['flow'] = query['flow'][0]

            security = query.get('security', [''])[0]
            if security == 'tls' or security == 'reality':
                clash_config['tls'] = True
                
                if 'sni' in query:
                    clash_config['servername'] = query['sni'][0]

                if security == 'reality':
                    reality_opts = {}
                    if 'pbk' in query: reality_opts['public-key'] = query['pbk'][0]
                    if 'sid' in query: reality_opts['short-id'] = query['sid'][0]
                    if 'fp' in query: reality_opts['fingerprint'] = query['fp'][0]
                    if reality_opts: clash_config['reality-opts'] = reality_opts
                else:
                    clash_config['skip-cert-verify'] = True

            network = clash_config['network']
            if network == 'ws':
                ws_opts = {'path': query.get('path', ['/'])[0]}
                if 'host' in query: ws_opts['headers'] = {'Host': query['host'][0]}
                clash_config['ws-opts'] = ws_opts
            elif network == 'grpc':
                clash_config['grpc-opts'] = {'grpc-service-name': query.get('serviceName', [''])[0]}
                
            return clash_config if self.is_valid_config(clash_config) else None
        except Exception:
            return None

    def parse_trojan(self, trojan_url):
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            if not parsed.hostname or not parsed.username: return None
            unique_name = self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', "trojan")
            clash_config = {
                'name': unique_name, 'type': 'trojan', 'server': parsed.hostname,
                'port': int(parsed.port or 443), 'password': parsed.username,
                'udp': True, 'skip-cert-verify': True
            }
            if 'sni' in query:
                clash_config['sni'] = query['sni'][0]
            return clash_config if self.is_valid_config(clash_config) else None
        except Exception: return None
    
    def parse_shadowsocks(self, ss_url):
        """
        تابع بازنویسی شده و قوی برای تجزیه فرمت های مختلف Shadowsocks.
        """
        try:
            parsed = urlparse(ss_url)
            
            # فرمت: ss://base64(method:password@host:port)
            if not parsed.username and '@' not in parsed.netloc:
                 try:
                    b64_part = parsed.netloc.split('#')[0]
                    b64_part += '=' * (-len(b64_part) % 4)
                    decoded_part = base64.b64decode(b64_part).decode('utf-8')
                    if '@' not in decoded_part: return None
                    auth_part, host_part = decoded_part.split('@', 1)
                    if ':' not in auth_part or ':' not in host_part: return None
                    cipher, password = auth_part.split(':', 1)
                    server, port_str = host_part.split(':', 1)
                    port = int(port_str)
                 except Exception: return None
            # فرمت: ss://method:password@host:port یا ss://base64(method:password)@host:port
            else:
                if parsed.username and parsed.password:
                    cipher = unquote(parsed.username)
                    password = unquote(parsed.password)
                elif parsed.username:
                    try:
                        b64_part = unquote(parsed.username)
                        b64_part += '=' * (-len(b64_part) % 4)
                        decoded_part = base64.b64decode(b64_part).decode('utf-8')
                        if ':' not in decoded_part: return None
                        cipher, password = decoded_part.split(':', 1)
                    except Exception: return None
                else: return None
                server = parsed.hostname
                port = parsed.port

            if not all([cipher, password, server, port]): return None

            clash_config = {
                'name': self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', 'ss'),
                'type': 'ss', 'server': server, 'port': int(port),
                'cipher': cipher, 'password': password, 'udp': True
            }
            return clash_config if self.is_valid_config(clash_config) else None
        except Exception: return None

    def parse_hysteria(self, hysteria_url):
        try:
            parsed = urlparse(hysteria_url)
            query = parse_qs(parsed.query)
            if not parsed.hostname: return None
            unique_name = self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', "hysteria")
            clash_config = {
                'name': unique_name, 'type': 'hysteria', 'server': parsed.hostname,
                'port': int(parsed.port or 443), 'auth_str': parsed.username, 'udp': True,
                'skip-cert-verify': True
            }
            if 'peer' in query: clash_config['sni'] = query['peer'][0]
            if 'alpn' in query: clash_config['alpn'] = query['alpn'][0].split(',')
            return clash_config if self.is_valid_config(clash_config) else None
        except Exception: return None

    def parse_tuic(self, tuic_url):
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            if not parsed.hostname or not parsed.username: return None
            unique_name = self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', "tuic")
            clash_config = {
                'name': unique_name, 'type': 'tuic', 'server': parsed.hostname,
                'port': int(parsed.port or 443), 'uuid': parsed.username,
                'password': query.get('password', [''])[0], 'skip-cert-verify': True
            }
            if 'sni' in query: clash_config['sni'] = query['sni'][0]
            if 'alpn' in query: clash_config['alpn'] = query['alpn'][0].split(',')
            return clash_config if self.is_valid_config(clash_config) else None
        except Exception: return None

    def clean_invalid_configs(self):
        self.parsed_clash_configs = [c for c in self.parsed_clash_configs if self.is_valid_config(c['clash_info'])]

    async def check_chat(self, chat_id, limit):
        try:
            print(f"🔍 Scanning chat '{chat_id}' with limit {limit}...")
            async for message in self.client.get_chat_history(chat_id, limit=limit):
                if not message.text: continue
                processed_texts = [message.text]
                if chat_id in BASE64_ENCODED_CHANNELS:
                    for b64_str in BASE64_PATTERN.findall(message.text):
                        try:
                            b64_str += '=' * (-len(b64_str) % 4)
                            decoded = base64.b64decode(b64_str).decode('utf-8', 'ignore')
                            processed_texts.extend(decoded.splitlines())
                        except: pass
                
                for text in processed_texts:
                    for pattern in V2RAY_PATTERNS:
                        for config_url in pattern.findall(text):
                            if config_url not in self.found_configs:
                                self.found_configs.add(config_url)
                                print(f"✅ Found: {config_url[:70]}...")
                                parsed = self.parse_config(config_url)
                                if parsed:
                                    self.parsed_clash_configs.append({'original_url': config_url, 'clash_info': parsed})
                                elif not (config_url.startswith('ss://') and ('security=' in config_url or 'type=' in config_url)):
                                    print(f"❌ Rejected/Invalid: {config_url[:70]}...")
        except FloodWait as e:
            print(f"⏳ FloodWait: waiting {e.value}s for {chat_id}")
            await asyncio.sleep(e.value)
            await self.check_chat(chat_id, limit)
        except Exception as e:
            print(f"❌ Error scanning {chat_id}: {e}")

    async def extract_configs(self):
        print("🔗 Connecting to Telegram...")
        try:
            async with self.client:
                print("✅ Connected successfully")
                tasks = [self.check_chat(c, 5) for c in ALL_CHANNELS] + \
                        [self.check_chat(g, 300) for g in TARGET_GROUPS]
                await asyncio.gather(*tasks)
                print("\n🧹 Cleaning invalid configs...")
                self.clean_invalid_configs()
        except Exception as e:
            print(f"🔴 Connection error: {e}")

    async def save_configs(self):
        if not self.parsed_clash_configs:
            print("⚠️ No valid configs found. Output files will be empty.")
            open(OUTPUT_YAML, "w").close()
            open(OUTPUT_TXT, "w").close()
            return

        print(f"\n💾 Saving {len(self.parsed_clash_configs)} valid configs...")
        clash_proxies = [c['clash_info'] for c in self.parsed_clash_configs]
        proxy_names = [p['name'] for p in clash_proxies]

        clash_config = {
            'mixed-port': 7890, 'allow-lan': True, 'mode': 'rule', 'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'dns': {'enable': True, 'ipv6': False, 'default-nameserver': ['8.8.8.8', '1.1.1.1'],
                    'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'use-hosts': True,
                    'nameserver': ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query']},
            'proxies': clash_proxies,
            'proxy-groups': [
                {'name': '🚀 PROXY', 'type': 'select', 'proxies': ['♻️ AUTO', 'DIRECT'] + proxy_names},
                {'name': '♻️ AUTO', 'type': 'url-test', 'proxies': proxy_names, 
                 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            ],
            'rules': ['GEOIP,IR,DIRECT', 'MATCH,🚀 PROXY']
        }
        
        try:
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, indent=2)
            print(f"✅ Saved Clash config to {OUTPUT_YAML}")
            
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join(c['original_url'] for c in self.parsed_clash_configs))
            print(f"✅ Saved raw configs to {OUTPUT_TXT}")
        except Exception as e:
            print(f"❌ Save error: {e}")

async def main():
    print("🚀 Starting V2Ray config extractor...")
    extractor = V2RayExtractor()
    await extractor.extract_configs()
    await extractor.save_configs()
    print(f"\n✨ Done! Found {len(extractor.found_configs)} unique configs, saved {len(extractor.parsed_clash_configs)} valid ones.")

if __name__ == "__main__":
    # فایل session دیگر به صورت خودکار حذف نمی‌شود
    asyncio.run(main())
