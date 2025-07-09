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
# این بخش برای اجرا در محیط GitHub Actions طراحی شده است
API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")

# نام فایل سشن برای Pyrogram
SESSION_NAME = "my_account"

# --- لیست کانال‌ها ---
# کانال‌هایی که به صورت مستقیم (غیر Base64) کانفیگ ارسال می‌کنند
NORMAL_CHANNELS = [
    "@SRCVPN",
    "@net0n3",
    "@xzjinx",
    "@vpns",
    "@Capoit",
    "@mrsoulh",
    "@sezar_sec",
    "@Fr33C0nfig",
]

# کانال‌هایی که کانفیگ‌ها را به صورت Base64 شده ارسال می‌کنند
BASE64_ENCODED_CHANNELS = [
    "@v2ra_config"
]

# لیست کلی کانال‌ها که در حلقه استفاده می‌شود
ALL_CHANNELS = NORMAL_CHANNELS + BASE64_ENCODED_CHANNELS

# --- لیست گروه‌ها ---
# شناسه‌های عددی گروه‌هایی که می‌خواهید بررسی شوند
# برای پیدا کردن شناسه، ربات @userinfobot را به گروه اضافه کنید یا از نسخه وب تلگرام استفاده کنید
TARGET_GROUPS = [
    -1001287072009,  # <<<< شناسه گروه شما
]


# خروجی‌ها
OUTPUT_YAML = "Config-jo.yaml"  # خروجی به فرمت YAML برای Clash
OUTPUT_TXT = "Config_jo.txt"    # خروجی به فرمت متنی ساده

# الگوهای شناسایی کانفیگ‌های مستقیم (URLها)
V2RAY_PATTERNS = [
    re.compile(r"(vless://[^\s\"'<>`]+)"),
    re.compile(r"(vmess://[^\s\"'<>`]+)"),
    re.compile(r"(trojan://[^\s\"'<>`]+)"),
    re.compile(r"(ss://[^\s\"'<>`]+)"),
    re.compile(r"(hy2://[^\s\"'<>`]+)"),
    re.compile(r"(hysteria://[^\s\"'<>`]+)"),
    re.compile(r"(tuic://[^\s\"'<>`]+)")
]

# الگوی جدید و اصلاح شده برای رشته‌های Base64 شده (پیدا کردن هر رشته طولانی Base64)
BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/=]{50,})", re.MULTILINE)

# --- کلاس V2RayExtractor ---
class V2RayExtractor:
    def __init__(self):
        self.found_configs = set()
        self.parsed_clash_configs = [] # هر آیتم شامل {'original_url': ..., 'clash_info': ...} است

        self.client = Client(
            SESSION_NAME,
            api_id=API_ID,
            api_hash=API_HASH
        )

    # --- توابع کمکی ---
    def _generate_unique_name(self, original_name, prefix="config"):
        if not original_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name)
        cleaned_name = cleaned_name.replace(' ', '_').strip('_-')
        
        if not cleaned_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
            
        return f"{cleaned_name}-{str(uuid.uuid4())[:8]}"
        
    def is_valid_config(self, config):
        """بررسی معتبر بودن ساختار اولیه کانفیگ برای Clash"""
        if not config or not isinstance(config, dict):
            return False
            
        required_fields = ['name', 'type', 'server', 'port']
        if not all(field in config and config[field] is not None for field in required_fields):
            return False
            
        proxy_type = config.get('type')
        if proxy_type == 'vmess':
            return 'uuid' in config and config.get('uuid')
        elif proxy_type == 'vless':
            return 'uuid' in config and config.get('uuid')
        elif proxy_type == 'trojan':
            return 'password' in config and config.get('password')
        elif proxy_type == 'ss':
            return 'password' in config and 'cipher' in config and config.get('password') and config.get('cipher')
        elif proxy_type in ['hysteria', 'tuic']:
            return True
        return False

    # --- توابع parse برای هر نوع کانفیگ ---
    def parse_config(self, config_url):
        """تجزیه و تحلیل کانفیگ برای استخراج اطلاعات اتصال برای Clash"""
        try:
            if config_url.startswith('ss://') and len(config_url) > 10:
                possible_b64 = config_url[5:].split('#', 1)[0]
                if len(possible_b64) % 4 != 0:
                    possible_b64 += '=' * (4 - (len(possible_b64) % 4))
                try:
                    decoded_check = base64.b64decode(possible_b64).decode('utf-8', errors='ignore')
                    if decoded_check.strip().startswith('{') and '"add":' in decoded_check and '"id":' in decoded_check:
                        config_url = 'vmess://' + possible_b64 + (('#' + config_url.split('#', 1)[1]) if '#' in config_url else '')
                except:
                    pass

            if config_url.startswith('vmess://'):
                return self.parse_vmess(config_url)
            elif config_url.startswith('vless://'):
                return self.parse_vless(config_url)
            elif config_url.startswith('trojan://'):
                return self.parse_trojan(config_url)
            elif config_url.startswith('ss://'):
                return self.parse_shadowsocks(config_url)
            elif config_url.startswith('hy2://') or config_url.startswith('hysteria://'):
                return self.parse_hysteria(config_url)
            elif config_url.startswith('tuic://'):
                return self.parse_tuic(config_url)
            else:
                return None
        except Exception as e:
            return None

    def parse_vmess(self, vmess_url):
        try:
            encoded_data = vmess_url.replace('vmess://', '')
            padding = len(encoded_data) % 4
            if padding:
                encoded_data += '=' * (4 - padding)

            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            config = json.loads(decoded_data)

            original_name = config.get('ps', '')
            unique_name = self._generate_unique_name(original_name, "vmess")

            vmess_cipher = config.get('scy', 'auto')
            clash_cipher = vmess_cipher
            supported_clash_ciphers = ['aes-128-gcm', 'chacha20-poly1305', 'aes-256-gcm']

            if vmess_cipher.lower() in ['none', 'auto']:
                clash_cipher = 'aes-128-gcm'
            elif vmess_cipher not in supported_clash_ciphers:
                clash_cipher = 'aes-128-gcm'

            clash_config = {
                'name': unique_name,
                'type': 'vmess',
                'server': config.get('add'),
                'port': int(config.get('port', 443)),
                'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)),
                'cipher': clash_cipher,
                'tls': config.get('tls') == 'tls',
                'skip-cert-verify': False,
                'network': config.get('net', 'tcp'),
                'udp': True
            }

            if clash_config['network'] == 'ws':
                clash_config['ws-opts'] = {
                    'path': config.get('path', '/'),
                    'headers': {'Host': config.get('host', '')} if config.get('host') else {}
                }
            if clash_config['network'] == 'h2':
                clash_config['h2-opts'] = {
                    'path': config.get('path', '/'),
                    'host': [config.get('host', '')] if config.get('host') else []
                }
            if clash_config['network'] == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': config.get('path', '')
                }
            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception:
            return None

    def parse_vless(self, vless_url):
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            original_name = unquote(parsed.fragment) if parsed.fragment else query.get('ps', [''])[0]
            unique_name = self._generate_unique_name(original_name, "vless")

            clash_config = {
                'name': unique_name,
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'udp': True,
                'network': query.get('type', ['tcp'])[0]
            }

            security = query.get('security', [''])[0]
            if security == 'tls':
                clash_config['tls'] = True
                clash_config['skip-cert-verify'] = True
                if query.get('sni'):
                    clash_config['servername'] = query.get('sni')[0]
                    
            elif security == 'reality':
                clash_config['tls'] = True
                clash_config['skip-cert-verify'] = True
                reality_opts = {}
                if query.get('pbk'):
                    reality_opts['public-key'] = query.get('pbk')[0]
                if query.get('sid'):
                    reality_opts['short-id'] = query.get('sid')[0]
                if reality_opts:
                    clash_config['reality-opts'] = reality_opts

            network = clash_config['network']
            if network == 'ws':
                ws_opts = {'path': query.get('path', ['/'])[0]}
                if query.get('host'):
                    ws_opts['headers'] = {'Host': query.get('host')[0]}
                clash_config['ws-opts'] = ws_opts
                
            elif network == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': query.get('serviceName', [''])[0]
                }
                
            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception:
            return None

    def parse_trojan(self, trojan_url):
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            original_name = unquote(parsed.fragment) if parsed.fragment else query.get('ps', [''])[0]
            unique_name = self._generate_unique_name(original_name, "trojan")

            clash_config = {
                'name': unique_name,
                'type': 'trojan',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'password': parsed.username,
                'udp': True,
                'skip-cert-verify': True
            }

            if query.get('sni'):
                clash_config['sni'] = query.get('sni')[0]

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception:
            return None

    def parse_shadowsocks(self, ss_url):
        try:
            if '://' not in ss_url:
                return None
                
            parsed = urlparse(ss_url)
            
            if '@' in parsed.netloc and ':' in parsed.netloc:
                if parsed.username and parsed.password:
                    cipher = parsed.username
                    password = parsed.password
                    server = parsed.hostname
                    port = parsed.port or 443
                elif parsed.username and not parsed.password:
                    try:
                        auth_part = parsed.username
                        padding = len(auth_part) % 4
                        if padding:
                            auth_part += '=' * (4 - padding)
                        decoded_auth = base64.b64decode(auth_part).decode('utf-8')
                        if ':' in decoded_auth:
                            cipher, password = decoded_auth.split(':', 1)
                            server = parsed.hostname
                            port = parsed.port or 443
                        else:
                            return None
                    except:
                        return None
                else:
                    return None
            else:
                try:
                    encoded_part = parsed.netloc
                    padding = len(encoded_part) % 4
                    if padding:
                        encoded_part += '=' * (4 - padding)
                        
                    decoded = base64.b64decode(encoded_part).decode('utf-8')
                    if ':' in decoded and '@' in decoded:
                        method_pass, server_port_fragment = decoded.split('@', 1)
                        server_port = server_port_fragment.split('#', 1)[0]

                        if ':' in method_pass:
                            cipher, password = method_pass.split(':', 1)
                        else:
                            return None

                        if ':' in server_port:
                            server, port = server_port.rsplit(':', 1)
                            port = int(port)
                        else:
                            return None
                    else:
                        return None
                except:
                    return None

            if not all([cipher, password, server]):
                return None

            clash_config = {
                'name': self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', 'ss'),
                'type': 'ss',
                'server': server,
                'port': int(port),
                'cipher': cipher,
                'password': password,
                'udp': True
            }

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception:
            return None

    def parse_hysteria(self, hysteria_url):
        try:
            parsed = urlparse(hysteria_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            original_name = unquote(parsed.fragment) if parsed.fragment else query.get('ps', [''])[0]
            unique_name = self._generate_unique_name(original_name, "hysteria")

            clash_config = {
                'name': unique_name,
                'type': 'hysteria',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'auth_str': parsed.username,
                'udp': True,
                'skip-cert-verify': True
            }
            
            if query.get('peer'):
                clash_config['sni'] = query.get('peer')[0]
            if query.get('alpn'):
                clash_config['alpn'] = query.get('alpn')[0].split(',')

            obfs = query.get('obfs', [None])[0] or query.get('obfsParam', [None])[0]
            if obfs:
                clash_config['obfs'] = obfs
            
            if query.get('protocol'):
                clash_config['protocol'] = query.get('protocol')[0]

            if query.get('upmbps'):
                clash_config['up_mbps'] = int(query.get('upmbps')[0])
            if query.get('downmbps'):
                clash_config['down_mbps'] = int(query.get('downmbps')[0])

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception:
            return None

    def parse_tuic(self, tuic_url):
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            original_name = unquote(parsed.fragment) if parsed.fragment else query.get('ps', [''])[0]
            unique_name = self._generate_unique_name(original_name, "tuic")

            clash_config = {
                'name': unique_name,
                'type': 'tuic',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'password': query.get('password', [''])[0],
                'udp-relay-mode': query.get('udp-relay-mode', ['native'])[0],
                'skip-cert-verify': True
            }
            
            if query.get('sni'):
                clash_config['sni'] = query.get('sni')[0]
            if query.get('alpn'):
                clash_config['alpn'] = query.get('alpn')[0].split(',')

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception:
            return None

    def clean_invalid_configs(self):
        """پاک کردن کانفیگ‌های نامعتبر"""
        valid_configs = [item for item in self.parsed_clash_configs if self.is_valid_config(item['clash_info'])]
        self.parsed_clash_configs = valid_configs

    async def check_chat(self, chat_id, limit):
        """بررسی یک چت (کانال یا گروه) و استخراج کانفیگ‌ها"""
        try:
            print(f"🔍 Scanning chat '{chat_id}' with limit {limit}...")
            async for message in self.client.get_chat_history(chat_id, limit=limit): 
                if not message.text:
                    continue

                processed_texts = [message.text]

                # این منطق Base64 برای گروه‌ها نیز اعمال می‌شود اگر شناسه آنها در لیست باشد
                # در حال حاضر فقط برای کانال‌ها تعریف شده، اما می‌توان گروه‌ها را نیز اضافه کرد
                if chat_id in BASE64_ENCODED_CHANNELS:
                    base64_matches = BASE64_PATTERN.findall(message.text)
                    for b64_str_match in base64_matches:
                        try:
                            cleaned_b64_str = re.sub(r'\s+', '', b64_str_match)
                            padding = len(cleaned_b64_str) % 4
                            if padding:
                                cleaned_b64_str += '=' * (4 - padding)

                            decoded_text = base64.b64decode(cleaned_b64_str).decode('utf-8', errors='ignore')
                            lines = decoded_text.splitlines()
                            processed_texts.extend([line.strip() for line in lines if line.strip()])
                        except Exception:
                            pass

                for text_to_scan in processed_texts:
                    for pattern in V2RAY_PATTERNS:
                        matches = pattern.findall(text_to_scan)
                        for config_url in matches:
                            if config_url not in self.found_configs:
                                self.found_configs.add(config_url)
                                print(f"✅ Found new config from {chat_id}: {config_url[:60]}...")
                                
                                parsed_config = self.parse_config(config_url)
                                if parsed_config:
                                    self.parsed_clash_configs.append({
                                        'original_url': config_url,
                                        'clash_info': parsed_config
                                    })
                                else:
                                    print(f"❌ Failed to parse or invalid structure: {config_url[:50]}...")

        except FloodWait as e:
            print(f"⏳ Waiting {e.value} seconds (Telegram limit) for {chat_id}")
            await asyncio.sleep(e.value)
            await self.check_chat(chat_id, limit) # Retry after waiting
        except RPCError as e:
            print(f"❌ RPC error in {chat_id}: {e.MESSAGE} (Code: {e.CODE})")
        except Exception as e:
            print(f"❌ General error in {chat_id}: {str(e)}")

    async def extract_configs(self):
        """استخراج کانفیگ‌ها از تمام کانال‌ها و گروه‌ها"""
        print("🔗 Connecting to Telegram...")
        try:
            async with self.client:
                print("✅ Connected successfully")
                
                # ایجاد وظایف برای کانال‌ها با محدودیت ۵ پیام
                channel_tasks = [self.check_chat(channel, limit=5) for channel in ALL_CHANNELS]
                
                # ایجاد وظایف برای گروه‌ها با محدودیت ۱۰۰ پیام
                group_tasks = [self.check_chat(group_id, limit=300) for group_id in TARGET_GROUPS]
                
                all_tasks = channel_tasks + group_tasks
                await asyncio.gather(*all_tasks)
                
                print("\n🧹 Cleaning invalid configs...")
                self.clean_invalid_configs()
                
        except Exception as e:
            print(f"🔴 Connection error: {str(e)}")
            self.found_configs.clear()
            self.parsed_clash_configs.clear()

    async def save_configs(self):
        """ذخیره کانفیگ‌ها در فرمت‌های YAML و TXT"""
        if not self.parsed_clash_configs:
            print("⚠️ No valid configs found. Output files will be empty.")
            open(OUTPUT_YAML, "w").close()
            open(OUTPUT_TXT, "w").close()
            return

        print(f"\n💾 Saving {len(self.parsed_clash_configs)} valid configs...")

        clash_config = {
            'mixed-port': 7890,
            'allow-lan': True,
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'dns': {
                'enable': True,
                'ipv6': False,
                'default-nameserver': ['223.5.5.5', '8.8.8.8'],
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.1/16',
                'use-hosts': True,
                'nameserver': ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query']
            },
            'proxies': [],
            'proxy-groups': [
                {'name': '🚀 Proxy', 'type': 'select', 'proxies': ['♻️ Auto', '🔯 Fallback', 'DIRECT']},
                {'name': '♻️ Auto', 'type': 'url-test', 'proxies': [], 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
                {'name': '🔯 Fallback', 'type': 'fallback', 'proxies': [], 'url': 'http://www.gstatic.com/generate_204', 'interval': 300},
            ],
            'rules': [
                'DOMAIN-SUFFIX,local,DIRECT',
                'IP-CIDR,127.0.0.0/8,DIRECT',
                'GEOIP,IR,DIRECT',
                'MATCH,🚀 Proxy'
            ]
        }

        valid_configs_clash_format = [config['clash_info'] for config in self.parsed_clash_configs]
        config_names = [c['name'] for c in valid_configs_clash_format]

        clash_config['proxies'] = valid_configs_clash_format
        clash_config['proxy-groups'][0]['proxies'].extend(config_names)
        clash_config['proxy-groups'][1]['proxies'] = config_names
        clash_config['proxy-groups'][2]['proxies'] = config_names

        try:
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False, indent=2)
            print(f"✅ Saved Clash config to {OUTPUT_YAML}")
            
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join([c['original_url'] for c in self.parsed_clash_configs]))
            print(f"✅ Saved raw configs to {OUTPUT_TXT}")
            
            config_types = {}
            for config in valid_configs_clash_format:
                config_type = config['type']
                config_types[config_type] = config_types.get(config_type, 0) + 1
            
            print("\n📊 Config Statistics:")
            for config_type, count in config_types.items():
                print(f"  {config_type.upper()}: {count} configs")
            
        except Exception as e:
            print(f"❌ Save error: {str(e)}")

async def main():
    """تابع اصلی"""
    print("🚀 Starting V2Ray config extractor...")
    
    extractor = V2RayExtractor()
    await extractor.extract_configs()
    await extractor.save_configs()
    
    print("\n✨ Extraction completed!")
    print(f"📊 Total unique configs found: {len(extractor.found_configs)}")
    print(f"✅ Total valid configs saved: {len(extractor.parsed_clash_configs)}")

if __name__ == "__main__":
    # با کامنت کردن این بخش، فایل session دیگر به صورت خودکار حذف نمی‌شود
    # و برنامه از لاگین قبلی استفاده می‌کند.
    # if os.path.exists(SESSION_NAME + ".session"):
    #     os.remove(SESSION_NAME + ".session")
    #     print("ℹ️ Old session file removed to ensure fresh login.")
    asyncio.run(main())
