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
API_ID = int(os.environ.get("API_ID", 12345))
API_HASH = os.environ.get("API_HASH", "your_api_hash_here")
SESSION_NAME = "my_account"
CHANNELS = ["@SRCVPN", "@net0n3", "@Anty_Filter","@vpns","@v2ra_config","@mrsoulh","@Capoit"]
OUTPUT_YAML = "Config-jo.yaml"
OUTPUT_TXT = "Config_jo.txt"

# الگوهای شناسایی کانفیگ‌ها
V2RAY_PATTERNS = [
    re.compile(r"(vless://[^\s]+)"),
    re.compile(r"(vmess://[^\s]+)"),
    re.compile(r"(trojan://[^\s]+)"),
    re.compile(r"(ss://[^\s]+)"),
    re.compile(r"(hy2://[^\s]+)"),
    re.compile(r"(hysteria://[^\s]+)"),
    re.compile(r"(tuic://[^\s]+)")
]

class V2RayExtractor:
    def __init__(self):
        self.found_configs = set()
        self.parsed_clash_configs = []
        self.client = Client(
            SESSION_NAME,
            api_id=API_ID,
            api_hash=API_HASH
        )

    def _generate_unique_name(self, original_name, prefix="config"):
        if not original_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
        
        # پاک کردن کاراکترهای غیرمجاز
        cleaned_name = re.sub(r'[^\w\s\-\_\u0600-\u06FF]', '', original_name)
        cleaned_name = cleaned_name.replace(' ', '_').strip('_-')
        
        if not cleaned_name:
            return f"{prefix}-{str(uuid.uuid4())[:8]}"
            
        return f"{cleaned_name}-{str(uuid.uuid4())[:8]}"

    def is_valid_config(self, config):
        """بررسی معتبر بودن کانفیگ"""
        if not config or not isinstance(config, dict):
            return False
            
        # بررسی فیلدهای ضروری
        required_fields = ['name', 'type', 'server', 'port']
        if not all(field in config for field in required_fields):
            return False
            
        # بررسی نوع پروکسی
        proxy_type = config.get('type')
        if proxy_type == 'vmess':
            return 'uuid' in config and config.get('uuid')
        elif proxy_type == 'vless':
            return 'uuid' in config and config.get('uuid')
        elif proxy_type == 'trojan':
            return 'password' in config and config.get('password')
        elif proxy_type == 'ss':
            return 'password' in config and 'cipher' in config and config.get('password') and config.get('cipher')
            
        return False

    def parse_vmess(self, vmess_url):
        """پارس کردن VMess URL"""
        try:
            encoded_data = vmess_url.replace('vmess://', '')
            
            # اضافه کردن padding اگر نیاز باشد
            padding = len(encoded_data) % 4
            if padding:
                encoded_data += '=' * (4 - padding)

            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            config = json.loads(decoded_data)

            # بررسی فیلدهای ضروری
            if not config.get('add') or not config.get('port') or not config.get('id'):
                return None

            clash_config = {
                'name': self._generate_unique_name(config.get('ps', ''), 'vmess'),
                'type': 'vmess',
                'server': config.get('add'),
                'port': int(config.get('port', 443)),
                'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)),
                'cipher': 'auto',
                'udp': True
            }

            # تنظیمات TLS
            if config.get('tls') == 'tls':
                clash_config['tls'] = True
                if config.get('host'):
                    clash_config['servername'] = config.get('host')
                clash_config['skip-cert-verify'] = True

            # تنظیمات شبکه
            network = config.get('net', 'tcp')
            if network == 'ws':
                clash_config['network'] = 'ws'
                ws_opts = {'path': config.get('path', '/')}
                if config.get('host'):
                    ws_opts['headers'] = {'Host': config.get('host')}
                clash_config['ws-opts'] = ws_opts
                
            elif network == 'h2':
                clash_config['network'] = 'http'
                if config.get('host'):
                    clash_config['http-opts'] = {'host': [config.get('host')]}
                    
            elif network == 'grpc':
                clash_config['network'] = 'grpc'
                clash_config['grpc-opts'] = {
                    'grpc-service-name': config.get('path', '')
                }

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception as e:
            print(f"❌ Error parsing VMess: {str(e)}")
            return None

    def parse_vless(self, vless_url):
        """پارس کردن VLESS URL"""
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            clash_config = {
                'name': self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', 'vless'),
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'udp': True,
                'network': query.get('type', ['tcp'])[0]
            }

            # تنظیمات امنیتی
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

            # تنظیمات شبکه
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
                
            elif network == 'h2':
                clash_config['network'] = 'http'
                if query.get('host'):
                    clash_config['http-opts'] = {'host': [query.get('host')[0]]}
                    
            elif network == 'xhttp':
                # xhttp را به ws تبدیل می‌کنیم
                clash_config['network'] = 'ws'
                ws_opts = {'path': query.get('path', ['/'])[0]}
                if query.get('host'):
                    ws_opts['headers'] = {'Host': query.get('host')[0]}
                clash_config['ws-opts'] = ws_opts

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception as e:
            print(f"❌ Error parsing VLESS: {str(e)}")
            return None

    def parse_trojan(self, trojan_url):
        """پارس کردن Trojan URL"""
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            clash_config = {
                'name': self._generate_unique_name(unquote(parsed.fragment) if parsed.fragment else '', 'trojan'),
                'type': 'trojan',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'password': parsed.username,
                'udp': True,
                'skip-cert-verify': True
            }

            # تنظیمات SNI
            if query.get('sni'):
                clash_config['sni'] = query.get('sni')[0]

            return clash_config if self.is_valid_config(clash_config) else None
            
        except Exception as e:
            print(f"❌ Error parsing Trojan: {str(e)}")
            return None

    def parse_shadowsocks(self, ss_url):
        """پارس کردن Shadowsocks URL - اصلاح شده"""
        try:
            if '://' not in ss_url:
                return None
                
            parsed = urlparse(ss_url)
            
            # روش اول: فرمت ss://method:password@server:port
            if '@' in parsed.netloc and ':' in parsed.netloc:
                if parsed.username and parsed.password:
                    # فرمت عادی
                    cipher = parsed.username
                    password = parsed.password
                    server = parsed.hostname
                    port = parsed.port or 443
                elif parsed.username and not parsed.password:
                    # احتمالاً base64 encoded است
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
                # روش دوم: فرمت ss://base64encoded#fragment
                try:
                    encoded_part = parsed.netloc
                    padding = len(encoded_part) % 4
                    if padding:
                        encoded_part += '=' * (4 - padding)
                        
                    decoded = base64.b64decode(encoded_part).decode('utf-8')
                    if ':' in decoded and '@' in decoded:
                        method_pass, server_port = decoded.split('@', 1)
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

            # بررسی معتبر بودن
            if not cipher or not password or not server:
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
            
        except Exception as e:
            print(f"❌ Error parsing Shadowsocks: {str(e)}")
            return None

    def clean_invalid_configs(self):
        """پاک کردن کانفیگ‌های نامعتبر"""
        valid_configs = []
        for config_data in self.parsed_clash_configs:
            config = config_data['clash_info']
            
            # بررسی اضافی برای اطمینان
            if config.get('type') == 'ss':
                # بررسی اینکه cipher و password معتبر هستند
                cipher = config.get('cipher')
                password = config.get('password')
                
                # اگر cipher یا password شامل UUID باشد، نامعتبر است
                if cipher and len(cipher) > 32 and '-' in cipher:
                    continue
                if password and (password == 'null' or not password.strip()):
                    continue
                    
            elif config.get('type') in ['vless', 'vmess']:
                # بررسی UUID
                uuid_val = config.get('uuid')
                if not uuid_val or len(uuid_val) != 36 or uuid_val.count('-') != 4:
                    continue
                    
            elif config.get('type') == 'trojan':
                # بررسی password
                password = config.get('password')
                if not password or len(password) < 8:
                    continue
            
            valid_configs.append(config_data)
        
        self.parsed_clash_configs = valid_configs

    async def check_channel(self, channel):
        """بررسی کانال و استخراج کانفیگ‌ها"""
        try:
            print(f"🔍 Scanning channel {channel}...")
            async for message in self.client.get_chat_history(channel, limit=8):
                if not message.text:
                    continue

                for pattern in V2RAY_PATTERNS:
                    matches = pattern.findall(message.text)
                    for config_url in matches:
                        if config_url not in self.found_configs:
                            self.found_configs.add(config_url)
                            parsed_config = None
                            
                            try:
                                if config_url.startswith('vmess://'):
                                    parsed_config = self.parse_vmess(config_url)
                                elif config_url.startswith('vless://'):
                                    parsed_config = self.parse_vless(config_url)
                                elif config_url.startswith('trojan://'):
                                    parsed_config = self.parse_trojan(config_url)
                                elif config_url.startswith('ss://'):
                                    parsed_config = self.parse_shadowsocks(config_url)
                                
                                if parsed_config:
                                    self.parsed_clash_configs.append({
                                        'original_url': config_url,
                                        'clash_info': parsed_config
                                    })
                                    print(f"✅ Found valid config: {parsed_config['name']} ({parsed_config['type']})")
                                else:
                                    print(f"❌ Invalid config: {config_url[:50]}...")
                                    
                            except Exception as e:
                                print(f"❌ Error parsing config: {str(e)}")

        except FloodWait as e:
            print(f"⏳ Waiting {e.value} seconds (Telegram limit) for {channel}")
            await asyncio.sleep(e.value)
            await self.check_channel(channel)
        except Exception as e:
            print(f"❌ Error in {channel}: {str(e)}")

    async def extract_configs(self):
        """استخراج کانفیگ‌ها از کانال‌ها"""
        print("🔗 Connecting to Telegram...")
        try:
            async with self.client:
                print("✅ Connected successfully")
                await asyncio.gather(*[self.check_channel(channel) for channel in CHANNELS])
                
                # پاک کردن کانفیگ‌های نامعتبر
                print("🧹 Cleaning invalid configs...")
                self.clean_invalid_configs()
                
        except Exception as e:
            print(f"🔴 Connection error: {str(e)}")
            self.found_configs.clear()
            self.parsed_clash_configs.clear()

    async def save_configs(self):
        """ذخیره کانفیگ‌ها"""
        if not self.parsed_clash_configs:
            print("⚠️ No valid configs found")
            return

        # ایجاد کانفیگ کامل Clash
        clash_config = {
            'mixed-port': 7890,
            'allow-lan': True,
            'bind-address': '*',
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
                {
                    'name': '🚀 Proxy',
                    'type': 'select',
                    'proxies': ['♻️ Auto', '🔯 Fallback', '🔮 LoadBalance', 'DIRECT']
                },
                {
                    'name': '♻️ Auto',
                    'type': 'url-test',
                    'proxies': [],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300,
                    'tolerance': 50
                },
                {
                    'name': '🔯 Fallback',
                    'type': 'fallback',
                    'proxies': [],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                },
                {
                    'name': '🔮 LoadBalance',
                    'type': 'load-balance',
                    'strategy': 'consistent-hashing',
                    'proxies': [],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                },
                {
                    'name': '🌍 Global',
                    'type': 'select',
                    'proxies': ['🚀 Proxy', 'DIRECT']
                },
                {
                    'name': '🍃 Hijacking',
                    'type': 'select',
                    'proxies': ['REJECT', 'DIRECT']
                }
            ],
            'rules': [
                'DOMAIN-SUFFIX,local,DIRECT',
                'IP-CIDR,127.0.0.0/8,DIRECT',
                'IP-CIDR,172.16.0.0/12,DIRECT',
                'IP-CIDR,192.168.0.0/16,DIRECT',
                'IP-CIDR,10.0.0.0/8,DIRECT',
                'IP-CIDR,17.0.0.0/8,DIRECT',
                'IP-CIDR,100.64.0.0/10,DIRECT',
                'DOMAIN-SUFFIX,ir,DIRECT',
                'GEOIP,IR,DIRECT',
                'DOMAIN-KEYWORD,ads,🍃 Hijacking',
                'DOMAIN-KEYWORD,analytics,🍃 Hijacking',
                'DOMAIN-KEYWORD,facebook,🌍 Global',
                'DOMAIN-KEYWORD,google,🌍 Global',
                'DOMAIN-KEYWORD,instagram,🌍 Global',
                'DOMAIN-KEYWORD,telegram,🌍 Global',
                'DOMAIN-KEYWORD,twitter,🌍 Global',
                'DOMAIN-KEYWORD,youtube,🌍 Global',
                'MATCH,🚀 Proxy'
            ]
        }

        # اضافه کردن کانفیگ‌های معتبر
        valid_configs = [config['clash_info'] for config in self.parsed_clash_configs]

        if not valid_configs:
            print("⚠️ No valid configs after final filtering")
            return

        clash_config['proxies'] = valid_configs
        
        # اضافه کردن نام کانفیگ‌ها به گروه‌ها
        config_names = [c['name'] for c in valid_configs]
        clash_config['proxy-groups'][1]['proxies'] = config_names  # Auto
        clash_config['proxy-groups'][2]['proxies'] = config_names  # Fallback
        clash_config['proxy-groups'][3]['proxies'] = config_names  # LoadBalance

        try:
            # ذخیره فایل YAML
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, 
                         default_flow_style=False, indent=2, width=1000)
            print(f"✅ Saved {len(valid_configs)} valid configs to {OUTPUT_YAML}")
            
            # ذخیره فایل TXT
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join([c['original_url'] for c in self.parsed_clash_configs]))
            print(f"✅ Saved raw configs to {OUTPUT_TXT}")
            
            # نمایش آمار
            config_types = {}
            for config in valid_configs:
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
    print("📱 Make sure you have set API_ID and API_HASH environment variables")
    
    extractor = V2RayExtractor()
    await extractor.extract_configs()
    await extractor.save_configs()
    
    print("✨ Extraction completed!")
    print(f"📊 Total configs found: {len(extractor.found_configs)}")
    print(f"✅ Valid configs: {len(extractor.parsed_clash_configs)}")

if __name__ == "__main__":
    asyncio.run(main())