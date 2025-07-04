import re
import asyncio
import aiohttp
import time
import base64
import json
import yaml
from pyrogram import Client
from pyrogram.errors import FloodWait
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import subprocess
import platform
import uuid
import os


# اطلاعات API تلگرام
# info.py

API_ID = int(os.environ.get("API_ID"))
API_HASH = os.environ.get("API_HASH")
BOT_TOKEN = os.environ.get("BOT_TOKEN")

# تنظیمات
CHANNELS = [
    "@SRCVPN",
    "@sezar_sec",
    "@SRCVPN",
    "@Anty_Filter",
    "@proxy_kafee",
    "@vpns"
]

OUTPUT_YAML = "Config-jo.yaml"  # خروجی به فرمت YAML برای Clash
OUTPUT_TXT = "Config_jo.txt"    # خروجی به فرمت متنی ساده
SESSION_NAME = "my_account"

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

# تنظیمات پروکسی (اختیاری)
# PROXY = {
#     "hostname": "127.0.0.1",
#     "port": 10808,
#     "scheme": "socks5"
# }

# تنظیمات تست
TEST_SETTINGS = {
    "timeout": 10,
    "test_urls": [
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip"
    ],
    "max_workers": 20,
    "ping_count": 3
}

class ConfigTester:
    def __init__(self):
        self.working_configs = []
        self.failed_configs = []
    
    def parse_config(self, config_url):
        """تجزیه و تحلیل کانفیگ برای استخراج اطلاعات اتصال"""
        try:
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
            print(f"❌ خطا در تجزیه کانفیگ: {str(e)}")
            return None
    
    def parse_vmess(self, vmess_url):
        """تجزیه VMess کانفیگ"""
        try:
            encoded_data = vmess_url.replace('vmess://', '')
            # Padding برای decode base64
            padding = len(encoded_data) % 4
            if padding:
                encoded_data += '=' * (4 - padding)
            
            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            config = json.loads(decoded_data)
            
            clash_config = {
                'name': config.get('ps', f"vmess-{str(uuid.uuid4())[:8]}"),
                'type': 'vmess',
                'server': config.get('add'),
                'port': int(config.get('port', 443)),
                'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)),
                'cipher': config.get('scy', 'auto'),
                'tls': config.get('tls') == 'tls',
                'skip-cert-verify': False,
                'network': config.get('net', 'tcp'),
                'udp': True
            }

            # تنظیمات برای websocket
            if clash_config['network'] == 'ws':
                clash_config['ws-opts'] = {
                    'path': config.get('path', '/'),
                    'headers': {'Host': config.get('host', '')} if config.get('host') else {}
                }

            # تنظیمات برای HTTP/2
            if clash_config['network'] == 'h2':
                clash_config['h2-opts'] = {
                    'path': config.get('path', '/'),
                    'host': [config.get('host', '')] if config.get('host') else []
                }

            # تنظیمات برای gRPC
            if clash_config['network'] == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': config.get('path', '')
                }

            return clash_config

        except Exception as e:
            print(f"❌ خطا در تجزیه VMess: {str(e)}")
            return None
    
    def parse_vless(self, vless_url):
        """تجزیه VLESS کانفیگ"""
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            
            clash_config = {
                'name': parse_qs(parsed.fragment).get('', [f"vless-{str(uuid.uuid4())[:8]}"])[0],
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'tls': query.get('security', [''])[0] == 'tls',
                'skip-cert-verify': False,
                'udp': True,
                'network': query.get('type', ['tcp'])[0],
                'servername': query.get('sni', [''])[0]
            }

            # تنظیمات flow برای XTLS
            if 'flow' in query:
                clash_config['flow'] = query['flow'][0]

            # تنظیمات برای websocket
            if clash_config['network'] == 'ws':
                clash_config['ws-opts'] = {
                    'path': query.get('path', ['/'])[0],
                    'headers': {'Host': query.get('host', [''])[0]} if query.get('host') else {}
                }

            # تنظیمات برای HTTP/2
            if clash_config['network'] == 'h2':
                clash_config['h2-opts'] = {
                    'path': query.get('path', ['/'])[0],
                    'host': [query.get('host', [''])[0]] if query.get('host') else []
                }

            # تنظیمات برای gRPC
            if clash_config['network'] == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': query.get('serviceName', [''])[0]
                }

            return clash_config

        except Exception as e:
            print(f"❌ خطا در تجزیه VLESS: {str(e)}")
            return None
    
    def parse_trojan(self, trojan_url):
        """تجزیه Trojan کانفیگ"""
        try:
            parsed = urlparse(trojan_url)
            query = parse_qs(parsed.query)
            
            return {
                'name': parsed.fragment or f"trojan-{str(uuid.uuid4())[:8]}",
                'type': 'trojan',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'password': parsed.username,
                'sni': query.get('sni', [''])[0],
                'skip-cert-verify': False,
                'udp': True,
                'network': query.get('type', ['tcp'])[0],
                'alpn': query.get('alpn', [''])[0].split(',') if query.get('alpn') else None
            }

        except Exception as e:
            print(f"❌ خطا در تجزیه Trojan: {str(e)}")
            return None
    
    def parse_shadowsocks(self, ss_url):
        """تجزیه Shadowsocks کانفیگ"""
        try:
            if '@' in ss_url:
                method_password, server_info = ss_url.replace('ss://', '').split('@')
                # Padding برای decode base64
                padding = len(method_password) % 4
                if padding:
                    method_password += '=' * (4 - padding)
                
                method_password = base64.b64decode(method_password).decode('utf-8')
                method, password = method_password.split(':', 1)
                host, port = server_info.split(':')
                
                return {
                    'name': f"ss-{str(uuid.uuid4())[:8]}",
                    'type': 'ss',
                    'server': host,
                    'port': int(port),
                    'password': password,
                    'cipher': method,
                    'udp': True
                }

        except Exception as e:
            print(f"❌ خطا در تجزیه Shadowsocks: {str(e)}")
            return None
    
    def parse_hysteria(self, hysteria_url):
        """تجزیه Hysteria کانفیگ"""
        try:
            parsed = urlparse(hysteria_url)
            query = parse_qs(parsed.query)
            
            return {
                'name': parsed.fragment or f"hysteria-{str(uuid.uuid4())[:8]}",
                'type': 'hysteria',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'auth_str': parsed.username,
                'obfs': query.get('obfsParam', [''])[0],
                'protocol': query.get('protocol', ['udp'])[0],
                'up_mbps': int(query.get('upmbps', ['10'])[0]),
                'down_mbps': int(query.get('downmbps', ['50'])[0]),
                'sni': query.get('peer', [''])[0],
                'skip-cert-verify': False,
                'alpn': query.get('alpn', [''])[0].split(',') if query.get('alpn') else None
            }

        except Exception as e:
            print(f"❌ خطا در تجزیه Hysteria: {str(e)}")
            return None
    
    def parse_tuic(self, tuic_url):
        """تجزیه TUIC کانفیگ"""
        try:
            parsed = urlparse(tuic_url)
            query = parse_qs(parsed.query)
            
            return {
                'name': parsed.fragment or f"tuic-{str(uuid.uuid4())[:8]}",
                'type': 'tuic',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'password': query.get('password', [''])[0],
                'sni': query.get('sni', [''])[0],
                'udp-relay-mode': query.get('udp-relay-mode', ['native'])[0],
                'skip-cert-verify': False,
                'alpn': query.get('alpn', [''])[0].split(',') if query.get('alpn') else None
            }

        except Exception as e:
            print(f"❌ خطا در تجزیه TUIC: {str(e)}")
            return None
    
    async def test_config_connection(self, config_info, config_url):
        """تست اتصال کانفیگ"""
        if not config_info:
            return False, "نمی‌تواند کانفیگ را تجزیه کند"
        
        # تست پینگ
        ping_result = await self.ping_test(config_info['server'])
        if not ping_result:
            return False, "پینگ ناموفق"
        
        # تست اتصال TCP
        tcp_result = await self.tcp_test(config_info['server'], config_info['port'])
        if not tcp_result:
            return False, "اتصال TCP ناموفق"
        
        return True, f"موفق - پینگ: {ping_result}ms"
    
    async def ping_test(self, host):
        """تست پینگ"""
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", host]
            else:
                cmd = ["ping", "-c", "1", host]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                if "time=" in output:
                    time_match = re.search(r'time=(\d+(?:\.\d+)?)ms', output)
                    if time_match:
                        return float(time_match.group(1))
                return 0
            return False
        except:
            return False
    
    async def tcp_test(self, host, port):
        """تست اتصال TCP"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def test_single_config(self, config_url):
        """تست یک کانفیگ"""
        try:
            config_info = self.parse_config(config_url)
            success, message = await self.test_config_connection(config_info, config_url)
            
            result = {
                'config': config_url,
                'info': config_info,
                'working': success,
                'message': message,
                'test_time': time.time()
            }
            
            if success:
                self.working_configs.append(result)
                name = config_info['name'] if config_info else 'Unknown'
                print(f"✅ {name}: {message}")
            else:
                self.failed_configs.append(result)
                name = config_info['name'] if config_info else 'Unknown'
                print(f"❌ {name}: {message}")
            
            return result
            
        except Exception as e:
            print(f"❌ خطا در تست کانفیگ: {str(e)}")
            return None
    
    async def test_all_configs(self, configs):
        """تست همه کانفیگ‌ها"""
        print(f"🧪 شروع تست {len(configs)} کانفیگ...")
        print("=" * 50)
        
        semaphore = asyncio.Semaphore(TEST_SETTINGS['max_workers'])
        
        async def test_with_semaphore(config):
            async with semaphore:
                return await self.test_single_config(config)
        
        tasks = [test_with_semaphore(config) for config in configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        print("=" * 50)
        print(f"📊 نتیجه تست:")
        print(f"✅ کانفیگ‌های کاری: {len(self.working_configs)}")
        print(f"❌ کانفیگ‌های غیرفعال: {len(self.failed_configs)}")
        print(f"📈 نرخ موفقیت: {len(self.working_configs)/(len(self.working_configs)+len(self.failed_configs))*100:.1f}%")
        
        return self.working_configs

class V2RayExtractor:
    def __init__(self):
        self.found_configs = set()
        self.client = Client(
            SESSION_NAME,
            api_id=API_ID,
            api_hash=API_HASH,
            proxy=PROXY
        )
        self.tester = ConfigTester()
    
    async def check_channel(self, channel):
        try:
            print(f"🔍 در حال بررسی کانال {channel}...")
            async for message in self.client.get_chat_history(channel, limit=5):
                if not message.text:
                    continue
               
                for pattern in V2RAY_PATTERNS:
                    matches = pattern.findall(message.text)
                    for config in matches:
                        if config not in self.found_configs:
                            self.found_configs.add(config)
                            print(f"✅ کانفیگ جدید یافت شد از {channel}: {config[:60]}...")
       
        except FloodWait as e:
            print(f"⏳ نیاز به انتظار {e.value} ثانیه (محدودیت تلگرام)")
            await asyncio.sleep(e.value)
            await self.check_channel(channel)
        except Exception as e:
            print(f"❌ خطا در {channel}: {str(e)}")
    
    async def extract_configs(self):
        async with self.client:
            tasks = [self.check_channel(channel) for channel in CHANNELS]
            await asyncio.gather(*tasks)
    
    async def test_and_save_configs(self):
        """تست و ذخیره کانفیگ‌ها به هر دو فرمت YAML و TXT"""
        if not self.found_configs:
            print("⚠️ هیچ کانفیگ جدیدی یافت نشد")
            # ایجاد فایل‌های خالی
            open(OUTPUT_YAML, "w").close()
            open(OUTPUT_TXT, "w").close()
            return
        
        print(f"\n🚀 شروع تست کردن کانفیگ ها...")
        working_configs = await self.tester.test_all_configs(list(self.found_configs))
        
        if working_configs:
            # ذخیره به فرمت YAML برای Clash
            clash_config = {
                'proxies': [],
                'proxy-groups': [
                    {
                        'name': '🚀 Auto Select',
                        'type': 'url-test',
                        'proxies': [],
                        'url': 'http://www.gstatic.com/generate_204',
                        'interval': 300
                    },
                    {
                        'name': '🔮 Proxy',
                        'type': 'select',
                        'proxies': ['🚀 Auto Select', 'DIRECT']
                    },
                    {
                        'name': '🎯 Domestic',
                        'type': 'select',
                        'proxies': ['DIRECT']
                    }
                ],
                'rules': [
                    'DOMAIN-SUFFIX,ir,🎯 Domestic',
                    'GEOIP,IR,🎯 Domestic',
                    'MATCH,🔮 Proxy'
                ]
            }
            
            # ذخیره به فرمت متنی ساده
            raw_configs = []
            
            for config_result in working_configs:
                if config_result['info']:
                    clash_config['proxies'].append(config_result['info'])
                    clash_config['proxy-groups'][0]['proxies'].append(config_result['info']['name'])
                raw_configs.append(config_result['config'])
            
            # ذخیره فایل YAML
            with open(OUTPUT_YAML, "w", encoding="utf-8") as f:
                yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
            
            # ذخیره فایل متنی
            with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
                f.write("\n".join(raw_configs))
            
            print(f"🎉 {len(working_configs)} کانفیگ کارکرده ذخیره شد:")
            print(f"  - فرمت Clash: {OUTPUT_YAML}")
            print(f"  - فرمت متنی: {OUTPUT_TXT}")
            
            # نمایش جزئیات کانفیگ‌های کاری
            print(f"\n📋 لیستی از کانفیگ های کاری:")
            for i, config_result in enumerate(working_configs[:10], 1):
                info = config_result['info']
                if info:
                    print(f"{i}. {info['name']} ({info['type']}) - {info['server']}:{info['port']}")
                else:
                    print(f"{i}. {config_result['config'][:50]}...")
        else:
            print("😞 هیچ کانفیگ کاری یافت نشد!")
            # ایجاد فایل‌های خالی
            open(OUTPUT_YAML, "w").close()
            open(OUTPUT_TXT, "w").close()

async def main():
    print("🚀 شروع استخراج و تست کانفیگ‌های V2Ray...")
    print("=" * 60)
    
    extractor = V2RayExtractor()
    
    await extractor.extract_configs()
    await extractor.test_and_save_configs()
    
    print("=" * 60)
    print("✨ اتمام کار!")

if __name__ == "__main__":
    asyncio.run(main())