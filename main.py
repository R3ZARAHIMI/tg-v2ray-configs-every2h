import re
import asyncio
import base64
import json
import yaml
import os
import uuid
from urllib.parse import urlparse, parse_qs

# Pyrogram imports
from pyrogram import Client
from pyrogram.errors import FloodWait, RPCError

# --- تنظیمات عمومی ---
API_ID = int(os.environ.get("API_ID", 12345))
API_HASH = os.environ.get("API_HASH", "your_api_hash_here")
SESSION_NAME = "my_account"
CHANNELS = ["@SRCVPN", "@sezar_sec", "@Anty_Filter"]
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
        cleaned_name = re.sub(r'[^\w\s\-\_]', '', original_name)
        cleaned_name = cleaned_name.replace(' ', '_').strip('_-')
        return f"{cleaned_name}-{str(uuid.uuid4())[:8]}" if cleaned_name else f"{prefix}-{str(uuid.uuid4())[:8]}"

    def is_valid_config(self, config):
        required_fields = {
            'vless': ['server', 'port', 'uuid'],
            'vmess': ['server', 'port', 'uuid'],
            'trojan': ['server', 'port', 'password'],
            'ss': ['server', 'port', 'password', 'cipher']
        }
        
        if not config or not isinstance(config, dict):
            return False
            
        proxy_type = config.get('type')
        if not proxy_type or proxy_type not in required_fields:
            return False
            
        return all(field in config for field in required_fields[proxy_type])

    def parse_vmess(self, vmess_url):
        try:
            encoded_data = vmess_url.replace('vmess://', '')
            padding = len(encoded_data) % 4
            if padding:
                encoded_data += '=' * (4 - padding)

            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            config = json.loads(decoded_data)

            clash_config = {
                'name': self._generate_unique_name(config.get('ps', 'vmess')),
                'type': 'vmess',
                'server': config.get('add'),
                'port': int(config.get('port', 443)),
                'uuid': config.get('id'),
                'alterId': int(config.get('aid', 0)),
                'cipher': 'auto',
                'udp': True
            }

            if config.get('tls') == 'tls':
                clash_config.update({
                    'tls': True,
                    'servername': config.get('host', ''),
                    'skip-cert-verify': False
                })

            network = config.get('net', 'tcp')
            if network == 'ws':
                clash_config.update({
                    'network': 'ws',
                    'ws-opts': {
                        'path': config.get('path', '/'),
                        'headers': {'Host': config.get('host', '')} if config.get('host') else {}
                    }
                })
            elif network == 'h2':
                clash_config['network'] = 'http'
            elif network == 'grpc':
                clash_config.update({
                    'network': 'grpc',
                    'grpc-opts': {
                        'grpc-service-name': config.get('path', '')
                    }
                })

            return clash_config if self.is_valid_config(clash_config) else None
        except Exception:
            return None

    def parse_vless(self, vless_url):
        try:
            parsed = urlparse(vless_url)
            query = parse_qs(parsed.query)
            
            if not parsed.hostname or not parsed.username:
                return None

            clash_config = {
                'name': self._generate_unique_name(parsed.fragment or "vless"),
                'type': 'vless',
                'server': parsed.hostname,
                'port': parsed.port or 443,
                'uuid': parsed.username,
                'udp': True,
                'network': query.get('type', ['tcp'])[0]
            }

            security = query.get('security', [''])[0]
            if security == 'tls':
                clash_config.update({
                    'tls': True,
                    'servername': query.get('sni', [''])[0],
                    'skip-cert-verify': False
                })
            elif security == 'reality':
                clash_config.update({
                    'tls': True,
                    'reality-opts': {
                        'public-key': query.get('pbk', [''])[0],
                        'short-id': query.get('sid', [''])[0]
                    }
                })

            network = clash_config['network']
            if network == 'ws':
                clash_config['ws-opts'] = {
                    'path': query.get('path', ['/'])[0],
                    'headers': {'Host': query.get('host', [''])[0]} if query.get('host') else {}
                }
            elif network == 'grpc':
                clash_config['grpc-opts'] = {
                    'grpc-service-name': query.get('serviceName', [''])[0]
                }
            elif network == 'xhttp':
                clash_config['network'] = 'http'

            return clash_config if self.is_valid_config(clash_config) else None
        except Exception:
            return None

    async def check_channel(self, channel):
        try:
            print(f"🔍 Scanning channel {channel}...")
            async for message in self.client.get_chat_history(channel, limit=100):
                if not message.text:
                    continue

                for pattern in V2RAY_PATTERNS:
                    matches = pattern.findall(message.text)
                    for config_url in matches:
                        if config_url not in self.found_configs:
                            self.found_configs.add(config_url)
                            parsed_config = None
                            
                            if config_url.startswith('vmess://'):
                                parsed_config = self.parse_vmess(config_url)
                            elif config_url.startswith('vless://'):
                                parsed_config = self.parse_vless(config_url)
                            
                            if parsed_config:
                                self.parsed_clash_configs.append({
                                    'original_url': config_url,
                                    'clash_info': parsed_config
                                })

        except FloodWait as e:
            print(f"⏳ Waiting {e.value} seconds (Telegram limit) for {channel}")
            await asyncio.sleep(e.value)
            await self.check_channel(channel)
        except Exception as e:
            print(f"❌ Error in {channel}: {str(e)}")

    async def extract_configs(self):
        print("Connecting to Telegram...")
        try:
            async with self.client:
                print("✅ Connected successfully")
                await asyncio.gather(*[self.check_channel(channel) for channel in CHANNELS])
        except Exception as e:
            print(f"🔴 Connection error: {str(e)}")
            self.found_configs.clear()
            self.parsed_clash_configs.clear()

    async def save_configs(self):
        if not self.parsed_clash_configs:
            print("⚠️ No valid configs found")
            return

        clash_config = {
            'proxies': [],
            'proxy-groups': [
                {
                    'name': '🚀 Auto',
                    'type': 'url-test',
                    'proxies': [],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                },
                {
                    'name': '🔮 Proxy',
                    'type': 'select',
                    'proxies': ['🚀 Auto', 'DIRECT']
                }
            ],
            'rules': [
                'DOMAIN-SUFFIX,ir,DIRECT',
                'GEOIP,IR,DIRECT',
                'MATCH,🔮 Proxy'
            ]
        }

        valid_configs = []
        for config in self.parsed_clash_configs:
            if config['clash_info'] and self.is_valid_config(config['clash_info']):
                valid_configs.append(config['clash_info'])

        clash_config['proxies'] = valid_configs
        clash_config['proxy-groups'][0]['proxies'] = [c['name'] for c in valid_configs]

        try:
            with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, width=float("inf"))
            print(f"✅ Saved {len(valid_configs)} configs to {OUTPUT_YAML}")
            
            with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
                f.write("\n".join([c['original_url'] for c in self.parsed_clash_configs]))
            print(f"✅ Saved raw configs to {OUTPUT_TXT}")
            
        except Exception as e:
            print(f"❌ Save error: {str(e)}")

async def main():
    print("🚀 Starting V2Ray config extractor...")
    extractor = V2RayExtractor()
    await extractor.extract_configs()
    await extractor.save_configs()
    print("✨ Done!")

if __name__ == "__main__":
    asyncio.run(main())