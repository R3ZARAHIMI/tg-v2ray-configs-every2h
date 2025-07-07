async def check_channel(self, channel):
    """بررسی کانال و استخراج کانفیگ‌ها"""
    try:
        print(f"🔍 Scanning channel {channel}...")
        # limit=30 برای هر کانال
        async for message in self.client.get_chat_history(channel, limit=3): 
            # بررسی هم متن اصلی و هم متن نقل قول شده
            texts_to_scan = []
            
            if message.text:
                texts_to_scan.append(message.text)
            
            # اگر پیام نقل قول شده دارد
            if message.quote:
                if message.quote.text:
                    texts_to_scan.append(message.quote.text)
            
            # اگر پیام پاسخ دارد (reply)
            if message.reply_to_message:
                reply_msg = await self.client.get_messages(
                    message.chat.id,
                    message.reply_to_message_id
                )
                if reply_msg and reply_msg.text:
                    texts_to_scan.append(reply_msg.text)

            if not texts_to_scan:
                continue

            for text in texts_to_scan:
                processed_texts = [text]

                # --- منطق Base64 Decode فقط برای کانال‌های مشخص شده ---
                if channel in BASE64_ENCODED_CHANNELS:
                    base64_matches = BASE64_PATTERN.findall(text)
                    # print(f"DEBUG: Found {len(base64_matches)} potential Base64 strings in raw message from {channel}.")

                    for b64_str_match in base64_matches:
                        b64_str = b64_str_match if isinstance(b64_str_match, str) else b64_str_match[0]

                        try:
                            # حذف تمام whitespace ها (شامل فضا، تب، خط جدید)
                            cleaned_b64_str = re.sub(r'\s+', '', b64_str) 
                            # اضافه کردن padding قبل از decode
                            padding = len(cleaned_b64_str) % 4
                            if padding:
                                cleaned_b64_str += '=' * (4 - padding)

                            decoded_text = base64.b64decode(cleaned_b64_str).decode('utf-8', errors='ignore')
                            
                            # --- مهم: متن دی‌کد شده را خط به خط تقسیم کن ---
                            lines = decoded_text.splitlines()
                            for line in lines:
                                if line.strip():
                                    processed_texts.append(line.strip())
                            
                            # print(f"DEBUG: Successfully decoded Base64 from {channel}. Added {len(lines)} lines for scanning.")
                        except Exception as e:
                            print(f"DEBUG: Failed to decode Base64 string '{b64_str[:50]}...' from {channel}: {e}")
                # --- پایان منطق Base64 Decode ---

                for text_to_scan in processed_texts:
                    for pattern in V2RAY_PATTERNS:
                        matches = pattern.findall(text_to_scan)
                        for config_url in matches:
                            if config_url not in self.found_configs:
                                self.found_configs.add(config_url)
                                print(f"✅ Found new config from {channel}: {config_url[:60]}...")
                                
                                parsed_config = None
                                try:
                                    parsed_config = self.parse_config(config_url)
                                    
                                    if parsed_config:
                                        self.parsed_clash_configs.append({
                                            'original_url': config_url,
                                            'clash_info': parsed_config
                                        })
                                        # print(f"✅ Parsed config: {parsed_config['name']} ({parsed_config['type']})")
                                    else:
                                        print(f"❌ Failed to parse config or invalid structure: {config_url[:50]}...")
                                        
                                except Exception as e:
                                    print(f"❌ Error during parsing/adding: {str(e)} for URL: {config_url[:50]}...")

    except FloodWait as e:
        print(f"⏳ Waiting {e.value} seconds (Telegram limit) for {channel}")
        await asyncio.sleep(e.value)
        await self.check_channel(channel)
    except RPCError as e:
        print(f"❌ RPC error in {channel}: {e.MESSAGE} (Code: {e.CODE})")
    except Exception as e:
        print(f"❌ General error in {channel}: {str(e)}")