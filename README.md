# 🎒 Config Jo (کانفیگ جو)

این پروژه یک اسکریپت هوشمند پایتون است که به صورت خودکار (هر ۲ ساعت) کانال‌های تلگرامی را اسکن کرده و کانفیگ‌های فعال V2Ray را استخراج و مرتب‌سازی می‌کند.

> **✨ نسخه جدید (v2.0):** اضافه شدن آرشیو هوشمند هفتگی و تفکیک کشورها.

---

## 🚀 قابلیت‌های کلیدی (Features)

### ۱. 📅 آرشیو هفتگی هوشمند (Smart Rolling Window)
برخلاف روش‌های قدیمی که فایل‌ها را در یک روز خاص کاملاً پاک می‌کردند، این سیستم از روش **"پنجره شناور"** استفاده می‌کند:
- هر کانفیگ دقیقاً **۷ روز** پس از اضافه شدن در لیست باقی می‌ماند.
- کانفیگ‌های قدیمی به صورت **تکی** حذف می‌شوند (نه حذف کل فایل).
- این یعنی همیشه به کانفیگ‌های زنده هفته گذشته دسترسی دارید بدون اینکه لیست ناگهان خالی شود.
- **فایل:** `conf-week.txt`

### ۲. 🌍 تفکیک کشورهای محبوب (Top Countries)
کانفیگ‌های استخراج شده به صورت خودکار پردازش شده و کشورهای پرطرفدار در فایل‌های جداگانه ذخیره می‌شوند تا دسترسی راحت‌تری داشته باشید:
- 🇺🇸 **آمریکا:** `conf-US.txt`
- 🇩🇪 **آلمان:** `conf-DE.txt`
- 🇳🇱 **هلند:** `conf-NL.txt`
- 🇬🇧 **انگلیس:** `conf-UK.txt`
- 🇫🇷 **فرانسه:** `conf-FR.txt`

---

## 🔗 لینک‌های سابسکرایب (Subscription Links)

برای کپی کردن، روی دکمه‌ی کپی در گوشه سمت راست کادر کلیک کنید.

### 📦 آرشیوهای اصلی

**اصلی (همه) - (پیشنهادی و سبک‌تر)**
شامل آخرین کانفیگ‌های استخراج شده:
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.txt)
```

**آرشیو هفتگی**
شامل آرشیو کامل ۷ روزه (تعداد بالا):
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-week.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-week.txt)
```

---

### 🌍 بر اساس کشور (اختصاصی)

**🇺🇸 آمریکا (USA)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-US.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-US.txt)
```

**🇩🇪 آلمان (Germany)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-DE.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-DE.txt)
```

**🇳🇱 هلند (Netherlands)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-NL.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-NL.txt)
```

**🇬🇧 انگلیس (UK)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-UK.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-UK.txt)
```

**🇫🇷 فرانسه (France)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-FR.txt](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-FR.txt)
```

---

### ⚙️ کلاینت‌های خاص

**Clash Meta (فرمت YAML)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config-jo.yaml](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config-jo.yaml)
```

**Sing-box (فرمت JSON)**
```
[https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.json](https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.json)
```

---

## 🤖 نحوه کارکرد (How it Works)
1. **اسکن:** اسکریپت هر ۲ ساعت اجرا می‌شود و لیست کانال‌های تلگرام را بررسی می‌کند.
2. **استخراج:** پروتکل‌های `vmess`, `vless`, `trojan`, `ss`, `hysteria2`, `tuic` شناسایی می‌شوند.
3. **پالایش:** نام کشور و پرچم به نام کانفیگ اضافه می‌شود.
4. **دسته‌بندی:**
   - کانفیگ‌ها در فایل اصلی `Config_jo.txt` ذخیره می‌شوند.
   - کانفیگ‌های جدید به آرشیو هفتگی `conf-week.txt` اضافه می‌شوند (و قدیمی‌ها حذف می‌شوند).
   - کانفیگ‌های ۵ کشور برتر در فایل‌های جداگانه کپی می‌شوند.
5. **انتشار:** تغییرات به صورت خودکار در گیت‌هاب Push می‌شوند.

---

## ⚠️ سلب مسئولیت (Disclaimer)
این پروژه صرفاً یک ابزار متن‌باز برای جمع‌آوری اطلاعات عمومی منتشر شده در تلگرام است. هیچ‌یک از سرورها متعلق به ما نیست و مسئولیتی در قبال محتوا یا پایداری آن‌ها نداریم.
