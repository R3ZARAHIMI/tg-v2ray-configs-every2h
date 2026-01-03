# 🎒 Config Jo — کانفیگ جو

**Config Jo** یک اسکریپت هوشمند پایتون است که به‌صورت خودکار (هر ۲ ساعت) کانال‌های تلگرام را اسکن می‌کند،  
کانفیگ‌های فعال **V2Ray** را استخراج کرده، پالایش می‌کند و در فایل‌های مرتب و قابل سابسکرایب منتشر می‌کند.

> ✨ **نسخه 2.0**  
> اضافه شدن آرشیو هوشمند هفتگی (Rolling Window) و تفکیک کانفیگ‌ها بر اساس کشور

---

## 🚀 قابلیت‌ها (Features)

### 📅 آرشیو هفتگی هوشمند (Smart Rolling Window)
برخلاف روش‌های سنتی که کل فایل‌ها را در یک روز خاص پاک می‌کردند، Config Jo از **پنجره شناور ۷ روزه** استفاده می‌کند:

- هر کانفیگ دقیقاً **۷ روز پس از اضافه شدن** در لیست باقی می‌ماند
- حذف کانفیگ‌ها **تکی و زمان‌محور** انجام می‌شود (نه پاک‌سازی کامل فایل)
- همیشه به کانفیگ‌های زنده‌ی هفته‌ی اخیر دسترسی دارید
- بدون شوک خالی شدن ناگهانی لیست

📄 **فایل:** `conf-week.txt`

---

### 🌍 تفکیک کشورهای پرطرفدار (Top Countries)

| کشور | فایل |
|----|----|
| 🇺🇸 آمریکا | `conf-US.txt` |
| 🇩🇪 آلمان | `conf-DE.txt` |
| 🇳🇱 هلند | `conf-NL.txt` |
| 🇬🇧 انگلیس | `conf-UK.txt` |
| 🇫🇷 فرانسه | `conf-FR.txt` |

---

## 🔗 لینک‌های سابسکرایب (Subscription Links)

### ⭐ فایل اصلی (پیشنهادی)
```text
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.txt
```

### 📅 آرشیو هفتگی
```text
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-week.txt
```

---

### 🌍 سابسکرایب بر اساس کشور

```text
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-US.txt
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-DE.txt
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-NL.txt
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-UK.txt
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/conf-FR.txt
```

---

### ⚙️ کلاینت‌های پشتیبانی‌شده

**Clash Meta**
```text
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config-jo.yaml
```

**Sing-box**
```text
https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.json
```

---

## ⚠️ سلب مسئولیت (Disclaimer)

این پروژه صرفاً یک ابزار متن‌باز برای جمع‌آوری کانفیگ‌های عمومی منتشرشده در تلگرام است.
