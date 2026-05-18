# rokno_a3 v2.0 - Web Intelligence & Technical Summary Engine

## نظام تحليل مواقع خفيف (Passive Recon Only)

### ✨ ما الجديد في v2.0

- **🎨 واجهة ملونة ذكية**: شريط تقدم متحرك + ألوان ANSI + حالات مرئية
- **🔧 إصلاح whatweb**: إذا فشلت الأداة، يستخدم curl + توقيعات يدوية تلقائياً
- **🤖 AI لا يفشل أبداً**: إذا فشلت خدمة AI، يستخدم تحليل محلي ذكي (لا N/A فارغة)
- **🔗 استخراج روابط محسّن**: gau + curl + robots.txt + sitemap.xml + regex للـ JS
- **📊 تقارير ذكية**: تعامل ذكي مع البيانات الناقصة - لا يظهر N/A قبيحة
- **🔄 fallback لكل أداة**: كل أداة لها بديل إذا فشلت

---

### ⚠️ حلول مشاكل التثبيت الشائعة

#### مشكلة 1: `pkg` لا يعمل مع root
```bash
# Ubuntu/Debian (ليس Termux):
sudo apt update
sudo apt install -y whois curl

# Termux (بدون root):
pkg install whois curl
```

#### مشكلة 2: `pip` - externally-managed-environment
```bash
# الحل الموصى به: venv
python3 -m venv ~/rokno_venv
source ~/rokno_venv/bin/activate
pip install requests

# أو تجاوز القيود:
pip install --break-system-packages requests

# أو apt:
sudo apt install python3-requests
```

#### مشكلة 3: ملف غير موجود
```bash
cd rokno_a3
python3 rokno_a3.py https://example.com
```

---

### المتطلبات الخارجية
```bash
sudo apt install -y whois curl

# اختياري (السكربت يعمل بدونها باستخدام fallback):
# whatweb, httpx, gau, assetfinder, linkfinder
```

### تثبيت Python
```bash
python3 -m venv ~/rokno_venv
source ~/rokno_venv/bin/activate
pip install requests
```

### الاستخدام

#### الوضع المجاني (بدون API key - افتراضي)
```bash
cd rokno_a3
python3 rokno_a3.py https://example.com
```
يستخدم تلقائياً **pollinations.ai** - مجاني 100% بدون تسجيل.

#### الوضع باستخدام Gemini (اختياري)
```bash
export GEMINI_API_KEY="AIza..."
python3 rokno_a3.py https://example.com
```

---

### 🛡️ Fallbacks المدمجة

| الأداة | الأساسي | البديل |
|--------|---------|--------|
| whatweb | whatweb JSON | curl + توقيعات يدوية 20+ تقنية |
| whois | whois CLI | RDAP API (curl) |
| httpx | httpx JSON | curl -I + regex |
| gau | gau | curl + href/src regex + robots.txt + sitemap.xml |
| assetfinder | assetfinder | crt.sh API |
| linkfinder | linkfinder.py | curl JS + regex endpoints |
| AI | Gemini / pollinations | تحليل محلي ذكي |

---

### هيكل المشروع
```
rokno_a3/
├── rokno_a3.py              ← المدخل الرئيسي (ملون + ذكي)
├── requirements.txt
├── README.md
├── config/
│   └── settings.py
├── core/
│   ├── validator.py
│   ├── engine.py            ← محرك مع خطوات واضحة
│   └── report_builder.py    ← تقارير ذكية بألوان
├── modules/
│   ├── domain_info.py       ← whois + RDAP fallback
│   ├── tech_detect.py       ← whatweb + curl + signatures
│   ├── server_headers.py    ← httpx + curl fallback
│   ├── link_collector.py    ← gau + curl + robots + sitemap + JS regex
│   ├── subdomain_finder.py  ← assetfinder + crt.sh
│   ├── data_compressor.py
│   └── gemini_analyzer.py   ← Gemini + Free AI + Local fallback
└── utils/
    ├── helpers.py
    └── terminal_ui.py       ← واجهة ملونة ذكية
```
