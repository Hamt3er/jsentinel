# JSentinel

**JSentinel** أداة احترافية مكتوبة بلغة **Go** لتحليل ملفات JavaScript بشكل **سلبي Passive Analysis** داخل نطاقات مصرح لك باختبارها فقط.  
الأداة مناسبة لعمل **Bug Bounty / AppSec / JS Recon** بدون تنفيذ استغلال أو إرسال محاولات تسجيل دخول أو اختبار صلاحية الأسرار المكتشفة.

> الاستخدام المسموح فقط على الأصول التي لديك إذن صريح لفحصها.  
> الأداة **تجمع وتحلل فقط** ما هو متاح علنًا من ملفات JS وخرائط sourcemap والروابط المرتبطة بها.

---

## المزايا

- فحص **ملف JS محلي**
- فحص **رابط JS مباشر**
- فحص **موقع كامل**:
  - استخراج ملفات JS من الصفحة
  - تحليل الروابط الداخلية
  - جمع `script src`
  - محاولة اكتشاف `sitemap.xml`
  - دعم `robots.txt`
- استخراج:
  - الروابط endpoints
  - الدومينات
  - مسارات API
  - مفاتيح/أسرار محتملة **Suspected Secrets**
  - التوكنات ذات entropy العالي
  - ملفات source maps
  - مؤشرات التخزين المحلي localStorage/sessionStorage
  - دوال وسلوكيات خطرة مثل:
    - `eval`
    - `new Function`
    - `innerHTML`
    - `document.write`
    - `postMessage`
    - `fetch`
    - `XMLHttpRequest`
    - `WebSocket`
- إخراج:
  - JSON
  - Markdown
  - نص console مرتب
- فلترة حسب النطاق
- حد للطلبات
- concurrency مضبوط
- timeout
- User-Agent مخصص
- دعم Linux / macOS / Windows عبر بناء Go المعتاد

---

## تحذير مهم

JSentinel لا يقوم بـ:
- تجربة المفاتيح أو التوكنات
- تسجيل دخول
- تخطي صلاحيات
- brute-force
- bypass
- تنفيذ payloads هجومية

هو أداة **تحليل ثابت + جمع سلبي** فقط. هذا يجعلها مناسبة أكثر للعمل المنضبط في برامج Bug Bounty.

---

## هيكلة المشروع

```text
jsentinel/
├── cmd/jsentinel/main.go
├── internal/config/config.go
├── internal/fetcher/fetcher.go
├── internal/parser/parser.go
├── internal/scanner/scanner.go
├── internal/report/report.go
├── go.mod
├── README.md
└── .gitignore
```

---

## التثبيت

### 1) تثبيت Go

تحقق من الإصدار:

```bash
go version
```

يفضل Go 1.22 أو أحدث.

### 2) استنساخ المشروع

```bash
git clone https://github.com/Hamt3er/jsentinel.git
cd jsentinel
```

### 3) جلب الاعتماديات

```bash
go mod tidy
```

### 4) بناء الأداة

#### لينكس / macOS / ويندوز

```bash
go build -o jsentinel ./cmd/jsentinel
```

على ويندوز:

```powershell
go build -o jsentinel.exe .\cmd\jsentinel
```

---

## الاستخدام السريع

### فحص ملف محلي

```bash
./jsentinel -file ./app.js
```

### فحص رابط JS مباشر

```bash
./jsentinel -url https://target.tld/static/app.js
```

### فحص موقع كامل

```bash
./jsentinel -site https://target.tld
```

### حفظ التقرير بصيغة JSON

```bash
./jsentinel -site https://target.tld -json-out report.json
```

### حفظ التقرير بصيغة Markdown

```bash
./jsentinel -site https://target.tld -md-out report.md
```

### تقييد التحليل على نفس النطاق فقط

```bash
./jsentinel -site https://target.tld -same-host
```

### زيادة عدد الروابط الداخلية المراد زيارتها

```bash
./jsentinel -site https://target.tld -max-pages 30
```

### ضبط عدد ملفات JS القصوى

```bash
./jsentinel -site https://target.tld -max-js 100
```

### تغيير User-Agent

```bash
./jsentinel -site https://target.tld -ua "Mozilla/5.0 JSentinel/1.0"
```

---

## كيف تعمل الأداة عمليًا

### وضع `-file`
- تقرأ ملف JavaScript محلي
- تستخرج:
  - endpoints
  - secrets محتملة
  - مصادر خارجية
  - مؤشرات الكود الخطر
- تعطيك تقرير جاهز

### وضع `-url`
- تجلب ملف JS من رابط مباشر
- تحلله بدون أي تنفيذ
- تكشف sourcemap إن وجد
- تعطيك تقريرًا مجمعًا

### وضع `-site`
- تجلب الصفحة الرئيسية
- تستخرج:
  - جميع ملفات JS من `script src`
  - الروابط الداخلية
  - robots.txt
  - sitemap.xml إن أمكن
- تزور عددًا محدودًا من الصفحات الداخلية
- تستخرج JS من الصفحات
- تحلل الملفات المجمعة
- تنتج تقريرًا موحدًا

---

## أمثلة عملية

### 1) تحليل ملف bundle كبير

```bash
./jsentinel -file ./main.8dd12a.js -md-out main_report.md
```

### 2) تحليل أصل ضمن برنامج Bug Bounty

```bash
./jsentinel -site https://app.example.com -same-host -max-pages 25 -max-js 120 -json-out app.json
```

### 3) تحليل JS من CDN معروف داخل النطاق المصرح

```bash
./jsentinel -url https://cdn.example.com/assets/runtime.js
```

---

## قراءة النتائج

### `Suspected Secrets`
هذه ليست أسرار مؤكدة دائمًا. الأداة تكتشف:
- AWS access key patterns
- GitHub token-like strings
- Google API keys
- Slack token-like strings
- JWT-like strings
- strings عالية entropy
- أسماء متغيرات أو مفاتيح تدل على:
  - api_key
  - secret
  - token
  - bearer
  - auth
  - client_secret
  - private_key

**مهم:** لا تقم بتجربة أو استخدام هذه القيم إلا إذا كان ذلك ضمن سماح البرنامج وبشكل قانوني ومنضبط.

### `Dangerous Sinks`
تفيد في مراجعة:
- DOM XSS
- client-side injection
- insecure message handling
- script injection surfaces

### `Source Maps`
إذا تم العثور على:
- `//# sourceMappingURL=...`
- ملف `.map`

فقد تحصل على:
- مسارات source أصلية
- أسماء ملفات
- بنية المشروع

---

## الإخراج JSON

التقرير يشمل:
- الهدف
- وقت الفحص
- ملفات JS التي تم تحليلها
- جميع النتائج المستخرجة
- ملخص بعدد العناصر

---

## الإخراج Markdown

مناسب لرفعه إلى:
- GitHub
- Notion
- تقارير Bug Bounty الأولية
- التوثيق الشخصي

---

## بناء نسخ لجميع الأنظمة

### لينكس amd64

```bash
GOOS=linux GOARCH=amd64 go build -o dist/jsentinel-linux-amd64 ./cmd/jsentinel
```

### لينكس arm64

```bash
GOOS=linux GOARCH=arm64 go build -o dist/jsentinel-linux-arm64 ./cmd/jsentinel
```

### macOS amd64

```bash
GOOS=darwin GOARCH=amd64 go build -o dist/jsentinel-darwin-amd64 ./cmd/jsentinel
```

### macOS arm64

```bash
GOOS=darwin GOARCH=arm64 go build -o dist/jsentinel-darwin-arm64 ./cmd/jsentinel
```

### Windows amd64

```bash
GOOS=windows GOARCH=amd64 go build -o dist/jsentinel-windows-amd64.exe ./cmd/jsentinel
```

---

## رفع المشروع إلى GitHub

### 1) إنشاء مستودع جديد على GitHub
أنشئ repo جديدًا باسم:

```text
jsentinel
```

### 2) تهيئة git محليًا

```bash
git init
git add .
git commit -m "Initial commit: JSentinel passive JS analysis tool"
```

### 3) ربط المستودع

```bash
git branch -M main
git remote add origin https://github.com/Hamt3er/jsentinel.git
git push -u origin main
```

### 4) إضافة Release لاحقًا
بعد بناء الملفات في `dist/` يمكنك رفعها كـ release assets.

---

## تحسينات مستقبلية مقترحة

- دعم headless browser اختياري
- دعم STDIN list mode
- دعم multiple targets
- دعم HTML report
- dedup أفضل للمسارات
- parser لـ source map JSON متقدم
- scoring للمخاطر
- GitHub Actions لبناء releases تلقائيًا

---

## ملاحظات تشغيلية مهمة

- لا تشغّل الأداة على نطاقات غير مصرح لك بها
- لا ترفع التقارير العامة إذا تضمنت أسرارًا حقيقية
- راجع النتائج يدويًا قبل إرسال أي bug report
- استخدم `-same-host` لتقليل الضوضاء
- اجمع النتائج مع أدوات أخرى مثل:
  - gau
  - waybackurls
  - katana
  - httpx
  - nuclei
  - لكن ضمن النطاق المسموح فقط

---

## ترخيص

اختر الترخيص الذي تفضله، مثل MIT.

