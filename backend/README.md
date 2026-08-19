# Backend kurulumu

## 1. Supabase tabloları

Supabase Dashboard içindeki **SQL Editor** bölümünde `sql/schema.sql` dosyasını çalıştırın.
Şema `urls`, `analyses` ve `risk_scores` tablolarını, indeksleri ve RLS ayarlarını oluşturur.

## 2. Ortam değişkenleri

`.env.example` dosyasını `.env` adıyla kopyalayın ve aşağıdaki değerleri doldurun:

```env
DATABASE_URL=postgresql://postgres:PASSWORD@db.PROJECT_REF.supabase.co:5432/postgres
VIRUSTOTAL_API_KEY=...
FRONTEND_ORIGIN=http://localhost:5173
```

`DATABASE_URL` parolası yalnızca backend'de tutulmalıdır. Frontend koduna veya Git'e
eklenmemelidir. Parolada özel URL karakterleri varsa percent-encoding uygulanmalıdır.
`VIRUSTOTAL_API_KEY` boş bırakılırsa diğer analizler çalışmaya devam eder.

`TELEGRAM_BOT_TOKEN` ve `TELEGRAM_CHAT_ID` birlikte tanımlanırsa risk skoru **80'den
büyük** analizlerde Telegram bildirimi gönderilir. Telegram erişilemezse analiz ve
veritabanı kaydı devam eder.

SMS/e-posta n8n workflow'u, metindeki bağlantıların VirusTotal özetini almak için
`POST /internal/signals/text-urls` adresini `X-N8N-Secret` başlığıyla çağırabilir.
Gövde: `{ "text": "..." }`. En fazla 10 benzersiz HTTP(S) URL'si kontrol edilir.

## 3. Kurulum ve çalıştırma

PowerShell:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8001
```

API dokümantasyonu: `http://127.0.0.1:8001/docs`

## 4. Test

```powershell
cd backend
.\venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\venv\Scripts\python.exe -m pytest -q
```

Temel endpoint'ler:

- `GET /health`
- `POST /analyze` — gövde: `{"url": "https://example.com"}`
- `POST /analyze-qr` — `multipart/form-data` içinde `file` alanıyla PNG/JPEG/WebP QR görseli

`N8N_QR_ENABLED=true` olduğunda QR'dan çıkarılan URL önce Sprint 3 QR webhook'unda
doğrulanır, ardından mevcut URL analiz akışına yönlendirilir.
- `POST /analyze-text` — gövde: `{"text": "Acil, hesabınızı doğrulayın."}`
- `GET /analyses?limit=50`

`/analyze-text`, mesajdaki aciliyet, korku, ödül vaadi, kimlik bilgisi talebi ve
şüpheli bağlantı sinyallerini döndürür. OpenAI kullanılamazsa anahtar kelime tabanlı
yedek analiz devreye girer; bu durumda yanıttaki `ai_used` değeri `false` olur.
`N8N_TEXT_ENABLED=true` olduğunda endpoint, SMS/e-posta n8n workflow'unu kullanarak
metindeki URL'leri VirusTotal ile kontrol eder ve bu bulguları risk puanına ekler.

## Sprint 2 gerçek uçtan uca testi

Bu test mock kullanmaz: çalışan FastAPI'ye istek gönderir; `N8N_TEXT_ENABLED=true`
ise istek n8n webhook'una, oradan da backend'in iç metin analizi uç noktasına gider.
Önce n8n ve FastAPI'yi `n8n/README.md` yönergeleriyle başlatın, sonra ayrı bir
terminalde çalıştırın:

```powershell
cd backend
$env:SPRINT2_E2E_BASE_URL="http://127.0.0.1:8001"
.\venv\Scripts\python.exe -m pytest -m e2e -q
```

Başarılı sonuç, `n8n_text_enabled: true` ile `status`, 0–100 arası `risk`, nedenler,
kullanıcı açıklaması ve `workflow_warnings` alanlarının gerçek servis zincirinden
geldiğini doğrular.
`SPRINT2_E2E_BASE_URL` tanımlı değilse bu test varsayılan test koşumunda atlanır.

## OpenAI API kotası

`insufficient_quota`, API projesinde faturalandırma/kredi bulunmadığını gösterir;
ChatGPT aboneliği API kredisi değildir. OpenAI hesabında billing ve proje bütçesini
etkinleştirdikten sonra backend'i yeniden başlatın. Kota veya geçici istek limiti
olmadığında platform risk hesaplamasını durdurmaz: anahtar kelime tabanlı analiz ve
deterministik Türkçe açıklama döner, yanıttaki `ai_used` alanı `false`, `ai_error`
alanı ise neden olur. OpenAI API anahtarını yalnızca backend `.env` dosyasında tutun.
