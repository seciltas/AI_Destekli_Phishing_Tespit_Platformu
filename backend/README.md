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
- `GET /analyses?limit=50`
