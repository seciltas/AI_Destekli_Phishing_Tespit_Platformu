# n8n — Sprint 1 URL analiz workflow'u

## n8n nedir?

n8n, API'leri ve işlemleri görsel bir akış üzerinde birbirine bağlayan bir otomasyon
uygulamasıdır. Her kutuya **node**, kutular arasındaki bağlantılara **connection**, tüm
şemaya **workflow** denir.

Bu projede n8n risk puanını hesaplamaz. Analiz adımlarını doğru sırada çağırır. Risk
hesabı ve Supabase kaydı FastAPI'de kalır.

```text
Webhook
  → WHOIS
  → DNS
  → SSL
  → Brand Similarity
  → VirusTotal
  → Combine Signals
  → Respond to Webhook
```

## Node'ların görevleri

1. **Webhook:** FastAPI'den `url` ve `domain` alanlarını alır.
2. **WHOIS:** Alan adının kayıt tarihini, yaşını ve registrar bilgisini alır.
3. **DNS:** A, MX ve NS kayıtlarını sorgular.
4. **SSL:** 443 portunda sertifikayı doğrular ve son kullanma tarihini alır.
5. **Brand Similarity:** Levenshtein mesafesiyle alan adını bilinen markalarla karşılaştırır.
6. **VirusTotal:** URL'nin VirusTotal analiz istatistiklerini alır. API anahtarı yoksa bu
   adım `configured: false` döndürür ve workflow devam eder.
7. **Combine Signals:** Önceki node çıktılarından tek bir JSON oluşturur.
8. **Respond to Webhook:** JSON sonucunu FastAPI'ye geri gönderir.

## İlk kurulum

Ön koşul: Docker Desktop açık ve sol alt köşede motor durumu **Running** olmalıdır.

Proje kökünden:

```powershell
cd n8n
docker compose --env-file .env -f docker-compose.yml up -d
```

n8n arayüzünü açın:

```text
http://localhost:5678
```

İlk açılışta n8n yerel owner hesabı oluşturmanızı isteyebilir. Buradaki hesap sadece
bilgisayarınızdaki n8n arayüzünü korur; Supabase veya GitHub hesabınız değildir.

Workflow otomatik import edilmemişse:

1. Sol menüden **Workflows** bölümünü açın.
2. Sağ üstteki üç nokta menüsünden **Import from File** seçin.
3. `workflows/sprint-1-url-analysis.json` dosyasını seçin.
4. Workflow'u açıp sağ üstten **Publish** düğmesine basın.

Bu bilgisayarda workflow daha önce CLI ile import edilip yayınlandı.

## Üç farklı URL kavramı

- **Editor URL:** `http://localhost:5678` — workflow tasarım ekranı.
- **Test URL:** Node'u elle dinlerken kullanılan geçici `/webhook-test/...` adresi.
- **Production URL:** Yayınlanmış workflow için sürekli açık `/webhook/...` adresi.

FastAPI production URL'yi kullanır:

```text
http://localhost:5678/webhook/phishing-url-analysis
```

## Tüm projeyi çalıştırma

Önce Docker Desktop'ı açın. Ardından üç terminal kullanın.

Terminal 1 — n8n:

```powershell
cd n8n
docker compose --env-file .env -f docker-compose.yml up -d
```

Terminal 2 — FastAPI:

```powershell
cd backend
.\venv\Scripts\python.exe -m uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

`--host 0.0.0.0` önemlidir: FastAPI yalnızca `127.0.0.1` üzerinde dinlerse Docker
container içindeki n8n ona ulaşamayabilir.

Terminal 3 — React:

```powershell
cd frontend
npm run dev
```

Kontrol adresleri:

- Frontend: `http://localhost:5173`
- FastAPI docs: `http://localhost:8001/docs`
- FastAPI health: `http://localhost:8001/health`
- n8n editor: `http://localhost:5678`

Sağlık cevabında aşağıdaki üç değer beklenir:

```json
{
  "status": "ok",
  "database_configured": true,
  "database_connected": true,
  "n8n_enabled": true
}
```

## Workflow'u arayüzde izleme

1. `http://localhost:5678` adresinde workflow'u açın.
2. Workflow yayınlanmış durumda kalsın.
3. Frontend'den bir URL analiz edin.
4. n8n sol menüsünden **Executions** bölümünü açın.
5. Son execution'a tıklayın.
6. Yeşil node'lara tıklayarak her adımın input ve output JSON'unu inceleyin.

Bu ekran sunum sırasında “n8n gerçekten ne yaptı?” sorusunun en iyi görsel cevabıdır.

## Durdurma ve yeniden başlatma

Container'ı durdurmak:

```powershell
cd n8n
docker compose -f docker-compose.yml stop
```

Yeniden başlatmak:

```powershell
docker compose --env-file .env -f docker-compose.yml up -d
```

Logları izlemek:

```powershell
docker compose -f docker-compose.yml logs -f n8n
```

Container'ı kaldırmak:

```powershell
docker compose -f docker-compose.yml down
```

`down` komutu workflow verilerini silmez; `n8n_data` volume'u korunur. Volume'u silen
`down -v` komutunu kullanmayın.

## Sık hatalar

### `ECONNREFUSED ...:8001`

FastAPI çalışmıyordur veya `--host 0.0.0.0` kullanılmamıştır.

### Webhook `404` döndürüyor

Workflow yayınlanmamıştır. n8n arayüzünde workflow'u açıp **Publish** düğmesine basın.

### `401 Geçersiz n8n erişim anahtarı`

`backend/.env` ve `n8n/.env` içindeki `N8N_SHARED_SECRET` değerleri aynı değildir.
Gerçek değerleri Git'e göndermeyin.

### VirusTotal `configured: false`

`backend/.env` içindeki `VIRUSTOTAL_API_KEY` boştur. Anahtar ekledikten sonra FastAPI'yi
yeniden başlatın.

### Analiz uzun sürüyor

WHOIS sunucuları bazen yavaş cevap verir. Sprint 1 workflow'u anlaşılır olması için
adımları sırayla çalıştırır; sonraki sprintte bağımsız adımlar paralelleştirilebilir.
