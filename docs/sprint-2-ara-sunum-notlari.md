# Sprint 2 Demo ve Ara Sunum Notları

## Sprint hedefi

1. **URL Analizi:** Bir URL girilir; risk göstergesi 0–100 değerini ve risk seviyesini renk koduyla gösterir. Sonuçta DNS, SSL ve alan adı yaşı sinyalleri listelenir.
2. **AI açıklaması:** Backend sonucu `ai_explanation` (veya `explanation`) alanını döndürdüğünde kullanıcıya sade dilde gösterilir.
3. **SMS/E-posta Analizi:** Şüpheli metin `/analyze-text` uç noktasına gönderilir; risk, nedenler ve AI özeti ekranda görünür.
4. **Geçmiş Analizler:** `/analyses` kaydı alınır; alan adına göre filtreleme ve en yeni/en yüksek risk sıralaması gösterilir.
5. **Otomatik bildirim:** Risk 80'den büyükse URL veya SMS/e-posta n8n workflow'u Telegram bildirim node'unu çağır. Telegram hatası analiz sonucunu kesmez.
Kullanıcının yapıştırdığı SMS veya e-posta metnindeki phishing sinyallerini
değerlendirmek, bağlantıları VirusTotal ile zenginleştirmek ve sonucu anlaşılır
Türkçe ile sunmak.

## 5 dakikalık demo akışı

1. **Hazırlık:** `GET /health` ile backend'in ayakta olduğunu gösterin. n8n editörde
   Sprint 2 workflow'unun yayımlı olduğunu ve `N8N_TEXT_ENABLED=true` ayarını doğrulayın.
2. **Normal metin:** “Toplantımız yarın 10.00'da.” girin. Beklenti: düşük risk,
   belirgin phishing sinyali yok ve güvenliğin garanti edilmediğini söyleyen açıklama.
3. **Phishing örneği:** “Bankanız: Hesabınız kapatılacak. Hemen şifrenizi
   https://example.com adresinden doğrulayın.” girin. Beklenti: aciliyet, korku,
   kimlik bilgisi talebi, kurum taklidi ve bağlantı sinyalleri; yüksek risk sonucu.
4. **Otomasyon kanıtı:** n8n > Executions ekranında sırasıyla Validate Request,
   VirusTotal URL Checks, Normalize URL Checks, Text Risk and AI ve Finalize Response
   düğümlerinin girdilerini/çıktılarını gösterin.
5. **Dayanıklılık:** `OPENAI_API_KEY` boşken veya kota yokken aynı örneği çalıştırın.
   Risk sonucu ve Türkçe yedek açıklama döner; `ai_used: false` ve `ai_error` nedenini
   açıklar. Böylece harici AI servisi analizi durdurmaz.

## Gerçek uçtan uca doğrulama

Servisler açıkken aşağıdaki koşum frontend'in kullandığı FastAPI uç noktasına gerçek
HTTP isteği gönderir. n8n açıksa çağrı gerçek webhook zincirinden geçer; mock yoktur.

```powershell
cd backend
$env:SPRINT2_E2E_BASE_URL="http://127.0.0.1:8001"
.\venv\Scripts\python.exe -m pytest -m e2e -q
```

Başarı ölçütü: sağlık yanıtında `n8n_text_enabled: true`; ardından HTTP 200, geçerli
`status`, 0–100 arası `risk`, boş olmayan `reasons` ve `ai_explanation`, ayrıca
`workflow_warnings` alanı.

## Entegrasyon sözleşmeleri

- `POST /analyze-text`: gövde `{ "text": "..." }`; yanıt `status`, `risk`,
  `reasons`, `signals`, `ai_explanation`, `ai_used`, `ai_error` ve
  `workflow_warnings` içerir.
- `POST /internal/text-analysis`: sadece `X-N8N-Secret` ile çağrılır; n8n'nin URL
  kontrol sonuçlarını alır ve nihai risk hesaplamasını yapar.
- `POST /analyze`: URL analizini, `GET /analyses` ise kayıt geçmişini sunar.

## OpenAI kota notu

SMS/e-posta uç noktası ve AI açıklaması backend/n8n entegrasyonuna bağlıdır. Frontend istek, yüklenme, hata ve sonuç durumlarını hazır olarak yönetir.

OpenAI ve Telegram gerçek servis demoları için ilgili API anahtarları/kota gerekir.
Anahtarlar eksik olduğunda teknik analiz ve risk skoru çalışmaya devam eder.

## Sprint 2 kapanış kontrol listesi

- [x] Gerçek WHOIS/DNS/SSL/VirusTotal sinyalleri ve Supabase kaydı
- [x] URL n8n workflow'unda AI açıklaması
- [x] Risk gauge ve AI açıklaması frontend gösterimi
- [x] SMS/e-posta backend endpoint'i ve deterministik metin risk motoru
- [x] SMS/e-posta n8n workflow'u, VirusTotal URL kontrolleri ve hata/timeout yönetimi
- [x] SMS/e-posta frontend sekmesi, loading/error/sonuç durumları
- [x] URL ve SMS/e-posta workflow'larında risk > 80 Telegram node'u
- [x] Geçmiş analizler tablosu, filtreleme ve sıralama
- [x] Backend testleri, frontend lint/build ve gerçek n8n webhook demoları

Gerçek AI ve Telegram bildirim demosu için OpenAI API kotası ile Telegram bot
bilgilerinin etkin olması gerekir. Bunlar kod eksiği değil, ortam yapılandırmasıdır.
`insufficient_quota` ChatGPT aboneliğiyle değil, OpenAI API projesindeki kredi veya
faturalandırmayla ilgilidir. Çözüm: OpenAI Platform'da proje billing/kredi ayarını
etkinleştirmek, bütçe limitini kontrol etmek ve backend'i yeniden başlatmaktır. Kota
çözülene kadar sistem yedek analizle çalışmaya devam eder; demo kesilmez.

## Sunumda vurgulanacak sınırlar

- VirusTotal sonucu tek başına kesin hüküm değildir; kullanıcıdan tıklamaması ve
  doğrulanmış kanaldan kontrol etmesi istenir.
- n8n orkestrasyonu yapar; risk puanı FastAPI backend'de hesaplanır.
- API anahtarları yalnızca `.env` dosyalarında tutulur ve ekrana/Git'e yazdırılmaz.
