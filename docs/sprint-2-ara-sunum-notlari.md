# Sprint 2 Ara Sunum Notları

## Demo akışı

1. **URL Analizi:** Bir URL girilir; risk göstergesi 0–100 değerini ve risk seviyesini renk koduyla gösterir. Sonuçta DNS, SSL ve alan adı yaşı sinyalleri listelenir.
2. **AI açıklaması:** Backend sonucu `ai_explanation` (veya `explanation`) alanını döndürdüğünde kullanıcıya sade dilde gösterilir.
3. **SMS/E-posta Analizi:** Şüpheli metin `/analyze-text` uç noktasına gönderilir; risk, nedenler ve AI özeti ekranda görünür.
4. **Geçmiş Analizler:** `/analyses` kaydı alınır; alan adına göre filtreleme ve en yeni/en yüksek risk sıralaması gösterilir.
5. **Otomatik bildirim:** Risk 80'den büyükse URL veya SMS/e-posta n8n workflow'u Telegram bildirim node'unu çağır. Telegram hatası analiz sonucunu kesmez.

## Entegrasyon sözleşmeleri

- `POST /analyze` mevcut URL analiz sonucunu döndürür. AI metni için isteğe bağlı `ai_explanation` alanı kullanılır.
- `POST /analyze-text` istek gövdesi: `{ "text": "..." }`. Yanıt en az `status`, `risk`, `reasons` ve `ai_explanation` alanlarını içermelidir.
- `GET /analyses` her kayıt için `id`, `url`, `domain`, `score` (veya `risk`), `status`, `created_at` alanlarını döndürmelidir.

## Bilinen bağımlılık

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
