# Sprint 2 Ara Sunum Notları

## Demo akışı

1. **URL Analizi:** Bir URL girilir; risk göstergesi 0–100 değerini ve risk seviyesini renk koduyla gösterir. Sonuçta DNS, SSL ve alan adı yaşı sinyalleri listelenir.
2. **AI açıklaması:** Backend sonucu `ai_explanation` (veya `explanation`) alanını döndürdüğünde kullanıcıya sade dilde gösterilir.
3. **SMS/E-posta Analizi:** Şüpheli metin `/analyze-text` uç noktasına gönderilir; risk, nedenler ve AI özeti ekranda görünür.
4. **Geçmiş Analizler:** `/analyses` kaydı alınır; alan adına göre filtreleme ve en yeni/en yüksek risk sıralaması gösterilir.

## Entegrasyon sözleşmeleri

- `POST /analyze` mevcut URL analiz sonucunu döndürür. AI metni için isteğe bağlı `ai_explanation` alanı kullanılır.
- `POST /analyze-text` istek gövdesi: `{ "text": "..." }`. Yanıt en az `status`, `risk`, `reasons` ve `ai_explanation` alanlarını içermelidir.
- `GET /analyses` her kayıt için `id`, `url`, `domain`, `score` (veya `risk`), `status`, `created_at` alanlarını döndürmelidir.

## Bilinen bağımlılık

SMS/e-posta uç noktası ve AI açıklaması backend/n8n entegrasyonuna bağlıdır. Frontend istek, yüklenme, hata ve sonuç durumlarını hazır olarak yönetir.
