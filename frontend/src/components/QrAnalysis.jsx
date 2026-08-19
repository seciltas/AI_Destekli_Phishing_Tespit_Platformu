import { useEffect, useState } from "react";
import axios from "axios";
import RiskGauge from "./RiskGauge";

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8001";
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const ALLOWED_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

function QrAnalysis() {
  const [file, setFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => () => previewUrl && URL.revokeObjectURL(previewUrl), [previewUrl]);

  const chooseFile = (event) => {
    const selected = event.target.files?.[0] ?? null;
    setError("");
    setResult(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl("");
    setFile(null);

    if (!selected) return;
    if (!ALLOWED_TYPES.has(selected.type)) {
      setError("Yalnızca PNG, JPEG veya WebP görsel yükleyebilirsiniz.");
      return;
    }
    if (selected.size > MAX_FILE_BYTES) {
      setError("QR görseli en fazla 5 MB olabilir.");
      return;
    }
    setFile(selected);
    setPreviewUrl(URL.createObjectURL(selected));
  };

  const analyzeQr = async (event) => {
    event.preventDefault();
    if (!file) return;
    setLoading(true);
    setError("");
    setResult(null);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const response = await axios.post(`${API_URL}/analyze-qr`, formData);
      setResult(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail ?? "QR analizi şu anda tamamlanamadı.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <section className="hero-panel">
        <p className="eyebrow">SPRINT 3 · QR MODÜLÜ</p>
        <h2>QR kod içindeki bağlantıyı kontrol edin</h2>
        <p className="intro">Görsel cihazınızda önizlenir; QR içindeki URL çıkarılarak mevcut güvenlik motorunda analiz edilir.</p>
        <form className="analysis-form qr-form" onSubmit={analyzeQr}>
          <label htmlFor="qr-file">QR kod görseli</label>
          <input id="qr-file" type="file" accept="image/png,image/jpeg,image/webp" onChange={chooseFile} />
          {previewUrl && <div className="qr-preview"><img src={previewUrl} alt="Yüklenecek QR kod önizlemesi" /><p>{file.name}</p></div>}
          <button type="submit" disabled={!file || loading}>{loading ? "QR analiz ediliyor…" : "QR kodu analiz et"}</button>
        </form>
        {error && <p className="error-message" role="alert">{error}</p>}
      </section>

      {result && <section className={`result-card result-${result.status}`}>
        <div className="result-summary">
          <div><p className="eyebrow">QR ANALİZ SONUCU</p><h2>{result.domain}</h2><p className="muted">QR içinden çıkarılan URL: {result.url}</p></div>
          <RiskGauge risk={result.risk} status={result.status} />
        </div>
        <div className="signal-grid">
          <div><span>SSL</span><strong>{result.ssl_valid ? "Geçerli" : "Geçersiz / bulunamadı"}</strong></div>
          <div><span>Alan adı yaşı</span><strong>{result.domain_age_days == null ? "Bilinmiyor" : `${result.domain_age_days} gün`}</strong></div>
          <div><span>Durum</span><strong>{result.status}</strong></div>
        </div>
        <h3>Risk nedenleri</h3>
        <ul className="reason-list">{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
        {result.ai_explanation && <aside className="ai-explanation"><p className="eyebrow">AI AÇIKLAMASI</p><p>{result.ai_explanation}</p></aside>}
      </section>}
    </>
  );
}

export default QrAnalysis;
