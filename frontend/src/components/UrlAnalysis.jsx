import { useState } from "react";
import axios from "axios";
import RiskGauge from "./RiskGauge";

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8001";

function UrlAnalysis() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeUrl = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await axios.post(`${API_URL}/analyze`, { url });
      setResult(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail ?? "Backend'e bağlanılamadı. Servislerin çalıştığını kontrol edin.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <section className="hero-panel">
        <h2>Şüpheli bağlantıyı kontrol edin</h2>
        <p className="intro">URL; alan adı yaşı, DNS, SSL ve VirusTotal sinyalleriyle analiz edilir.</p>
        <form className="analysis-form" onSubmit={analyzeUrl}>
          <label htmlFor="url">İncelenecek URL</label>
          <div className="input-row">
            <input id="url" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" autoComplete="url" required />
            <button type="submit" disabled={loading}>{loading ? "Analiz ediliyor…" : "Analiz et"}</button>
          </div>
        </form>
        {error && <p className="error-message" role="alert">{error}</p>}
      </section>

      {result && <section className={`result-card result-${result.status}`}>
        <div className="result-summary">
          <div><p className="eyebrow">ANALİZ SONUCU</p><h2>{result.domain}</h2><p className="muted">{result.url}</p></div>
          <RiskGauge risk={result.risk} status={result.status} />
        </div>
        <div className="signal-grid">
          <div><span>SSL</span><strong>{result.ssl_valid ? "Geçerli" : "Geçersiz / bulunamadı"}</strong></div>
          <div><span>Alan adı yaşı</span><strong>{result.domain_age_days == null ? "Bilinmiyor" : `${result.domain_age_days} gün`}</strong></div>
          <div><span>Durum</span><strong>{result.status}</strong></div>
        </div>
        <h3>Risk nedenleri</h3>
        <ul className="reason-list">{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
        {(result.ai_explanation || result.explanation) && <aside className="ai-explanation"><p className="eyebrow">AI AÇIKLAMASI</p><p>{result.ai_explanation ?? result.explanation}</p></aside>}
      </section>}
    </>
  );
}

export default UrlAnalysis;
