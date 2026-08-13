import { useState } from "react";
import axios from "axios";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8001";

function App() {
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
      setError(
        requestError.response?.data?.detail ??
          "Backend'e bağlanılamadı. Servislerin çalıştığını kontrol edin.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="app-shell">
      <section className="hero-panel">
        <p className="eyebrow">PHISHING RİSK ANALİZİ</p>
        <h1>Şüpheli bağlantıyı kontrol edin</h1>
        <p className="intro">
          URL; alan adı yaşı, DNS, SSL ve VirusTotal sinyalleriyle analiz edilir.
        </p>

        <form className="url-form" onSubmit={analyzeUrl}>
          <label htmlFor="url">İncelenecek URL</label>
          <div className="input-row">
            <input
              id="url"
              type="text"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com"
              autoComplete="url"
              required
            />
            <button type="submit" disabled={loading}>
              {loading ? "Analiz ediliyor…" : "Analiz et"}
            </button>
          </div>
        </form>

        {error && <p className="error-message">{error}</p>}
      </section>

      {result && (
        <section className={`result-card result-${result.status}`}>
          <div className="result-header">
            <div>
              <p className="eyebrow">ANALİZ SONUCU</p>
              <h2>{result.domain}</h2>
            </div>
            <div className="score" aria-label={`Risk skoru ${result.risk}`}>
              <strong>{result.risk}</strong>
              <span>/100</span>
            </div>
          </div>

          <div className="risk-track" aria-hidden="true">
            <span style={{ width: `${result.risk}%` }} />
          </div>

          <dl className="signal-grid">
            <div>
              <dt>Durum</dt>
              <dd>{result.status}</dd>
            </div>
            <div>
              <dt>SSL</dt>
              <dd>{result.ssl_valid ? "Geçerli" : "Geçersiz / bulunamadı"}</dd>
            </div>
            <div>
              <dt>Alan adı yaşı</dt>
              <dd>
                {result.domain_age_days == null
                  ? "Bilinmiyor"
                  : `${result.domain_age_days} gün`}
              </dd>
            </div>
          </dl>

          <h3>Risk nedenleri</h3>
          <ul className="reason-list">
            {result.reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}

export default App;
