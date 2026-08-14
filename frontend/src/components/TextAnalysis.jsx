import { useState } from "react";
import axios from "axios";
import RiskGauge from "./RiskGauge";

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8001";

function TextAnalysis() {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeText = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await axios.post(`${API_URL}/analyze-text`, { text });
      setResult(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail ?? "Metin analizi şu anda tamamlanamadı.");
    } finally {
      setLoading(false);
    }
  };

  return <section className="hero-panel text-analysis">
    <p className="eyebrow">METİN ANALİZİ</p>
    <h2>SMS veya e-postayı inceleyin</h2>
    <p className="intro">Mesajdaki aciliyet, korku ve ödül vaadi gibi phishing sinyalleri analiz edilir.</p>
    <form className="analysis-form" onSubmit={analyzeText}>
      <label htmlFor="message-text">SMS veya e-posta metni</label>
      <textarea id="message-text" value={text} onChange={(event) => setText(event.target.value)} placeholder="Size gelen şüpheli mesajı buraya yapıştırın…" minLength="3" required />
      <button type="submit" disabled={loading}>{loading ? "İnceleniyor…" : "Metni analiz et"}</button>
    </form>
    {error && <p className="error-message" role="alert">{error}</p>}
    {result && <div className={`text-result result-${result.status ?? "suspicious"}`}>
      {result.risk != null && <RiskGauge risk={result.risk} status={result.status ?? "suspicious"} />}
      <div><h3>{result.status === "dangerous" ? "Yüksek riskli mesaj" : "Metin analizi sonucu"}</h3><p>{result.ai_explanation ?? result.explanation ?? result.summary}</p>
        {result.reasons?.length > 0 && <ul className="reason-list">{result.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
      </div>
    </div>}
  </section>;
}

export default TextAnalysis;
