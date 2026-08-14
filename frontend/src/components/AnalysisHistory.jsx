import { useEffect, useMemo, useState } from "react";
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8001";

function AnalysisHistory() {
  const [analyses, setAnalyses] = useState([]);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState("newest");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    axios.get(`${API_URL}/analyses`).then((response) => setAnalyses(response.data)).catch((requestError) => setError(requestError.response?.data?.detail ?? "Analiz geçmişi alınamadı.")).finally(() => setLoading(false));
  }, []);

  const visibleAnalyses = useMemo(() => analyses.filter((item) => `${item.domain} ${item.url}`.toLowerCase().includes(filter.toLowerCase())).sort((first, second) => {
    if (sort === "risk") return (second.score ?? second.risk ?? 0) - (first.score ?? first.risk ?? 0);
    return new Date(second.created_at ?? 0) - new Date(first.created_at ?? 0);
  }), [analyses, filter, sort]);

  return <section className="history-panel">
    <p className="eyebrow">ANALİZ KAYITLARI</p><h2>Geçmiş analizler</h2>
    <div className="history-controls"><input aria-label="Alan adına göre filtrele" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Alan adına göre filtrele" /><select aria-label="Sıralama" value={sort} onChange={(event) => setSort(event.target.value)}><option value="newest">En yeni</option><option value="risk">En yüksek risk</option></select></div>
    {loading && <p>Geçmiş yükleniyor…</p>}{error && <p className="error-message" role="alert">{error}</p>}
    {!loading && !error && <div className="table-wrap"><table><thead><tr><th>Alan adı</th><th>Risk</th><th>Durum</th><th>Tarih</th></tr></thead><tbody>{visibleAnalyses.map((item) => <tr key={item.id ?? `${item.domain}-${item.created_at}`}><td><strong>{item.domain}</strong><small>{item.url}</small></td><td>{item.score ?? item.risk ?? "—"}</td><td><span className={`status status-${item.status}`}>{item.status}</span></td><td>{item.created_at ? new Date(item.created_at).toLocaleString("tr-TR") : "—"}</td></tr>)}</tbody></table>{visibleAnalyses.length === 0 && <p className="empty-state">Bu filtreyle eşleşen analiz bulunamadı.</p>}</div>}
  </section>;
}

export default AnalysisHistory;
