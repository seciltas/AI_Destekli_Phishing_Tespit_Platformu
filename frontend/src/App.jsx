import { useState } from "react";
import "./App.css";
import AnalysisHistory from "./components/AnalysisHistory";
import TextAnalysis from "./components/TextAnalysis";
import UrlAnalysis from "./components/UrlAnalysis";
import QrAnalysis from "./components/QrAnalysis";

const routes = {
  "/": "url",
  "/metin-analizi": "text",
  "/qr-analizi": "qr",
  "/gecmis-analizler": "history",
};

function App() {
  const [activeView, setActiveView] = useState(routes[window.location.pathname] ?? "url");

  const navigate = (view) => {
    const path = Object.entries(routes).find(([, routeView]) => routeView === view)?.[0] ?? "/";
    window.history.pushState({}, "", path);
    setActiveView(view);
  };

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">PHISHING RİSK ANALİZİ</p>
          <h1>Güvenlik merkezi</h1>
        </div>
        <nav aria-label="Ana navigasyon" className="main-nav">
          <button className={activeView === "url" ? "active" : ""} onClick={() => navigate("url")}>URL Analizi</button>
          <button className={activeView === "text" ? "active" : ""} onClick={() => navigate("text")}>SMS/E-posta Analizi</button>
          <button className={activeView === "qr" ? "active" : ""} onClick={() => navigate("qr")}>QR Analizi</button>
          <button className={activeView === "history" ? "active" : ""} onClick={() => navigate("history")}>Geçmiş Analizler</button>
        </nav>
      </header>

      {activeView === "url" && <UrlAnalysis />}
      {activeView === "text" && <TextAnalysis />}
      {activeView === "qr" && <QrAnalysis />}
      {activeView === "history" && <AnalysisHistory />}
    </main>
  );
}

export default App;
