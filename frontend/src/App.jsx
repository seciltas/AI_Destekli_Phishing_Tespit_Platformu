import { useState } from "react";
import axios from "axios";

function App() {
  const [result, setResult] = useState(null);

  const analyzeUrl = async () => {
    try {
      const response = await axios.get(
        "http://127.0.0.1:8001/analyze"
      );

      setResult(response.data);
    } catch (error) {
      console.error(error);
      alert("Backend'e bağlanılamadı!");
    }
  };

  return (
    <div style={{ padding: "40px" }}>
      <h1>AI Destekli Phishing Tespit Platformu</h1>

      <button onClick={analyzeUrl}>
        Analiz Yap
      </button>

      {result && (
        <div style={{ marginTop: "20px" }}>
          <h3>Sonuç</h3>
          <p>Risk Skoru: {result.risk}</p>
          <p>Durum: {result.status}</p>
        </div>
      )}
    </div>
  );
}

export default App;