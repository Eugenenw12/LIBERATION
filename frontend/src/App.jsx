import React, { useEffect, useState } from "react";
import axios from "axios";

const API_BASE = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");

export default function App() {
  const [status, setStatus] = useState("Checking backend...");

  useEffect(() => {
    if (!API_BASE) {
      setStatus("VITE_API_BASE is not set.");
      return;
    }
    axios
      .get(`${API_BASE}/health`)
      .then((res) => setStatus(`Backend says: ${res.data?.status || "ok"}`))
      .catch(() => setStatus(`Could not reach ${API_BASE}/health`));
  }, []);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: 24 }}>
      <h1>Liberation</h1>
      <p>{status}</p>
    </div>
  );
                 }
