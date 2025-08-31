import React, { useState } from "react";
import axios from "axios";

const API = (import.meta.env.VITE_API_BASE || "").replace(/\/$/, "");

export default function App() {
  const [out, setOut] = useState("");
  const [phone, setPhone] = useState("");
  const [password, setPassword] = useState("");

  const call = async (fn) => {
    try { await fn(); }
    catch (e) { setOut(String(e?.response?.data?.error || e.message)); }
  };

  return (
    <div style={{ fontFamily: "system-ui", padding: 16, maxWidth: 600, margin: "0 auto" }}>
      <h1>LIBERATION (Frontend)</h1>
      <p>API: <code>{API || "(set VITE_API_BASE)"}</code></p>

      <div style={{ display: "grid", gap: 8 }}>
        <input placeholder="phone" value={phone} onChange={e => setPhone(e.target.value)} />
        <input placeholder="password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={() => call(async () => {
            const { data } = await axios.get(`${API}/health`);
            setOut(JSON.stringify(data, null, 2));
          })}>Health</button>

          <button onClick={() => call(async () => {
            const { data } = await axios.post(`${API}/auth/register`, { phone, password });
            setOut(JSON.stringify(data, null, 2));
          })}>Register</button>

          <button onClick={() => call(async () => {
            const { data } = await axios.post(`${API}/auth/login`, { phone, password });
            localStorage.setItem("at", data.accessToken);
            setOut(JSON.stringify(data, null, 2));
          })}>Login</button>

          <button onClick={() => call(async () => {
            const at = localStorage.getItem("at");
            const { data } = await axios.get(`${API}/auth/me`, {
              headers: { Authorization: `Bearer ${at}` }
            });
            setOut(JSON.stringify(data, null, 2));
          })}>Me</button>
        </div>
      </div>

      <pre style={{ background: "#111", color: "#0f0", padding: 12, marginTop: 16, borderRadius: 8, whiteSpace: "pre-wrap" }}>
        {out}
      </pre>
    </div>
  );
      }
