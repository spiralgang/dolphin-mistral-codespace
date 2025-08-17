import React, { useState } from "react";

export default function NetworkPanel() {
  const [target, setTarget] = useState("");
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);

  const handleNmap = async () => {
    setLoading(true);
    setResult("Running Nmap scan...");
    const res = await fetch("/api/nmap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();
    setResult(data.result);
    setLoading(false);
  };

  const handleSSL = async () => {
    setLoading(true);
    setResult("Checking SSL...");
    const res = await fetch("/api/ssl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    setResult(data.result);
    setLoading(false);
  };

  const handleQuantum = async () => {
    setLoading(true);
    setResult("Checking quantum readiness...");
    const res = await fetch("/api/quantum", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    setResult(data.result);
    setLoading(false);
  };

  return (
    <div className="bg-white p-4 rounded shadow my-3">
      <h2 className="font-bold text-lg mb-2">Network Monitor</h2>
      <div className="flex flex-col gap-2">
        <input className="border p-1" placeholder="IP or domain for Nmap" value={target} onChange={e => setTarget(e.target.value)} />
        <button className="bg-blue-600 text-white px-2 py-1 rounded" onClick={handleNmap} disabled={loading}>Run Nmap Scan</button>
        <input className="border p-1" placeholder="Domain for SSL/Quantum" value={domain} onChange={e => setDomain(e.target.value)} />
        <button className="bg-green-600 text-white px-2 py-1 rounded" onClick={handleSSL} disabled={loading}>Check SSL Certificate</button>
        <button className="bg-purple-600 text-white px-2 py-1 rounded" onClick={handleQuantum} disabled={loading}>Quantum Readiness Check</button>
        <pre className="bg-gray-100 p-2 mt-2 rounded text-xs whitespace-pre-wrap">{result}</pre>
      </div>
    </div>
  );
}