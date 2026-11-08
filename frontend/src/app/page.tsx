"use client";

import React, { useState } from "react";
import { Search, Loader2, ShieldCheck, ShieldAlert, AlertTriangle, Lock, Globe, Database, Bot } from "lucide-react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await res.json();
      setReport(data);
    } catch (err) {
      alert("Backend not reachable. Ensure FastAPI is running on port 8000.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 px-4 py-12 flex flex-col items-center font-sans">
      {/* Header */}
      <div className="w-full max-w-4xl text-center space-y-3 mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-950 border border-blue-800 text-blue-400 text-xs font-semibold uppercase tracking-wider">
          <ShieldAlert className="w-4 h-4" /> HackMatrix AI + Web3 Security Defense
        </div>
        <h1 className="text-4xl sm:text-5xl font-black tracking-tight text-white">
          PhishLens Defense Engine
        </h1>
        <p className="text-slate-400 max-w-xl mx-auto text-sm sm:text-base">
          Autonomous phishing verification powered by live TLS inspection, domain age heuristics, and transparent threat logging.
        </p>
      </div>

      {/* URL Input Form */}
      <form onSubmit={handleScan} className="w-full max-w-2xl flex gap-2">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Paste URL to inspect (e.g., https://paypal-security-alert.top)"
          className="w-full px-4 py-3 bg-slate-900 border border-slate-800 text-white rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-slate-500 text-sm"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold rounded-xl flex items-center gap-2 transition text-sm"
        >
          {loading ? <Loader2 className="animate-spin w-4 h-4" /> : <Search className="w-4 h-4" />}
          Inspect
        </button>
      </form>

      {/* Report Dashboard */}
      {report && (
        <div className="w-full max-w-4xl mt-10 space-y-6">
          {/* Top Score Banner */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-bold text-white tracking-wide">{report.hostname}</h2>
                {report.status === "SAFE" && (
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4" /> SAFE
                  </span>
                )}
                {report.status === "SUSPICIOUS" && (
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-amber-950 text-amber-400 border border-amber-800 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" /> SUSPICIOUS
                  </span>
                )}
                {report.status === "MALICIOUS" && (
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-950 text-rose-400 border border-rose-800 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4" /> MALICIOUS DETECTED
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1">Page Title: {report.content.title}</p>
            </div>
            <div className="text-right">
              <span className="text-xs uppercase text-slate-500 font-bold tracking-wider">Threat Score</span>
              <div className="text-3xl font-black text-white">{report.score}<span className="text-slate-500 text-lg">/100</span></div>
            </div>
          </div>

          {/* Three Telemetry Columns */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* TLS */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
              <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
                <Lock className="w-4 h-4" /> TLS Trust Chain
              </div>
              <div className="text-xs space-y-1 text-slate-300">
                <p><span className="text-slate-500">Status:</span> {report.tls.valid ? "Valid & Encrypted" : "Broken/Untrusted"}</p>
                <p><span className="text-slate-500">Issuer:</span> {report.tls.issuer}</p>
                <p><span className="text-slate-500">Remaining:</span> {report.tls.days_remaining} days</p>
              </div>
            </div>

            {/* WHOIS */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
              <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
                <Globe className="w-4 h-4" /> Domain Telemetry
              </div>
              <div className="text-xs space-y-1 text-slate-300">
                <p><span className="text-slate-500">Registrar:</span> {report.domain.registrar}</p>
                <p><span className="text-slate-500">Age:</span> {report.domain.age_days} days</p>
                <p><span className="text-slate-500">Flag:</span> {report.domain.is_new ? "Recently Created (<30d)" : "Established"}</p>
              </div>
            </div>

            {/* Web3 */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-2">
              <div className="flex items-center gap-2 text-purple-400 font-semibold text-sm">
                <Database className="w-4 h-4" /> Web3 Immutable Log
              </div>
              <div className="text-xs space-y-1 text-slate-300">
                <p><span className="text-slate-500">Ledger:</span> {report.web3.network}</p>
                <p><span className="text-slate-500">Hash:</span> {report.web3.domain_hash.slice(0, 14)}...</p>
                <p><span className="text-slate-500">Status:</span> Cryptographically Anchored</p>
              </div>
            </div>
          </div>

          {/* Explainable AI Result Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
              <Bot className="w-4 h-4" /> Explainable AI (XAI) Investigation
            </div>
            <p className="text-sm text-slate-200 leading-relaxed">
              {report.ai_report.verdict_summary}
            </p>
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Identified Risk Indicators:</span>
              <ul className="list-disc list-inside text-xs text-rose-300 space-y-1">
                {report.ai_report.key_flags.map((flag: string, idx: number) => (
                  <li key={idx}>{flag}</li>
                ))}
              </ul>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs text-blue-300 font-medium">
              💡 Recommended Action: {report.ai_report.recommended_action}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}