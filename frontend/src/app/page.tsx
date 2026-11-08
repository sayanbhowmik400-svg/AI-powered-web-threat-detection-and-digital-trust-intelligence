"use client";

import React, { useState } from "react";
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Lock, 
  Globe, 
  Database,
  Bot, 
  Search, 
  Loader2, 
  Lightbulb 
} from "lucide-react";

interface ScanResponse {
  hostname: string;
  score: number;
  status: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  tls: {
    valid: boolean;
    issuer: string;
    days_remaining: number;
  };
  domain: {
    registrar: string;
    age_days: number | null;
    is_new: boolean;
  };
  content: {
    title: string;
    has_password_field: boolean;
    has_payment_keywords: boolean;
  };
  ai_report: {
    verdict_summary: string;
    key_flags: string[];
    recommended_action: string;
  };
  web3: {
    network: string;
    domain_hash: string;
    verified_ledger: boolean;
  };
}

export default function PhishLensDashboard() {
  const [url, setUrl] = useState("https://app.remix.live");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ScanResponse | null>({
    hostname: "app.remix.live",
    score: 40,
    status: "SUSPICIOUS",
    tls: { valid: true, issuer: "Let's Encrypt", days_remaining: 70 },
    domain: { registrar: "Privacy Redacted", age_days: 2, is_new: true },
    content: { title: "Remix IDE - Smart Contract Development", has_password_field: false, has_payment_keywords: false },
    ai_report: {
      verdict_summary: "Automated heuristics evaluated risk score at 40/100 based on TLS and domain freshness.",
      key_flags: [
        "TLS Certificate: Trusted",
        "Domain Age: 2 days",
        "Form Fields: Standard page"
      ],
      recommended_action: "Avoid entering credentials or sensitive personal information on this site."
    },
    web3: {
      network: "Polygon Amoy Testnet (Chain ID 80002)",
      domain_hash: "0x129d5f8a8a42e7b1a209930f",
      verified_ledger: true
    }
  });

  const handleScan = async (targetUrl?: string) => {
    const scanTarget = targetUrl || url;
    if (!scanTarget.trim()) return;

    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanTarget.trim() }),
      });
      if (!res.ok) throw new Error("Backend request failed");
      const data: ScanResponse = await res.json();
      setReport(data);
    } catch {
      alert("Backend connection failed! Ensure FastAPI server is running on port 8000.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07090E] text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200 p-4 sm:p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        
        {/* Header / Brand */}
        <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-slate-800/80 pb-5 gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-[1px] flex items-center justify-center shadow-lg shadow-cyan-500/10">
              <div className="w-full h-full bg-[#0D111A] rounded-[11px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-xl tracking-wider text-white">PHISH<span className="text-cyan-400">LENS</span></span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold">Live v2.4</span>
              </div>
              <p className="text-xs text-slate-400 font-mono">HackMatrix AI + Web3 Security Defense</p>
            </div>
          </div>
          <p className="text-xs text-slate-500 font-mono text-left sm:text-right max-w-xs">
            Autonomous threat verification powered by live TLS inspection, domain age heuristics, and transparent threat logging.
          </p>
        </header>

        {/* Search Input Section */}
        <section className="space-y-3">
          <form 
            onSubmit={(e) => { e.preventDefault(); handleScan(); }} 
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://app.remix.live"
              className="flex-1 px-4 py-3 bg-[#0D111A] border border-slate-800 focus:border-cyan-500 rounded-xl text-sm font-mono text-white outline-none placeholder:text-slate-600 transition shadow-inner"
            />
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-bold text-xs uppercase tracking-wider rounded-xl flex items-center gap-2 transition disabled:opacity-50 shadow-md shadow-cyan-500/20 active:scale-95"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              <span>Inspect</span>
            </button>
          </form>

          {/* Quick Demo Pre-fills */}
          <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
            <span>Quick test:</span>
            <button 
              type="button" 
              onClick={() => { setUrl("https://app.remix.live"); handleScan("https://app.remix.live"); }} 
              className="underline hover:text-cyan-400 transition"
            >
              app.remix.live
            </button>
            <span>•</span>
            <button 
              type="button" 
              onClick={() => { setUrl("https://paypa1-security-auth.top"); handleScan("https://paypa1-security-auth.top"); }} 
              className="underline hover:text-rose-400 transition"
            >
              paypa1-security-auth.top
            </button>
            <span>•</span>
            <button 
              type="button" 
              onClick={() => { setUrl("https://github.com"); handleScan("https://github.com"); }} 
              className="underline hover:text-emerald-400 transition"
            >
              github.com
            </button>
          </div>
        </section>

        {/* RESULTS REPORT DASHBOARD */}
        {report && (
          <div className="space-y-6 pt-2">
            
            {/* Top Host & Verdict Banner */}
            <div className="bg-[#0D111A] border border-slate-800 rounded-2xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-2xl font-bold font-mono text-white tracking-wide">{report.hostname}</h2>
                  
                  {report.status === "SAFE" && (
                    <span className="px-3 py-1 rounded-full text-xs font-bold font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" /> SAFE
                    </span>
                  )}
                  {report.status === "SUSPICIOUS" && (
                    <span className="px-3 py-1 rounded-full text-xs font-bold font-mono bg-amber-950/80 text-amber-400 border border-amber-800 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" /> SUSPICIOUS
                    </span>
                  )}
                  {report.status === "MALICIOUS" && (
                    <span className="px-3 py-1 rounded-full text-xs font-bold font-mono bg-rose-950/80 text-rose-400 border border-rose-800 flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4" /> MALICIOUS
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-2 font-mono">
                  Page Title: <span className="text-slate-200">{report.content.title || "Unknown"}</span>
                </p>
              </div>

              {/* Threat Score */}
              <div className="text-left sm:text-right bg-[#131926] px-5 py-3 rounded-xl border border-slate-800">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Threat Score</span>
                <div className="text-3xl font-black font-mono text-white">
                  {report.score}<span className="text-slate-500 text-sm">/100</span>
                </div>
              </div>
            </div>

            {/* Exactly 3 Telemetry Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              
              {/* Card 1: TLS Trust Chain */}
              <div className="bg-[#131926] border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between text-xs font-mono font-bold text-cyan-400">
                  <span className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-cyan-400" /> TLS Trust Chain
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${report.tls.valid ? "bg-emerald-950 text-emerald-400 border-emerald-800" : "bg-rose-950 text-rose-400 border-rose-800"}`}>
                    {report.tls.valid ? "VALID" : "INVALID"}
                  </span>
                </div>
                
                <div className="text-xs font-mono space-y-2 text-slate-300 pt-1">
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Status:</span>
                    <span className="text-white font-medium">{report.tls.valid ? "Valid & Encrypted" : "Invalid / Untrusted"}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Issuer:</span>
                    <span className="truncate max-w-[130px] text-white">{report.tls.issuer}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Remaining:</span>
                    <span className="text-slate-200">{report.tls.days_remaining} days</span>
                  </div>
                </div>
              </div>

              {/* Card 2: Domain Telemetry */}
              <div className="bg-[#131926] border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between text-xs font-mono font-bold text-indigo-400">
                  <span className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-indigo-400" /> Domain Telemetry
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${report.domain.is_new ? "bg-rose-950 text-rose-400 border-rose-800" : "bg-emerald-950 text-emerald-400 border-emerald-800"}`}>
                    {report.domain.is_new ? "FRESH (<30d)" : "ESTABLISHED"}
                  </span>
                </div>
                
                <div className="text-xs font-mono space-y-2 text-slate-300 pt-1">
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Registrar:</span>
                    <span className="truncate max-w-[130px] text-white">{report.domain.registrar || "Privacy Redacted"}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Age:</span>
                    <span className="text-white font-medium">{report.domain.age_days !== null ? `${report.domain.age_days} days` : "Unknown"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Flag:</span>
                    <span className={report.domain.is_new ? "text-amber-400 font-medium" : "text-emerald-400 font-medium"}>
                      {report.domain.is_new ? "Recently Created (<30d)" : "Established Domain"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Card 3: Web3 Immutable Log */}
              <div className="bg-[#131926] border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between text-xs font-mono font-bold text-purple-400">
                  <span className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-purple-400" /> Web3 Immutable Log
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded border bg-purple-950 text-purple-300 border-purple-800 font-mono">
                    ON-CHAIN
                  </span>
                </div>
                
                <div className="text-xs font-mono space-y-2 text-slate-300 pt-1">
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Ledger:</span>
                    <span className="truncate max-w-[130px] text-purple-300">{report.web3.network}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-500">Hash:</span>
                    <span className="truncate max-w-[130px] text-cyan-400 font-mono">{report.web3.domain_hash}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Status:</span>
                    <span className="text-emerald-400 font-medium">Cryptographically Anchored</span>
                  </div>
                </div>
              </div>

            </div>

            {/* Explainable AI (XAI) Investigation Box */}
            <div className="bg-[#0D111A] border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm font-mono border-b border-slate-800/80 pb-3">
                <Bot className="w-5 h-5 text-emerald-400" />
                <span>Explainable AI (XAI) Investigation</span>
              </div>
              
              <p className="text-sm text-slate-200 leading-relaxed font-sans">
                {report.ai_report.verdict_summary}
              </p>

              <div className="space-y-2 pt-1">
                <span className="text-xs uppercase font-mono text-slate-400 font-bold tracking-wider">
                  Identified Risk Indicators:
                </span>
                <ul className="space-y-1.5 text-xs font-mono text-slate-300">
                  {report.ai_report.key_flags.map((flag, idx) => (
                    <li key={idx} className="flex items-center gap-2.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                      <span>{flag}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="p-4 bg-[#131926] border border-slate-800 rounded-xl text-xs font-sans text-amber-200 flex items-start gap-3 mt-2">
                <Lightbulb className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold uppercase font-mono text-amber-400 mr-1.5">Recommended Action:</span>
                  {report.ai_report.recommended_action}
                </div>
              </div>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}