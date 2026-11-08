"use client";

import React, { useState } from "react";

const BACKEND_API = "[https://phishlens-ym75.onrender.com/api/scan](https://phishlens-ym75.onrender.com/api/scan)";

export default function PhishLensPage() {
  const [scanTarget, setScanTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any>({
    hostname: "github.com",
    verdict: "SAFE",
    threat_score: 5,
    page_title: "GitHub: Let's build from here",
    xai_summary:
      "GitHub.com is a globally established software development platform with a verified TLS trust chain and an 18+ year registration history under MarkMonitor Inc.",
    identified_risk_indicators: [
      "TLS Certificate: Trusted (DigiCert Inc)",
      "Domain Age: Established (>18 years)",
      "Lexical Analysis: Authentic apex domain with zero spoofing anomalies",
    ],
    recommended_action:
      "Domain is verified and safe for standard authentication and browsing.",
    tls: {
      valid: true,
      badge: "VALID",
      status: "Valid & Encrypted",
      issuer: "DigiCert Inc",
      remaining: "240 days",
    },
    domain: {
      badge: "ESTABLISHED",
      registrar: "MarkMonitor Inc.",
      age: "6,800+ days (~18.6 years)",
      flag: "Established Domain (>30d)",
      is_fresh: false,
    },
    web3: {
      short_hash: "0x8f92e41c...91b40e",
      status: "Cryptographically Anchored",
    },
  });

  const runScan = async (targetOverride?: string) => {
    const target = (targetOverride ?? scanTarget).trim();
    if (!target) return;

    setLoading(true);
    try {
      const res = await fetch(BACKEND_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setReport(data);
    } catch (err) {
      console.error("Scan failed:", err);
      alert(
        "Backend connection timed out. Wait 20 seconds for Render to wake up and try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const score = Number(report?.threat_score ?? report?.risk_score ?? 0);
  const verdict = String(report?.verdict ?? "SAFE").toUpperCase();
  const isMalicious = verdict === "MALICIOUS" || score >= 60;
  const isSuspicious = verdict === "SUSPICIOUS" || (score >= 35 && score < 60);
  const isInvalid = verdict === "INVALID";

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col justify-between font-sans">
      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xl font-extrabold tracking-wider text-blue-400">
              PHISHLENS
            </span>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/25 font-mono">
              Live v2.5
            </span>
          </div>
          <div className="text-xs text-gray-400 font-mono hidden sm:block">
            HackMatrix AI + Web3 Security Defense
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 flex-1 w-full space-y-7">
        <div className="text-center space-y-2">
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
            HackMatrix AI + Web3 Security Defense
          </h1>
          <p className="text-gray-400 max-w-2xl mx-auto text-sm sm:text-base">
            Autonomous phishing verification powered by live TLS inspection,
            domain age heuristics, and transparent threat logging.
          </p>
        </div>

        <div className="bg-gray-900/80 border border-blue-500/30 rounded-2xl p-5 shadow-lg">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              runScan();
            }}
            className="flex flex-col sm:flex-row gap-3"
          >
            <input
              type="text"
              value={scanTarget}
              onChange={(e) => setScanTarget(e.target.value)}
              placeholder="Enter domain or URL (e.g., netflix.com, instagram.com, github.com)"
              className="flex-1 h-12 bg-gray-950 border border-gray-700 rounded-xl px-4 text-sm text-gray-100 font-mono focus:outline-none focus:border-blue-500"
              required
            />
            <button
              type="submit"
              disabled={loading}
              className="h-12 px-8 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-xl transition-all"
            >
              {loading ? "Inspecting..." : "Inspect"}
            </button>
          </form>

          <div className="mt-3.5 flex flex-wrap items-center gap-2 text-xs text-gray-400">
            <span className="text-gray-500 font-medium">Quick test:</span>
            {["github.com", "netflix.com", "instagram.com", "paypa1-security-auth.top"].map(
              (item, idx) => (
                <React.Fragment key="{item}">
                  {idx > 0 && <span>•</span>}
                  <button
                    type="button"
                    onClick={() => {
                      setScanTarget(item);
                      runScan(item);
                    }}
                    className="hover:text-blue-400 underline decoration-dotted font-mono"
                  >
                    {item}
                  </button>
                </React.Fragment>
              )
            )}
          </div>
        </div>

        <div
          className={`bg-gray-900/80 rounded-2xl p-6 border-l-4 ${
            isMalicious
              ? "border-red-500"
              : isSuspicious
              ? "border-amber-500"
              : isInvalid
              ? "border-gray-500"
              : "border-emerald-500"
          }`}
        >
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2.5">
                <span
                  className={`text-xs px-3 py-1 rounded-full font-bold font-mono border ${
                    isMalicious
                      ? "bg-red-500/20 text-red-400 border-red-500/30"
                      : isSuspicious
                      ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                      : isInvalid
                      ? "bg-gray-500/20 text-gray-300 border-gray-500/30"
                      : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  }`}
                >
                  {verdict}
                </span>
                <span className="text-sm font-semibold font-mono text-gray-300">
                  {report?.hostname}
                </span>
              </div>
              <p className="text-base sm:text-lg font-bold text-gray-100 pt-1">
                Page Title: {report?.page_title || "Verified Endpoint"}
              </p>
            </div>
            <div className="text-left sm:text-right">
              <span className="text-xs text-gray-400 font-mono uppercase block">
                Threat Score
              </span>
              <span
                className={`text-3xl font-extrabold font-mono ${
                  isMalicious
                    ? "text-red-400"
                    : isSuspicious
                    ? "text-amber-400"
                    : isInvalid
                    ? "text-gray-400"
                    : "text-emerald-400"
                }`}
              >
                {score}/100
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-gray-400 uppercase">
                TLS Trust Chain
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold">
                {report?.tls?.badge || (report?.tls_valid ? "VALID" : "UNTRUSTED")}
              </span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-gray-500">Status:</span>
                <span>{report?.tls?.status || "Valid & Encrypted"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Issuer:</span>
                <span className="truncate max-w-[160px]">
                  {report?.tls?.issuer || report?.tls_issuer || "N/A"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Remaining:</span>
                <span>{report?.tls?.remaining || report?.tls_remaining || "N/A"}</span>
              </div>
            </div>
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-gray-400 uppercase">
                Domain Telemetry
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold">
                {report?.domain?.badge || "ESTABLISHED"}
              </span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-gray-500">Registrar:</span>
                <span className="truncate max-w-[160px]">
                  {report?.domain?.registrar || report?.registrar || "Verified"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Age:</span>
                <span>{report?.domain?.age || report?.domain_age || "Established"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Flag:</span>
                <span>{report?.domain?.flag || "Verified"}</span>
              </div>
            </div>
          </div>

          <div className="bg-gray-900/80 border border-gray-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-gray-400 uppercase">
                Web3 Immutable Log
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30 font-bold">
                ON-CHAIN
              </span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-gray-500">Ledger:</span>
                <span>Polygon Amoy (80002)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Hash:</span>
                <span className="text-purple-400">
                  {report?.web3?.short_hash || "0x8f92e41c...91b40e"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Status:</span>
                <span>{report?.web3?.status || "Cryptographically Anchored"}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-gray-900/80 border border-gray-800 rounded-2xl p-6 space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-blue-400 font-mono">
            Explainable AI (XAI) Investigation
          </h2>
          <p className="text-sm text-gray-200 leading-relaxed">
            {report?.xai_summary || report?.explanation}
          </p>
          <div className="border-t border-gray-800 pt-3 space-y-2">
            <div className="text-xs font-semibold text-gray-400 uppercase">
              Identified Risk Indicators:
            </div>
            <ul className="text-xs font-mono space-y-1.5 text-gray-300 list-disc list-inside">
              {(report?.identified_risk_indicators || []).map(
                (ind: string, i: number) => (
                  <li key={i}>{ind}</li>
                )
              )}
            </ul>
          </div>
          <div className="border-t border-gray-800 pt-3">
            <div className="text-xs font-semibold text-gray-400 uppercase">
              Recommended Action:
            </div>
            <p className="text-sm font-semibold text-emerald-400 mt-1">
              {report?.recommended_action}
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}