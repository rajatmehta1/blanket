"use client";

import { useState } from "react";
import DomainSelector from "@/components/DomainSelector";
import ProviderSelector from "@/components/ProviderSelector";
import RepoInput from "@/components/RepoInput";
import ScanButton from "@/components/ScanButton";
import ResultsPanel from "@/components/ResultsPanel";

const DOMAINS = [
  { id: "healthcare", label: "Healthcare", icon: "🏥", frameworks: ["HIPAA", "SOC2"] },
  { id: "finance", label: "Finance", icon: "🏦", frameworks: ["PCI-DSS", "SOC2", "SOX"] },
  { id: "saas", label: "SaaS", icon: "☁️", frameworks: ["SOC2", "GDPR"] },
  { id: "general", label: "General", icon: "🔧", frameworks: [] },
];

const PROVIDERS = [
  { id: "anthropic", label: "Anthropic Claude", models: ["claude-sonnet-4-20250514", "claude-opus-4-20250514"] },
  { id: "openai", label: "OpenAI", models: ["gpt-4o", "gpt-4o-mini"] },
  { id: "ollama", label: "Ollama (Local)", models: ["llama3.1"] },
  { id: "none", label: "Static Only (Free)", models: [] },
];

export default function Home() {
  const [domain, setDomain] = useState("general");
  const [provider, setProvider] = useState("none");
  const [repos, setRepos] = useState<string[]>([]);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedDomain = DOMAINS.find((d) => d.id === domain)!;

  const handleScan = async () => {
    if (repos.length === 0) {
      setError("Add at least one repository.");
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const resp = await fetch("/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_name: "web-scan",
          domain,
          frameworks: selectedDomain.frameworks,
          repos: repos.map((r) => (r.startsWith("/") || r.startsWith("C:") ? { local_path: r } : { url: r })),
        }),
      });
      const data = await resp.json();
      if (data.scan_id) {
        await pollScan(data.scan_id);
      } else {
        setError("Failed to start scan.");
      }
    } catch (e: any) {
      setError(e.message || "Scan failed.");
    } finally {
      setScanning(false);
    }
  };

  const pollScan = async (scanId: string) => {
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const resp = await fetch(`/api/v1/scan/${scanId}`);
      const data = await resp.json();
      if (data.status === "completed" || data.status === "failed") {
        setResult(data);
        return;
      }
    }
    setError("Scan timed out.");
  };

  return (
    <main className="min-h-screen p-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="text-center mb-12">
        <h1 className="text-4xl font-extrabold text-white mb-2">
          <span className="text-accent">Blanket</span>Audit
        </h1>
        <p className="text-gray-400 text-lg">
          AI-powered architecture governance — security, compliance, quality
        </p>
      </div>

      {/* Domain selector */}
      <section className="mb-8">
        <h2 className="text-sm text-gray-500 uppercase tracking-wider mb-3">Domain</h2>
        <DomainSelector domains={DOMAINS} selected={domain} onSelect={setDomain} />
        {selectedDomain.frameworks.length > 0 && (
          <div className="mt-2 text-sm text-gray-500">
            Frameworks: {selectedDomain.frameworks.map((f) => (
              <span key={f} className="inline-block bg-accent/10 text-accent px-2 py-0.5 rounded-full text-xs font-mono mr-1">
                {f}
              </span>
            ))}
          </div>
        )}
      </section>

      {/* Provider selector */}
      <section className="mb-8">
        <h2 className="text-sm text-gray-500 uppercase tracking-wider mb-3">LLM Provider</h2>
        <ProviderSelector providers={PROVIDERS} selected={provider} onSelect={setProvider} />
      </section>

      {/* Repo input */}
      <section className="mb-8">
        <h2 className="text-sm text-gray-500 uppercase tracking-wider mb-3">Repositories</h2>
        <RepoInput repos={repos} onChange={setRepos} />
      </section>

      {/* Scan button */}
      <ScanButton scanning={scanning} onClick={handleScan} />

      {/* Error */}
      {error && (
        <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Results */}
      {result && <ResultsPanel result={result} />}
    </main>
  );
}
