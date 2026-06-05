"use client";

import { useEffect, useState } from "react";
import { api, ComplianceReport, Framework } from "@/lib/api";
import { FileText, Download, Plus, Globe, CheckCircle2, Clock, AlertCircle } from "lucide-react";

interface FrameworkEntry {
  id: string; name: string; short: string;
  jurisdiction: string; flag: string;
  status: string; deadline: string; mandate_type: string; body: string;
  key_requirements: string[]; reference: string; description: string;
}

const MANDATE_COLOR: Record<string, string> = {
  mandatory: "bg-red-50 text-red-700 border-red-200",
  advisory:  "bg-blue-50 text-blue-700 border-blue-200",
  emerging:  "bg-purple-50 text-purple-700 border-purple-200",
};

const STATUS_META: Record<string, { icon: React.ReactNode; label: string; cls: string }> = {
  implemented: { icon: <CheckCircle2 size={12} />, label: "Report available", cls: "text-green-600" },
  stub:        { icon: <Clock size={12} />,         label: "Coming soon",       cls: "text-amber-600" },
  planned:     { icon: <AlertCircle size={12} />,   label: "Planned",           cls: "text-gray-400"  },
};

function FrameworkCard({
  fw, selected, onClick,
}: { fw: FrameworkEntry; selected: boolean; onClick: () => void }) {
  const mandate = MANDATE_COLOR[fw.mandate_type] ?? MANDATE_COLOR.advisory;
  const status  = STATUS_META[fw.status] ?? STATUS_META.stub;
  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-4 rounded-xl border transition-all ${
        selected ? "border-brand bg-brand/5 shadow-sm" : "border-gray-200 hover:border-gray-300 bg-white"
      }`}
    >
      <div className="flex items-start gap-2 mb-2">
        <span className="text-lg leading-none">{fw.flag}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="font-semibold text-sm text-gray-900">{fw.short}</span>
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${mandate}`}>
              {fw.mandate_type.toUpperCase()}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5 truncate">{fw.jurisdiction} · {fw.body}</p>
        </div>
      </div>
      <p className="text-xs text-gray-400 mb-2 line-clamp-2">{fw.description}</p>
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-400">Deadline: <strong className="text-gray-600">{fw.deadline}</strong></span>
        <span className={`flex items-center gap-1 text-xs font-medium ${status.cls}`}>
          {status.icon}{status.label}
        </span>
      </div>
    </button>
  );
}

export default function ReportsPage() {
  const [frameworks, setFrameworks]   = useState<FrameworkEntry[]>([]);
  const [reports,    setReports]      = useState<ComplianceReport[]>([]);
  const [selected,   setSelected]     = useState<FrameworkEntry | null>(null);
  const [generating, setGenerating]   = useState(false);
  const [jurisdiction, setJurisdiction] = useState<string>("All");

  useEffect(() => {
    fetch("http://localhost:8080/api/v1/reports/frameworks")
      .then(r => r.json()).then(setFrameworks).catch(() => {});
    api.listReports().catch(() => []).then(setReports);
  }, []);

  const jurisdictions = ["All", ...Array.from(new Set(frameworks.map(f => f.jurisdiction)))];
  const visible = jurisdiction === "All" ? frameworks : frameworks.filter(f => f.jurisdiction === jurisdiction);

  const generate = async () => {
    if (!selected || selected.status !== "implemented") return;
    setGenerating(true);
    try {
      const r = await api.generateReport(selected.id as Framework, {
        org_name: "Demo Financial Services Pvt. Ltd.",
        entity_type: "Scheduled Commercial Bank",
        license_number: "DEMO/2024/001",
      });
      setReports(prev => [r, ...prev]);
    } catch (e) { console.error(e); }
    finally { setGenerating(false); }
  };

  const openReport = async (id: string) => {
    try {
      const html = await api.getReportHtml(id);
      const w = window.open("", "_blank");
      w?.document.write(html);
    } catch { alert("Could not load report. Is the API running?"); }
  };

  return (
    <div className="p-8 max-w-6xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Compliance Reports</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          PQC readiness reports mapped to {frameworks.length} regulatory frameworks across {jurisdictions.length - 1} jurisdictions
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: framework selector */}
        <div className="lg:col-span-3">
          {/* Jurisdiction filter */}
          <div className="flex gap-2 mb-3 flex-wrap">
            {jurisdictions.map(j => (
              <button key={j} onClick={() => setJurisdiction(j)}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                  jurisdiction === j ? "bg-brand text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                }`}>{j}</button>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[560px] overflow-y-auto pr-1">
            {visible.map(fw => (
              <FrameworkCard key={fw.id} fw={fw} selected={selected?.id === fw.id} onClick={() => setSelected(fw)} />
            ))}
            {frameworks.length === 0 && (
              <div className="col-span-2 text-center py-8 text-gray-400 text-sm">
                Start the API server to load frameworks
              </div>
            )}
          </div>
        </div>

        {/* Right: detail + generate */}
        <div className="lg:col-span-2">
          {selected ? (
            <div className="bg-white rounded-xl border border-gray-200 p-5 sticky top-4">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-2xl">{selected.flag}</span>
                <div>
                  <h3 className="font-bold text-gray-900">{selected.short}</h3>
                  <p className="text-xs text-gray-500">{selected.jurisdiction}</p>
                </div>
              </div>
              <p className="text-xs text-gray-600 mb-3 leading-relaxed">{selected.description}</p>

              <div className="mb-3">
                <p className="text-xs font-semibold text-gray-700 mb-1.5">Key requirements</p>
                <ul className="space-y-1">
                  {selected.key_requirements.map((r, i) => (
                    <li key={i} className="text-xs text-gray-600 flex items-start gap-1.5">
                      <span className="text-brand mt-0.5 shrink-0">•</span>{r}
                    </li>
                  ))}
                </ul>
              </div>

              <p className="text-[10px] text-gray-400 mb-4 font-mono border-t border-gray-100 pt-3">
                {selected.reference}
              </p>

              {selected.status === "implemented" ? (
                <button onClick={generate} disabled={generating}
                  className="w-full flex items-center justify-center gap-2 bg-brand text-white px-4 py-2.5 rounded-lg text-sm font-semibold hover:bg-brand-light disabled:opacity-60 transition-colors">
                  <Plus size={14} />
                  {generating ? "Generating…" : `Generate ${selected.short} Report`}
                </button>
              ) : (
                <div className="w-full py-2.5 text-center text-sm text-gray-400 bg-gray-50 rounded-lg border border-dashed border-gray-200">
                  {selected.short} template coming soon
                </div>
              )}
            </div>
          ) : (
            <div className="bg-gray-50 rounded-xl border border-dashed border-gray-200 py-12 text-center">
              <Globe size={28} className="mx-auto mb-2 text-gray-300" />
              <p className="text-sm text-gray-400">Select a framework to generate a report</p>
            </div>
          )}
        </div>
      </div>

      {/* Generated reports */}
      {reports.length > 0 && (
        <div className="mt-8">
          <h2 className="text-sm font-semibold text-gray-700 mb-3">Generated reports</h2>
          <div className="space-y-2">
            {reports.map(r => {
              const fw = frameworks.find(f => f.id === r.framework);
              return (
                <div key={r.id} className="bg-white rounded-xl border border-gray-200 p-4 flex items-center gap-4 shadow-sm">
                  <span className="text-xl">{fw?.flag ?? "📄"}</span>
                  <div className="flex-1">
                    <p className="font-medium text-sm">{fw?.short ?? r.framework} Compliance Report</p>
                    <p className="text-xs text-gray-400">
                      {new Date(r.generated_at).toLocaleString()} ·{" "}
                      {r.snapshot.readiness_pct.toFixed(0)}% readiness ·{" "}
                      {r.snapshot.blocked_count} blocked
                    </p>
                  </div>
                  <button onClick={() => openReport(r.id)}
                    className="flex items-center gap-1.5 text-xs font-semibold text-brand hover:text-brand-light transition-colors">
                    <Download size={12} />View
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
