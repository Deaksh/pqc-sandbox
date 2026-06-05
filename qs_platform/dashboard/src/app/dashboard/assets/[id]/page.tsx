"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, AssetDetailPayload, FindingDetail, BenchmarkRow, CompatIssueDetail } from "@/lib/api";
import { VerdictBadge } from "@/components/VerdictBadge";
import { ScoreBar } from "@/components/ScoreBar";
import {
  ArrowLeft, ChevronDown, ChevronRight, CheckCircle2,
  AlertTriangle, XCircle, Info, MessageSquare, Code2,
  Loader2, Shield, RefreshCw, Zap, Package,
} from "lucide-react";
import clsx from "clsx";

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_META = {
  BLOCKED: { icon: XCircle,       cls: "text-red-600",    bg: "bg-red-50 border-red-200",    label: "BLOCKED"  },
  CAUTION: { icon: AlertTriangle, cls: "text-amber-600",  bg: "bg-amber-50 border-amber-200", label: "CAUTION"  },
  INFO:    { icon: Info,          cls: "text-blue-500",   bg: "bg-blue-50 border-blue-200",   label: "INFO"     },
  OK:      { icon: CheckCircle2,  cls: "text-green-600",  bg: "bg-green-50 border-green-200", label: "OK"       },
};

const FLAG_CLS: Record<string, string> = {
  bad:  "text-red-600 font-semibold",
  warn: "text-amber-600 font-semibold",
  ok:   "text-gray-700",
};

// ── Benchmark table ───────────────────────────────────────────────────────────

function BenchmarkTable({ rows }: { rows: BenchmarkRow[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-xs text-gray-500 uppercase tracking-wide border-b border-gray-100">
            <th className="py-2 pr-4 text-left font-semibold">Metric</th>
            <th className="py-2 px-4 text-right font-semibold">Current (classical)</th>
            <th className="py-2 px-4 text-right font-semibold">After migration (PQC)</th>
            <th className="py-2 px-4 text-right font-semibold">Delta</th>
            <th className="py-2 pl-4 text-right font-semibold">Ratio</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {rows.map(row => (
            <tr key={row.metric} className="hover:bg-gray-50">
              <td className="py-2.5 pr-4 font-medium text-gray-800">{row.metric}</td>
              <td className="py-2.5 px-4 text-right text-gray-500 font-mono text-xs">{row.classical}</td>
              <td className={clsx("py-2.5 px-4 text-right font-mono text-xs", FLAG_CLS[row.flag] ?? "text-gray-700")}>{row.pqc}</td>
              <td className={clsx("py-2.5 px-4 text-right font-mono text-xs", FLAG_CLS[row.flag] ?? "text-gray-500")}>{row.delta}</td>
              <td className={clsx("py-2.5 pl-4 text-right font-mono text-xs", FLAG_CLS[row.flag] ?? "text-gray-500")}>{row.ratio}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Compat issue card ─────────────────────────────────────────────────────────

function CompatCard({ issue }: { issue: CompatIssueDetail }) {
  const meta = SEV_META[issue.severity] ?? SEV_META.INFO;
  const Icon = meta.icon;
  return (
    <div className={clsx("rounded-lg border p-3.5 mb-2", meta.bg)}>
      <div className="flex items-start gap-2">
        <Icon size={15} className={clsx("mt-0.5 shrink-0", meta.cls)} />
        <div className="flex-1 min-w-0">
          <p className={clsx("text-sm font-semibold", meta.cls)}>
            [{issue.category.toUpperCase()}] {issue.title}
          </p>
          <p className="text-xs text-gray-600 mt-1 leading-relaxed">{issue.detail}</p>
          {issue.mitigation && (
            <p className="text-xs text-blue-700 mt-2 bg-blue-50 rounded px-2 py-1.5 border border-blue-100">
              <span className="font-semibold">Fix: </span>{issue.mitigation}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Acknowledge modal ─────────────────────────────────────────────────────────

function AckModal({
  assetId, algorithm, onClose, onSaved,
}: { assetId: string; algorithm: string; onClose: () => void; onSaved: () => void }) {
  const [note, setNote]     = useState("");
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await api.acknowledgeIssue(assetId, "", algorithm, note);
      onSaved();
      onClose();
    } catch { /* silent */ }
    finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-sm mx-4 p-6">
        <h3 className="font-semibold text-gray-900 mb-1">Acknowledge finding</h3>
        <p className="text-xs text-gray-500 mb-3">
          <code className="bg-gray-100 px-1 rounded">{algorithm}</code> — add a note explaining
          why this is accepted risk or what remediation is planned.
        </p>
        <textarea
          rows={3}
          value={note}
          onChange={e => setNote(e.target.value)}
          placeholder="e.g. Tracked in JIRA PQC-42, migration planned for Q3 2026..."
          className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-brand/30"
        />
        <div className="flex gap-2 mt-3">
          <button onClick={onClose} className="flex-1 py-2 border border-gray-200 rounded-lg text-sm text-gray-600 hover:bg-gray-50">Cancel</button>
          <button onClick={save} disabled={saving} className="flex-1 py-2 bg-brand text-white rounded-lg text-sm font-semibold hover:bg-brand-light disabled:opacity-60 flex items-center justify-center gap-2">
            {saving && <Loader2 size={13} className="animate-spin" />}
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Finding card ──────────────────────────────────────────────────────────────

function FindingCard({
  finding, assetId, onAcknowledged,
}: { finding: FindingDetail; assetId: string; onAcknowledged: () => void }) {
  const [open,   setOpen]   = useState(true);
  const [tab,    setTab]    = useState<"why" | "bench" | "compat" | "diff">("why");
  const [acking, setAcking] = useState(false);

  const tabs: { id: typeof tab; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: "why",    label: "Why vulnerable",     icon: <Shield size={13} /> },
    { id: "bench",  label: "Performance impact", icon: <Zap size={13} />,   count: finding.benchmark_rows.length },
    { id: "compat", label: "Compatibility",       icon: <Package size={13} />, count: finding.compat_issues.length },
    { id: "diff",   label: "Config fix",          icon: <Code2 size={13} /> },
  ];

  const blockedCount = finding.compat_issues.filter(i => i.severity === "BLOCKED").length;
  const cautionCount = finding.compat_issues.filter(i => i.severity === "CAUTION").length;

  return (
    <>
      {acking && (
        <AckModal
          assetId={assetId}
          algorithm={finding.algorithm}
          onClose={() => setAcking(false)}
          onSaved={onAcknowledged}
        />
      )}

      <div className={clsx(
        "bg-white rounded-xl border shadow-sm overflow-hidden mb-4",
        finding.acknowledged ? "border-gray-200 opacity-75" : "border-gray-200",
      )}>
        {/* Header */}
        <button
          className="w-full flex items-center gap-3 px-5 py-4 hover:bg-gray-50 transition-colors text-left"
          onClick={() => setOpen(o => !o)}
        >
          {open ? <ChevronDown size={16} className="text-gray-400 shrink-0" /> : <ChevronRight size={16} className="text-gray-400 shrink-0" />}

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-gray-900">{finding.algorithm}</span>
              <span className="text-gray-400 text-xs">→</span>
              <span className="text-brand font-medium text-sm">{finding.recommended_pqc}</span>
              <span className="text-xs bg-blue-50 text-blue-700 px-2 py-0.5 rounded-full border border-blue-100">{finding.standard}</span>
              {finding.acknowledged && (
                <span className="text-xs bg-green-50 text-green-700 px-2 py-0.5 rounded-full border border-green-100 flex items-center gap-1">
                  <CheckCircle2 size={10} /> Acknowledged
                </span>
              )}
            </div>
            {finding.location && (
              <p className="text-xs text-gray-400 font-mono mt-0.5 truncate">{finding.location}</p>
            )}
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {blockedCount > 0 && (
              <span className="text-xs text-red-600 bg-red-50 border border-red-200 px-2 py-0.5 rounded-full font-semibold">{blockedCount} BLOCKED</span>
            )}
            {cautionCount > 0 && (
              <span className="text-xs text-amber-600 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full font-semibold">{cautionCount} CAUTION</span>
            )}
            <VerdictBadge verdict={finding.verdict} />
            <div className="w-28">
              <ScoreBar score={finding.score} label={finding.score_label} />
            </div>
          </div>
        </button>

        {/* Body */}
        {open && (
          <div className="border-t border-gray-100">
            {/* Tabs */}
            <div className="flex border-b border-gray-100 px-5 gap-1">
              {tabs.map(t => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={clsx(
                    "flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors",
                    tab === t.id
                      ? "border-brand text-brand"
                      : "border-transparent text-gray-500 hover:text-gray-700",
                  )}
                >
                  {t.icon}{t.label}
                  {t.count !== undefined && t.count > 0 && (
                    <span className={clsx(
                      "ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold",
                      tab === t.id ? "bg-brand/10 text-brand" : "bg-gray-100 text-gray-500",
                    )}>
                      {t.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="px-5 py-4">
              {/* WHY VULNERABLE */}
              {tab === "why" && (
                <div className="space-y-3">
                  <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                    <p className="text-sm font-semibold text-amber-800 mb-1">Why this algorithm is quantum-vulnerable</p>
                    <p className="text-sm text-amber-900 leading-relaxed">{finding.why_vulnerable}</p>
                  </div>
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <p className="text-sm font-semibold text-blue-800 mb-1">Recommended replacement: {finding.recommended_pqc}</p>
                    <p className="text-sm text-blue-900 leading-relaxed">
                      Standardised by {finding.standard}. This is a lattice-based algorithm
                      providing security against both classical and quantum attacks. It is
                      backward-compatible when deployed in hybrid mode alongside the current algorithm.
                    </p>
                  </div>
                  {finding.ack_note && (
                    <div className="bg-green-50 border border-green-200 rounded-lg p-3 flex gap-2">
                      <MessageSquare size={14} className="text-green-600 mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-semibold text-green-800">Acknowledged note</p>
                        <p className="text-xs text-green-700 mt-0.5">{finding.ack_note}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* BENCHMARK */}
              {tab === "bench" && (
                <div>
                  <p className="text-xs text-gray-500 mb-3">
                    Measured using NIST reference implementation baselines.
                    <span className="text-red-600 font-medium"> Red</span> = significant regression (≥10×),
                    <span className="text-amber-600 font-medium"> amber</span> = notable (≥2×).
                  </p>
                  <BenchmarkTable rows={finding.benchmark_rows} />
                </div>
              )}

              {/* COMPAT */}
              {tab === "compat" && (
                <div>
                  {finding.compat_issues.length === 0 ? (
                    <div className="flex items-center gap-2 text-green-700 bg-green-50 rounded-lg p-3 border border-green-200">
                      <CheckCircle2 size={15} />
                      <span className="text-sm">No compatibility issues detected for your system configuration.</span>
                    </div>
                  ) : (
                    <>
                      <p className="text-xs text-gray-500 mb-3">
                        These are concrete things that will break or need remediating before migration.
                        Each has a specific fix.
                      </p>
                      {finding.compat_issues.map((issue, i) => (
                        <CompatCard key={i} issue={issue} />
                      ))}
                    </>
                  )}
                </div>
              )}

              {/* CONFIG DIFF */}
              {tab === "diff" && (
                <div>
                  <p className="text-xs text-gray-500 mb-3">
                    Copy-paste this into your OpenSSL configuration to enable hybrid PQC key exchange.
                    This is a drop-in change — it keeps classical as fallback.
                  </p>
                  <pre className="bg-slate-900 text-green-400 rounded-lg p-4 text-xs overflow-x-auto leading-relaxed font-mono whitespace-pre-wrap">
                    {finding.config_diff}
                  </pre>
                </div>
              )}
            </div>

            {/* Footer actions */}
            <div className="border-t border-gray-100 px-5 py-3 flex items-center justify-between bg-gray-50">
              <span className="text-xs text-gray-400">
                {finding.compat_issues.length} compatibility check{finding.compat_issues.length !== 1 ? "s" : ""} ·{" "}
                {finding.benchmark_rows.length} metrics measured
              </span>
              {!finding.acknowledged ? (
                <button
                  onClick={() => setAcking(true)}
                  className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 hover:text-brand transition-colors"
                >
                  <CheckCircle2 size={13} /> Mark as reviewed
                </button>
              ) : (
                <span className="text-xs text-green-600 flex items-center gap-1">
                  <CheckCircle2 size={13} /> Reviewed
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router  = useRouter();
  const [data,    setData]    = useState<AssetDetailPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [rescanning, setRescanning] = useState(false);

  const load = () => {
    api.getAssetDetail(id)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [id]);

  const rescan = async () => {
    setRescanning(true);
    try {
      await api.triggerScan(id);
      setTimeout(() => { load(); setRescanning(false); }, 4000);
    } catch { setRescanning(false); }
  };

  if (loading) {
    return (
      <div className="p-8 flex items-center gap-2 text-gray-400">
        <Loader2 size={16} className="animate-spin" /> Loading investigation…
      </div>
    );
  }
  if (!data) {
    return <div className="p-8 text-gray-400">Asset not found.</div>;
  }

  const { asset, latest_scan, findings } = data;
  const blockedCount = findings.filter(f => f.verdict === "BLOCKED").length;
  const cautionCount = findings.filter(f => f.verdict === "CAUTION").length;

  return (
    <div className="p-8 max-w-4xl">
      {/* Back */}
      <button
        onClick={() => router.push("/dashboard/assets")}
        className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-brand mb-5 transition-colors"
      >
        <ArrowLeft size={14} /> Back to assets
      </button>

      {/* Asset header */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5 mb-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-gray-900">{asset.name}</h1>
            <p className="text-sm text-gray-400 font-mono mt-0.5">{asset.target}</p>
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full font-medium">
                {asset.asset_type.replace("_", " ")}
              </span>
              {asset.team && (
                <span className="text-xs bg-blue-50 text-blue-700 px-2 py-0.5 rounded-full">{asset.team}</span>
              )}
              {asset.tags.map(tag => (
                <span key={tag} className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">{tag}</span>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            {latest_scan && <VerdictBadge verdict={latest_scan.verdict ?? "CAUTION"} />}
            <button
              onClick={rescan}
              disabled={rescanning}
              className="flex items-center gap-1.5 text-xs font-semibold text-brand hover:text-brand-light disabled:opacity-50 transition-colors"
            >
              <RefreshCw size={12} className={rescanning ? "animate-spin" : ""} />
              {rescanning ? "Scanning…" : "Re-scan"}
            </button>
          </div>
        </div>

        {/* Summary bar */}
        {latest_scan && (
          <div className="mt-4 pt-4 border-t border-gray-100 grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-2xl font-black text-gray-900">{findings.length}</p>
              <p className="text-xs text-gray-500 mt-0.5">Algorithms found</p>
            </div>
            <div>
              <p className={clsx("text-2xl font-black", blockedCount > 0 ? "text-red-600" : "text-gray-400")}>{blockedCount}</p>
              <p className="text-xs text-gray-500 mt-0.5">Blockers</p>
            </div>
            <div>
              <p className={clsx("text-2xl font-black", cautionCount > 0 ? "text-amber-600" : "text-gray-400")}>{cautionCount}</p>
              <p className="text-xs text-gray-500 mt-0.5">Cautions</p>
            </div>
          </div>
        )}
      </div>

      {/* Findings */}
      {findings.length === 0 ? (
        <div className="bg-white rounded-xl border border-dashed border-gray-300 py-12 text-center">
          <Shield size={28} className="mx-auto mb-2 text-gray-300" />
          <p className="text-gray-500">No findings yet — run a scan first.</p>
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-gray-700">
              {findings.length} finding{findings.length !== 1 ? "s" : ""} — click any to investigate
            </h2>
            <p className="text-xs text-gray-400">
              {findings.filter(f => f.acknowledged).length} of {findings.length} reviewed
            </p>
          </div>
          {findings.map((f, i) => (
            <FindingCard key={i} finding={f} assetId={id} onAcknowledged={load} />
          ))}
        </>
      )}
    </div>
  );
}
