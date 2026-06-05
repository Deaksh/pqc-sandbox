"use client";
import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Clock, HelpCircle, RefreshCw, Plus, ExternalLink, Loader2, X, WifiOff } from "lucide-react";
import clsx from "clsx";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

interface VendorRisk {
  id: string; name: string; endpoint: string; category: string;
  criticality: string; team?: string; status: string; risk_level: string;
  is_blocking: boolean; pqc_support: string; pqc_tls_ready: boolean;
  expected_full: string; roadmap_notes: string; recommendation: string;
  current_tls_version: string; reference: string; probe_error?: string;
}
interface Summary {
  total_vendors: number; assessed: number; blocking: number;
  ready: number; partial: number; planned: number; unknown: number;
}

const STATUS_META: Record<string, { icon: React.ReactNode; cls: string; bg: string }> = {
  BLOCKING: { icon: <AlertTriangle size={13} />, cls: "text-red-700",    bg: "bg-red-50 border-red-200" },
  READY:    { icon: <CheckCircle2  size={13} />, cls: "text-green-700",  bg: "bg-green-50 border-green-200" },
  PARTIAL:  { icon: <Clock        size={13} />, cls: "text-amber-700",  bg: "bg-amber-50 border-amber-200" },
  PLANNED:  { icon: <Clock        size={13} />, cls: "text-blue-700",   bg: "bg-blue-50 border-blue-200" },
  UNKNOWN:  { icon: <HelpCircle   size={13} />, cls: "text-gray-500",   bg: "bg-gray-50 border-gray-200" },
};

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "text-red-700 bg-red-50 border-red-200",
  HIGH:     "text-orange-700 bg-orange-50 border-orange-200",
  MEDIUM:   "text-amber-700 bg-amber-50 border-amber-200",
  LOW:      "text-green-700 bg-green-50 border-green-200",
};

const CAT_LABEL: Record<string, string> = {
  payment: "💳 Payment", ca: "🔐 CA", hsm: "🔑 HSM",
  cloud: "☁️ Cloud", saas: "🌐 SaaS", api: "🔌 API",
};

function KPI({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm text-center">
      <p className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-1">{label}</p>
      <p className={`text-3xl font-black ${color ?? "text-gray-900"}`}>{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
    </div>
  );
}

function AddVendorModal({ onClose, onAdd }: { onClose: () => void; onAdd: (v: VendorRisk) => void }) {
  const [form, setForm] = useState({ name: "", endpoint: "", category: "saas", criticality: "high", team: "" });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const handle = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.endpoint) { setError("Name and endpoint are required."); return; }
    setSaving(true);
    try {
      const res = await fetch(`${BASE}/api/v1/vendors`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(await res.text());
      // Optimistically add to list with UNKNOWN status
      onAdd({
        id: crypto.randomUUID(), ...form,
        status: "UNKNOWN", risk_level: "MEDIUM", is_blocking: false,
        pqc_support: "unknown", pqc_tls_ready: false,
        expected_full: "unknown", roadmap_notes: "Assessment pending.",
        recommendation: "Run a vendor questionnaire to determine PQC readiness.",
        current_tls_version: "unknown", reference: "",
      });
      onClose();
    } catch {
      setError("Failed to add vendor — is the API running?");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-base font-semibold">Add Vendor</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X size={18} /></button>
        </div>
        <form onSubmit={handle} className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Vendor name *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30"
              placeholder="e.g. Stripe, AWS ACM, DigiCert" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Endpoint / domain *</label>
            <input value={form.endpoint} onChange={e => setForm(f => ({ ...f, endpoint: e.target.value }))}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30"
              placeholder="e.g. api.stripe.com" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Category</label>
              <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30">
                <option value="saas">SaaS</option>
                <option value="payment">Payment</option>
                <option value="ca">Certificate Authority</option>
                <option value="cloud">Cloud</option>
                <option value="hsm">HSM</option>
                <option value="api">API</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1">Criticality</label>
              <select value={form.criticality} onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1">Team owner</label>
            <input value={form.team} onChange={e => setForm(f => ({ ...f, team: e.target.value }))}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30"
              placeholder="e.g. Platform, Security, Payments" />
          </div>
          {error && <p className="text-xs text-red-600 bg-red-50 rounded-lg px-3 py-2">{error}</p>}
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-200 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-50">
              Cancel
            </button>
            <button type="submit" disabled={saving}
              className="flex-1 px-4 py-2 bg-brand text-white rounded-lg text-sm font-semibold hover:bg-brand-light disabled:opacity-50">
              {saving ? "Adding…" : "Add Vendor"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function VendorsPage() {
  const [data,      setData]      = useState<{ summary: Summary; vendors: VendorRisk[] } | null>(null);
  const [loading,   setLoading]   = useState(true);
  const [apiError,  setApiError]  = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [selected,  setSelected]  = useState<VendorRisk | null>(null);
  const [showAdd,   setShowAdd]   = useState(false);

  const load = () =>
    fetch(`${BASE}/api/v1/vendors/assess`)
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(d => { setData(d); setApiError(false); })
      .catch(() => setApiError(true))
      .finally(() => { setLoading(false); setAssessing(false); });

  useEffect(() => { load(); }, []);

  const reassess = () => { setAssessing(true); load(); };

  if (loading) return (
    <div className="p-8 flex items-center gap-2 text-gray-400">
      <Loader2 size={16} className="animate-spin" /> Loading vendor risk data…
    </div>
  );

  if (apiError) return (
    <div className="p-8 max-w-lg">
      <div className="bg-amber-50 border border-amber-200 rounded-2xl p-6 flex items-start gap-4">
        <WifiOff size={22} className="text-amber-600 mt-0.5 shrink-0" />
        <div>
          <p className="font-semibold text-amber-900">API server not reachable</p>
          <p className="text-sm text-amber-800 mt-1">
            Start the backend to load vendor risk data:
          </p>
          <pre className="mt-2 text-xs bg-amber-100 rounded-lg px-3 py-2 text-amber-900 overflow-x-auto">
            uvicorn qs_platform.api.main:app --reload --port 8080
          </pre>
          <button onClick={() => { setLoading(true); setApiError(false); load(); }}
            className="mt-3 text-xs font-semibold text-amber-700 hover:text-amber-900 underline">
            Retry
          </button>
        </div>
      </div>
    </div>
  );

  const s = data?.summary;
  const vendors = data?.vendors ?? [];

  return (
    <div className="p-8 max-w-6xl">
      {showAdd && (
        <AddVendorModal
          onClose={() => setShowAdd(false)}
          onAdd={v => setData(prev => prev ? {
            ...prev,
            vendors: [...prev.vendors, v],
            summary: { ...prev.summary, total_vendors: prev.summary.total_vendors + 1, unknown: prev.summary.unknown + 1 },
          } : null)}
        />
      )}

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Vendor / Supply-Chain Risk</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Which of your third-party dependencies will block your PQC migration?
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={reassess} disabled={assessing}
            className="flex items-center gap-1.5 text-sm font-semibold text-brand hover:text-brand-light disabled:opacity-50 transition-colors">
            <RefreshCw size={14} className={assessing ? "animate-spin" : ""} />
            Re-assess
          </button>
          <button onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 bg-brand text-white px-3 py-2 rounded-lg text-sm font-semibold hover:bg-brand-light transition-colors">
            <Plus size={13} /> Add Vendor
          </button>
        </div>
      </div>

      {/* KPI strip */}
      {s && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          <KPI label="Blocking migration" value={s.blocking} color={s.blocking > 0 ? "text-red-600" : "text-gray-400"} sub="critical + no roadmap" />
          <KPI label="PQC Ready"   value={s.ready}   color="text-green-600" />
          <KPI label="Partial / Planned" value={(s.partial ?? 0) + (s.planned ?? 0)} color="text-amber-600" />
          <KPI label="Unknown"     value={s.unknown}  color="text-gray-500" sub="needs questionnaire" />
        </div>
      )}

      {vendors.length > 0 && s && s.blocking > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-5 flex items-start gap-3">
          <AlertTriangle size={18} className="text-red-600 mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold text-red-800 text-sm">
              {s.blocking} vendor{s.blocking > 1 ? "s are" : " is"} blocking your PQC migration
            </p>
            <p className="text-red-700 text-xs mt-1">
              These critical vendors have no known PQC roadmap. Your migration cannot complete until they support PQC.
              Issue formal vendor questionnaires and add PQC support to contract renewal criteria.
            </p>
          </div>
        </div>
      )}

      {vendors.length === 0 ? (
        <div className="bg-gray-50 rounded-xl border border-dashed border-gray-200 py-16 text-center">
          <p className="text-sm text-gray-500 font-medium">No vendors tracked yet</p>
          <p className="text-xs text-gray-400 mt-1 mb-4">Add your payment providers, CAs, HSMs, and cloud vendors</p>
          <button onClick={() => setShowAdd(true)}
            className="inline-flex items-center gap-2 bg-brand text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-brand-light transition-colors">
            <Plus size={14} /> Add your first vendor
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Vendor list */}
          <div className="lg:col-span-2 space-y-2">
            {vendors.map(v => {
              const meta = STATUS_META[v.status] ?? STATUS_META.UNKNOWN;
              return (
                <button key={v.id} onClick={() => setSelected(v)}
                  className={clsx(
                    "w-full text-left bg-white rounded-xl border p-4 hover:shadow-md transition-all",
                    selected?.id === v.id ? "border-brand shadow-md" : "border-gray-200",
                    v.is_blocking && "border-l-4 border-l-red-500",
                  )}>
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-lg">{CAT_LABEL[v.category]?.split(" ")[0] ?? "🔌"}</span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-sm text-gray-900">{v.name}</span>
                          {v.team && <span className="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full">{v.team}</span>}
                          {v.criticality === "critical" && (
                            <span className="text-xs bg-red-50 text-red-600 px-1.5 py-0.5 rounded border border-red-100 font-semibold">CRITICAL</span>
                          )}
                        </div>
                        <p className="text-xs text-gray-400 font-mono mt-0.5">{v.endpoint}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={clsx("flex items-center gap-1 text-xs font-semibold px-2 py-1 rounded-lg border", meta.bg, meta.cls)}>
                        {meta.icon}{v.status}
                      </span>
                      <span className={clsx("text-xs font-bold px-2 py-1 rounded-lg border", RISK_COLOR[v.risk_level] ?? RISK_COLOR.MEDIUM)}>
                        {v.risk_level}
                      </span>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Detail panel */}
          <div className="lg:col-span-1">
            {selected ? (
              <div className="bg-white rounded-xl border border-gray-200 p-5 sticky top-4 shadow-sm">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3 className="font-bold text-gray-900">{selected.name}</h3>
                    <p className="text-xs text-gray-400 font-mono">{selected.endpoint}</p>
                  </div>
                  <span className={clsx("text-xs font-bold px-2 py-1 rounded-lg border", RISK_COLOR[selected.risk_level])}>
                    {selected.risk_level}
                  </span>
                </div>

                <div className="space-y-3 text-sm">
                  <div className="bg-gray-50 rounded-lg p-3">
                    <p className="text-xs font-semibold text-gray-500 mb-1">PQC Support Status</p>
                    <p className={clsx("font-bold", STATUS_META[selected.status]?.cls)}>
                      {selected.pqc_support.toUpperCase()} — {selected.status}
                    </p>
                    {selected.expected_full !== "unknown" && (
                      <p className="text-xs text-gray-500 mt-0.5">Expected full support: {selected.expected_full}</p>
                    )}
                  </div>

                  <div>
                    <p className="text-xs font-semibold text-gray-500 mb-1">Roadmap</p>
                    <p className="text-xs text-gray-700 leading-relaxed">{selected.roadmap_notes || "No known roadmap."}</p>
                    {selected.reference && (
                      <a href={selected.reference} target="_blank" rel="noopener"
                        className="flex items-center gap-1 text-xs text-brand mt-1 hover:underline">
                        <ExternalLink size={10} /> Official source
                      </a>
                    )}
                  </div>

                  <div className="bg-amber-50 border border-amber-200 rounded-lg p-3">
                    <p className="text-xs font-semibold text-amber-800 mb-1">Recommendation</p>
                    <p className="text-xs text-amber-900 leading-relaxed">{selected.recommendation}</p>
                  </div>

                  {selected.current_tls_version && selected.current_tls_version !== "unknown" && (
                    <div>
                      <p className="text-xs font-semibold text-gray-500 mb-1">Live TLS probe</p>
                      <p className="text-xs text-gray-600">Version: {selected.current_tls_version}</p>
                    </div>
                  )}
                  {selected.probe_error && (
                    <p className="text-xs text-gray-400">Probe: {selected.probe_error}</p>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-gray-50 rounded-xl border border-dashed border-gray-200 py-12 text-center">
                <p className="text-sm text-gray-400">Click a vendor to see details</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
