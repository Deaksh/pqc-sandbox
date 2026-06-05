"use client";

import { useEffect, useState } from "react";
import { api, Asset } from "@/lib/api";
import { VerdictBadge } from "@/components/VerdictBadge";
import { ScoreBar } from "@/components/ScoreBar";
import Link from "next/link";
import { RefreshCw, Plus, Server, Globe, FileCode2, X, Loader2, ExternalLink } from "lucide-react";

type ScanMeta = { verdict: string; score: number; label: string };

const ASSET_TYPE_OPTIONS = [
  { value: "tls_endpoint", label: "TLS Endpoint",  hint: "e.g. api.mybank.com" },
  { value: "cbom_file",    label: "CBOM File",      hint: "Absolute path to .json CBOM" },
  { value: "sarif_file",   label: "SARIF File",     hint: "Absolute path to .sarif/.json" },
  { value: "code_repo",    label: "Code Repo",      hint: "Path to local repo directory" },
];

const ASSET_ICONS: Record<string, React.ReactNode> = {
  tls_endpoint: <Globe    size={15} className="text-blue-400" />,
  cbom_file:    <FileCode2 size={15} className="text-purple-400" />,
  sarif_file:   <FileCode2 size={15} className="text-orange-400" />,
  code_repo:    <Server   size={15} className="text-green-400" />,
};

function AddAssetModal({ onClose, onAdd }: { onClose: () => void; onAdd: (a: Asset) => void }) {
  const [form, setForm]   = useState({ name: "", asset_type: "tls_endpoint", target: "", team: "", tags: "" });
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState("");
  const selectedType = ASSET_TYPE_OPTIONS.find(o => o.value === form.asset_type);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || !form.target.trim()) { setError("Name and target are required."); return; }
    setSaving(true); setError("");
    try {
      const asset = await api.createAsset({
        name: form.name.trim(), asset_type: form.asset_type, target: form.target.trim(),
        team: form.team.trim() || undefined,
        tags: form.tags ? form.tags.split(",").map(t => t.trim()).filter(Boolean) : [],
      });
      onAdd(asset); onClose();
    } catch (err: any) { setError(err.message ?? "Failed to create asset."); }
    finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-base font-semibold">Add Asset</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X size={18} /></button>
        </div>
        <form onSubmit={submit} className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1.5">Asset Type</label>
            <div className="grid grid-cols-2 gap-2">
              {ASSET_TYPE_OPTIONS.map(opt => (
                <button key={opt.value} type="button"
                  onClick={() => setForm(f => ({ ...f, asset_type: opt.value, target: "" }))}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-left text-sm transition-colors ${
                    form.asset_type === opt.value ? "border-brand bg-brand/5 text-brand font-medium" : "border-gray-200 text-gray-600 hover:border-gray-300"
                  }`}>
                  {ASSET_ICONS[opt.value]}{opt.label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1.5">Asset Name <span className="text-red-500">*</span></label>
            <input type="text" placeholder="e.g. Internet Banking API" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1.5">
              Target <span className="text-red-500">*</span>
              <span className="font-normal text-gray-400 ml-1">— {selectedType?.hint}</span>
            </label>
            <input type="text" placeholder={selectedType?.hint} value={form.target}
              onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Team</label>
              <input type="text" placeholder="e.g. Payments" value={form.team}
                onChange={e => setForm(f => ({ ...f, team: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30" />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-600 mb-1.5">Tags <span className="font-normal text-gray-400">(comma-separated)</span></label>
              <input type="text" placeholder="prod, regulated" value={form.tags}
                onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/30" />
            </div>
          </div>
          {error && <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>}
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="flex-1 px-4 py-2 border border-gray-200 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-50">Cancel</button>
            <button type="submit" disabled={saving} className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-brand text-white rounded-lg text-sm font-semibold hover:bg-brand-light disabled:opacity-60 transition-colors">
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              {saving ? "Adding…" : "Add Asset"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function AssetsPage() {
  const [assets,   setAssets]   = useState<Asset[]>([]);
  const [scans,    setScans]    = useState<Record<string, ScanMeta>>({});
  const [loading,  setLoading]  = useState(true);
  const [scanning, setScanning] = useState<string | null>(null);
  const [showAdd,  setShowAdd]  = useState(false);

  useEffect(() => {
    api.listAssets().then(setAssets).catch(console.error).finally(() => setLoading(false));
  }, []);

  const handleScan = async (assetId: string) => {
    setScanning(assetId);
    try {
      await api.triggerScan(assetId);
      setTimeout(() => {
        api.listScans(assetId).then(results => {
          const latest = results[0];
          if (latest?.verdict) {
            setScans(prev => ({ ...prev, [assetId]: { verdict: latest.verdict!, score: latest.difficulty_score ?? 0, label: latest.difficulty_label ?? "" } }));
          }
        }).finally(() => setScanning(null));
      }, 3500);
    } catch { setScanning(null); }
  };

  if (loading) return <div className="p-8 flex items-center gap-2 text-gray-400"><Loader2 size={16} className="animate-spin" />Loading assets…</div>;

  return (
    <>
      {showAdd && <AddAssetModal onClose={() => setShowAdd(false)} onAdd={a => setAssets(prev => [...prev, a])} />}
      <div className="p-8 max-w-5xl">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Asset Inventory</h1>
            <p className="text-sm text-gray-500 mt-0.5">{assets.length} system{assets.length !== 1 ? "s" : ""} in scope</p>
          </div>
          <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 bg-brand text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-brand-light transition-colors shadow-sm">
            <Plus size={14} /> Add Asset
          </button>
        </div>

        {assets.length === 0 ? (
          <div className="bg-white rounded-xl border border-dashed border-gray-300 py-16 text-center">
            <Server size={32} className="mx-auto mb-3 text-gray-300" />
            <p className="text-gray-500 font-medium">No assets yet</p>
            <p className="text-sm text-gray-400 mt-1 mb-4">Add a TLS endpoint, CBOM file, or SARIF report to get started</p>
            <button onClick={() => setShowAdd(true)} className="inline-flex items-center gap-2 bg-brand text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-brand-light transition-colors">
              <Plus size={14} /> Add your first asset
            </button>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-xs text-gray-500 uppercase tracking-wide border-b border-gray-100">
                <tr>
                  <th className="px-5 py-3 text-left">Asset</th>
                  <th className="px-4 py-3 text-left">Team</th>
                  <th className="px-4 py-3 text-left">Last Scanned</th>
                  <th className="px-4 py-3 text-center">Verdict</th>
                  <th className="px-4 py-3 text-left w-44">Score</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {assets.map(asset => {
                  const scan = scans[asset.id];
                  const isScanning = scanning === asset.id;
                  return (
                    <tr key={asset.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2.5">
                          <span className="shrink-0">{ASSET_ICONS[asset.asset_type] ?? <Server size={15} className="text-gray-400" />}</span>
                          <div>
                            <Link href={`/dashboard/assets/${asset.id}`} className="font-medium text-gray-900 hover:text-brand transition-colors">{asset.name}</Link>
                            <div className="text-xs text-gray-400 font-mono truncate max-w-[200px]">{asset.target}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        {asset.team
                          ? <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full font-medium">{asset.team}</span>
                          : <span className="text-gray-300 text-xs">—</span>}
                      </td>
                      <td className="px-4 py-3.5 text-xs text-gray-400">
                        {asset.last_scanned_at ? new Date(asset.last_scanned_at).toLocaleString() : <span className="text-gray-300">Never</span>}
                      </td>
                      <td className="px-4 py-3.5 text-center">
                        {isScanning
                          ? <Loader2 size={14} className="animate-spin text-gray-400 mx-auto" />
                          : scan ? <VerdictBadge verdict={scan.verdict as any} /> : <span className="text-gray-300 text-xs">—</span>}
                      </td>
                      <td className="px-4 py-3.5 w-44">
                        {!isScanning && scan ? <ScoreBar score={scan.score} label={scan.label} /> : null}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <button onClick={() => handleScan(asset.id)} disabled={isScanning}
                          className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand hover:text-brand-light disabled:opacity-40 transition-colors">
                          <RefreshCw size={12} className={isScanning ? "animate-spin" : ""} />
                          {isScanning ? "Scanning…" : "Scan Now"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
