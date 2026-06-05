"use client";

import { useEffect, useState } from "react";
import { api, OrgSnapshot } from "@/lib/api";
import { ScoreBar } from "@/components/ScoreBar";
import {
  RadialBarChart, RadialBar, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from "recharts";
import { AlertTriangle, CheckCircle2, XCircle, Activity } from "lucide-react";

function KpiCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-widest text-gray-500 mb-1">{label}</p>
      <p className={`text-3xl font-black ${color ?? "text-gray-900"}`}>{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

// Mock trend data — replace with historical snapshots from API
const TREND = [
  { month: "Jan", readiness: 22, blocked: 8, caution: 12 },
  { month: "Feb", readiness: 35, blocked: 6, caution: 10 },
  { month: "Mar", readiness: 48, blocked: 4, caution: 9 },
  { month: "Apr", readiness: 61, blocked: 3, caution: 7 },
  { month: "May", readiness: 74, blocked: 2, caution: 5 },
  { month: "Jun", readiness: 82, blocked: 1, caution: 4 },
];

export default function DashboardPage() {
  const [snapshot, setSnapshot] = useState<OrgSnapshot | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getSnapshot()
      .then(setSnapshot)
      .catch(() => {
        // Use mock data when API is not running
        setSnapshot({
          org_id: "org_demo",
          snapshot_at: new Date().toISOString(),
          total_assets: 24,
          scanned_assets: 22,
          go_count: 14,
          caution_count: 6,
          blocked_count: 2,
          avg_difficulty_score: 42,
          readiness_pct: 63.6,
          teams: {
            "Payments": { team: "Payments", total: 8, go: 4, caution: 3, blocked: 1, avg_score: 51 },
            "Identity": { team: "Identity", total: 6, go: 5, caution: 1, blocked: 0, avg_score: 28 },
            "API Gateway": { team: "API Gateway", total: 5, go: 3, caution: 1, blocked: 1, avg_score: 55 },
            "Mobile": { team: "Mobile", total: 3, go: 2, caution: 1, blocked: 0, avg_score: 35 },
          },
        });
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-8 text-gray-400">Loading dashboard...</div>;
  if (!snapshot) return null;

  const teamData = Object.values(snapshot.teams).map(t => ({
    name: t.team,
    GO: t.go,
    CAUTION: t.caution,
    BLOCKED: t.blocked,
  }));

  const radialData = [
    { name: "Readiness", value: snapshot.readiness_pct, fill: "#16a34a" },
  ];

  return (
    <div className="p-8 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">PQC Migration Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">
          {snapshot.scanned_assets} of {snapshot.total_assets} assets scanned ·
          Last updated {new Date(snapshot.snapshot_at).toLocaleDateString()}
        </p>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <KpiCard
          label="PQC Readiness"
          value={`${snapshot.readiness_pct.toFixed(0)}%`}
          sub={`${snapshot.go_count} systems ready`}
          color="text-green-600"
        />
        <KpiCard
          label="Avg. Difficulty"
          value={`${snapshot.avg_difficulty_score.toFixed(0)}/100`}
          sub="lower is better"
          color="text-blue-600"
        />
        <KpiCard
          label="CAUTION"
          value={snapshot.caution_count}
          sub="systems need planning"
          color="text-yellow-600"
        />
        <KpiCard
          label="BLOCKED"
          value={snapshot.blocked_count}
          sub="immediate action required"
          color="text-red-600"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Radial readiness */}
        <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm flex flex-col items-center">
          <h2 className="text-sm font-semibold text-gray-700 mb-2">Org Readiness</h2>
          <ResponsiveContainer width={180} height={180}>
            <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="90%"
              startAngle={90} endAngle={90 - 360 * snapshot.readiness_pct / 100}
              data={radialData}>
              <RadialBar dataKey="value" cornerRadius={8} />
            </RadialBarChart>
          </ResponsiveContainer>
          <p className="text-3xl font-black text-green-600 -mt-4">
            {snapshot.readiness_pct.toFixed(0)}%
          </p>
          <p className="text-xs text-gray-400">systems at GO verdict</p>
        </div>

        {/* Team breakdown bar */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Readiness by Team</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={teamData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
              <XAxis dataKey="name" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="GO" stackId="a" fill="#16a34a" radius={[0, 0, 0, 0]} />
              <Bar dataKey="CAUTION" stackId="a" fill="#d97706" />
              <Bar dataKey="BLOCKED" stackId="a" fill="#dc2626" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Trend */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-8">
        <h2 className="text-sm font-semibold text-gray-700 mb-4">Readiness Trend (6-month)</h2>
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={TREND} margin={{ left: -20, right: 8 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
            <XAxis dataKey="month" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} unit="%" />
            <Tooltip formatter={(v) => `${v}%`} />
            <Bar dataKey="readiness" fill="#2a5298" radius={[4, 4, 0, 0]} name="Readiness %" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Per-team detail table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">Team Detail</h2>
        </div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-xs text-gray-500 uppercase tracking-wide">
            <tr>
              <th className="px-5 py-3 text-left">Team</th>
              <th className="px-4 py-3 text-center">Assets</th>
              <th className="px-4 py-3 text-center text-green-700">GO</th>
              <th className="px-4 py-3 text-center text-yellow-700">CAUTION</th>
              <th className="px-4 py-3 text-center text-red-700">BLOCKED</th>
              <th className="px-5 py-3 text-left">Avg. Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {Object.values(snapshot.teams).map(t => (
              <tr key={t.team} className="hover:bg-gray-50">
                <td className="px-5 py-3 font-medium">{t.team}</td>
                <td className="px-4 py-3 text-center text-gray-600">{t.total}</td>
                <td className="px-4 py-3 text-center font-semibold text-green-600">{t.go}</td>
                <td className="px-4 py-3 text-center font-semibold text-yellow-600">{t.caution}</td>
                <td className="px-4 py-3 text-center font-semibold text-red-600">{t.blocked}</td>
                <td className="px-5 py-3 w-48">
                  <ScoreBar score={Math.round(t.avg_score)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
