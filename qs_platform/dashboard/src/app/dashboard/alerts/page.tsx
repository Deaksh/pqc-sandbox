"use client";

import { AlertTriangle, CheckCircle2, Bell } from "lucide-react";

const MOCK_ALERTS = [
  { id: "1", severity: "HIGH", type: "verdict_regression", asset: "API Gateway", detail: "Verdict regressed from CAUTION to BLOCKED. New OpenSSL 1.x dependency detected in CI build.", time: "2 hours ago", acked: false },
  { id: "2", severity: "HIGH", type: "new_vulnerable_algo", asset: "Payments Core", detail: "New quantum-vulnerable algorithm detected: RSA-2048 (PKCS#1 v1.5) introduced in payments-lib v2.3.1.", time: "Yesterday", acked: false },
  { id: "3", severity: "MEDIUM", type: "cert_expiry", asset: "Internet Banking API", detail: "TLS certificate expires in 14 days. Renew with PQC-capable CA to avoid disruption.", time: "3 days ago", acked: true },
];

export default function AlertsPage() {
  return (
    <div className="p-8 max-w-3xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Drift Alerts</h1>
        <p className="text-sm text-gray-500">New vulnerable crypto, verdict regressions, certificate events</p>
      </div>

      <div className="space-y-3">
        {MOCK_ALERTS.map(alert => (
          <div key={alert.id} className={`bg-white rounded-xl border p-4 shadow-sm flex gap-4 ${alert.acked ? "opacity-60" : ""} ${alert.severity === "HIGH" ? "border-red-200" : "border-yellow-200"}`}>
            <div className="shrink-0 mt-0.5">
              {alert.acked
                ? <CheckCircle2 size={18} className="text-gray-300" />
                : <AlertTriangle size={18} className={alert.severity === "HIGH" ? "text-red-500" : "text-yellow-500"} />
              }
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${alert.severity === "HIGH" ? "bg-red-100 text-red-700" : "bg-yellow-100 text-yellow-700"}`}>
                  {alert.severity}
                </span>
                <span className="text-xs text-gray-500 font-mono">{alert.asset}</span>
                <span className="text-xs text-gray-400">{alert.time}</span>
              </div>
              <p className="text-sm text-gray-700">{alert.detail}</p>
            </div>
            {!alert.acked && (
              <button className="shrink-0 text-xs font-semibold text-brand hover:text-brand-light self-start transition-colors">
                Acknowledge
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
