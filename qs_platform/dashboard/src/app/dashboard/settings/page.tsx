"use client";

import { Shield, Key, Users, Bell } from "lucide-react";

export default function SettingsPage() {
  return (
    <div className="p-8 max-w-2xl">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Settings</h1>

      <div className="space-y-4">
        {[
          { icon: Shield, title: "SSO Configuration", desc: "Connect your identity provider (SAML 2.0 / OIDC). Supports Okta, Azure AD, Google Workspace.", badge: "Enterprise" },
          { icon: Key, title: "API Keys", desc: "Generate API keys for CI/CD pipeline integration. Keys have org-scoped permissions.", badge: null },
          { icon: Users, title: "Team Management", desc: "Invite team members, assign roles (Owner, Admin, Analyst, Viewer), manage access.", badge: null },
          { icon: Bell, title: "Alert Webhooks", desc: "Send drift alerts to Slack, PagerDuty, or any webhook endpoint.", badge: "Pro" },
        ].map(({ icon: Icon, title, desc, badge }) => (
          <div key={title} className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm flex items-start gap-4">
            <Icon size={20} className="text-brand mt-0.5 shrink-0" />
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-semibold text-sm">{title}</h3>
                {badge && <span className="text-xs bg-brand/10 text-brand px-2 py-0.5 rounded-full font-semibold">{badge}</span>}
              </div>
              <p className="text-xs text-gray-500">{desc}</p>
            </div>
            <button className="text-xs font-semibold text-brand hover:text-brand-light shrink-0 transition-colors">Configure</button>
          </div>
        ))}
      </div>

      <div className="mt-8 p-4 bg-gray-50 rounded-xl border border-gray-200 text-xs text-gray-500">
        <p className="font-semibold mb-1 text-gray-700">Privacy & Telemetry</p>
        <p>QuantumShift Platform processes all cryptographic data locally within your infrastructure.
           No scan data, asset inventories, or compliance reports are transmitted to external servers.
           The open-source pqc-sandbox core (Apache 2.0) is zero-telemetry by design.</p>
      </div>
    </div>
  );
}
