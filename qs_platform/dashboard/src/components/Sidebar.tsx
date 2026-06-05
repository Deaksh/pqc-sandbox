"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";
import { Shield, Server, FileText, Bell, Settings, LogOut, LayoutDashboard, Link2, GitPullRequest } from "lucide-react";

const NAV = [
  { href: "/dashboard",            label: "Overview",       icon: LayoutDashboard },
  { href: "/dashboard/assets",     label: "Assets",         icon: Server },
  { href: "/dashboard/vendors",    label: "Vendor Risk",    icon: Link2 },
  { href: "/dashboard/reports",    label: "Compliance",     icon: FileText },
  { href: "/dashboard/alerts",     label: "Alerts",         icon: Bell },
  { href: "/dashboard/settings",   label: "Settings",       icon: Settings },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="w-56 bg-brand flex flex-col min-h-screen text-white shrink-0">
      <div className="px-5 py-5 border-b border-white/10">
        <div className="flex items-center gap-2">
          <Shield size={20} className="text-blue-300" />
          <span className="font-bold text-sm tracking-tight">QuantumShift</span>
        </div>
        <p className="text-xs text-white/50 mt-0.5">PQC Compliance Platform</p>
      </div>
      <nav className="flex-1 px-2 py-4 space-y-0.5">
        {NAV.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={clsx(
              "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
              (path === href || (href !== "/dashboard" && path.startsWith(href)))
                ? "bg-white/15 text-white"
                : "text-white/60 hover:bg-white/10 hover:text-white"
            )}
          >
            <Icon size={16} />
            {label}
          </Link>
        ))}
      </nav>
      <div className="px-4 py-4 border-t border-white/10">
        <button className="flex items-center gap-2 text-white/50 hover:text-white text-xs transition-colors">
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
