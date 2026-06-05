import clsx from "clsx";
import type { Verdict } from "@/lib/api";

const META: Record<Verdict, { label: string; cls: string }> = {
  GO:      { label: "GO",      cls: "bg-green-100 text-green-800 border-green-300" },
  CAUTION: { label: "CAUTION", cls: "bg-yellow-100 text-yellow-800 border-yellow-300" },
  BLOCKED: { label: "BLOCKED", cls: "bg-red-100 text-red-800 border-red-300" },
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const m = META[verdict] ?? META.CAUTION;
  return (
    <span className={clsx("inline-block px-2 py-0.5 rounded-full text-xs font-bold border", m.cls)}>
      {m.label}
    </span>
  );
}
