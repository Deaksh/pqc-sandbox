"use client";
import clsx from "clsx";

const color = (score: number) =>
  score <= 30 ? "bg-green-500" : score <= 60 ? "bg-yellow-500" : score <= 80 ? "bg-orange-500" : "bg-red-600";

export function ScoreBar({ score, label }: { score: number; label?: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden">
        <div className={clsx("h-full rounded-full transition-all", color(score))} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs font-bold text-gray-600 w-12 text-right">{score}/100</span>
      {label && <span className="text-xs font-semibold text-gray-500">{label}</span>}
    </div>
  );
}
