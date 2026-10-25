import type { ApprovalStatus, Decision } from "../types";
import { Check, Clock3, FileSearch, ShieldOff, X } from "lucide-react";

export function StatusBadge({ status }: { status: Decision | ApprovalStatus | "INSPECTED" }) {
  const Icon = status === "INSPECTED" ? FileSearch : status === "ALLOW" || status === "APPROVED" ? Check : status === "BLOCK" || status === "REJECTED" ? (status === "BLOCK" ? ShieldOff : X) : Clock3;
  const label = status === "REQUIRE_APPROVAL" ? "REQUIRES APPROVAL" : status;
  const tone = status === "INSPECTED" ? "inspection" : status === "ALLOW" || status === "APPROVED" ? "allow" : status === "BLOCK" || status === "REJECTED" ? "block" : "review";
  return <span className={`status-badge ${tone}`}><Icon size={14} strokeWidth={2.4} aria-hidden="true"/>{label}</span>;
}
