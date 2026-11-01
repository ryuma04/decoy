import type { Event, Severity } from "./types";

/**
 * Calculates the accurate severity level for an event based on the project's
 * threat intelligence rules and hard overrides (07 §6.3):
 * - Production touch: CRITICAL (Risk 95-100)
 * - Honeytoken hit/used: CRITICAL (Risk 90)
 * - Confirmed injection/theft: CRITICAL (Risk 85+)
 * - Authenticated K8s / execution: HIGH (Risk 60-74)
 * - Auth attempts / scanning: MEDIUM (Risk 25-49)
 * - General telemetry: LOW (Risk < 25)
 */
export function getEventSeverity(ev: Event): Severity {
  // If explicitly tagged in envelope or event
  const explicit = (ev as unknown as { severity?: string }).severity ||
    (ev.envelope as unknown as { severity?: string })?.severity;
  if (explicit && typeof explicit === "string") {
    const s = explicit.toLowerCase();
    if (s === "critical" || s === "high" || s === "medium" || s === "low") {
      return s as Severity;
    }
  }

  // 1. HARD CRITICAL: Any interaction with production environment
  if (ev.origin === "production") return "critical";

  // 2. HARD CRITICAL: Honeytoken touched or triggered
  if (ev.tokens && ev.tokens.length > 0) return "critical";
  if (ev.type === "token.used" || ev.type === "token.hit" || ev.service === "beacon") return "critical";

  const summary = (ev.summary || "").toLowerCase();
  const type = (ev.type || "").toLowerCase();

  // 3. HARD CRITICAL: Credential theft, shell breakouts, shadow files, AWS keys, SQLi/exploit
  if (
    summary.includes("stolen") ||
    summary.includes("credential") ||
    summary.includes(".aws") ||
    summary.includes("shadow") ||
    summary.includes("sudo") ||
    summary.includes("kubeconfig") ||
    summary.includes("injection") ||
    summary.includes("divert") ||
    summary.includes("exploit") ||
    type.includes("exploit") ||
    type.includes("theft") ||
    type.includes("breach")
  ) {
    return "critical";
  }

  // 4. HIGH: Authenticated K8s requests, command execution, database queries
  if (
    ev.service === "k8s" ||
    type === "k8s.api_request" ||
    type === "command.exec" ||
    type === "sql.query" ||
    ev.service === "dbadmin" ||
    summary.includes("cat ") ||
    summary.includes("curl ") ||
    summary.includes("wget ") ||
    summary.includes("download") ||
    summary.includes("login successful")
  ) {
    return "high";
  }

  // 5. MEDIUM: Authentication failures, recon probes, HTTP requests
  if (
    type.startsWith("auth.") ||
    type.includes("failed") ||
    type.includes("attempt") ||
    type === "http.request" ||
    summary.includes("recon") ||
    summary.includes("scan") ||
    summary.includes("probe")
  ) {
    return "medium";
  }

  return "low";
}

/**
 * Returns a numerical risk score (0-100) matching 07 §6 bands.
 */
export function getEventRiskScore(ev: Event): number {
  const sev = getEventSeverity(ev);
  switch (sev) {
    case "critical":
      if (ev.origin === "production") return 100;
      if (ev.tokens && ev.tokens.length > 0) return 90;
      return 85;
    case "high":
      return 65;
    case "medium":
      return 35;
    case "low":
    default:
      return 10;
  }
}
