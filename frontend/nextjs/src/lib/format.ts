// Time helpers: store UTC, show IST (11 §Layout).
import { formatDistanceToNowStrict } from "date-fns";
import { formatInTimeZone } from "date-fns-tz";

export const IST = "Asia/Kolkata";

export function istTime(iso: string): string {
  return formatInTimeZone(iso, IST, "HH:mm:ss");
}

export function istFull(iso: string): string {
  return formatInTimeZone(iso, IST, "dd MMM yyyy, HH:mm:ss 'IST'");
}

export function ago(iso: string): string {
  return `${formatDistanceToNowStrict(new Date(iso))} ago`;
}
