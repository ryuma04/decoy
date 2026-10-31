// Typed client for the analyst API (04 §B). The browser only calls /api/...; next.config.ts forwards to core.
import type { ApiError, Event, Page, User } from "@/lib/types";

export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (body as ApiError | null)?.error;
    throw new HttpError(res.status, err?.code ?? "http_error", err?.message ?? `HTTP ${res.status}`);
  }
  return body as T;
}

export const api = {
  login: (email: string, password: string) =>
    call<{ user: User }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => call<void>("/auth/logout", { method: "POST" }),
  me: () => call<{ user: User }>("/auth/me"),
  listEvents: (params: Record<string, string> = {}) =>
    call<Page<Event>>(`/events?${new URLSearchParams(params).toString()}`),
  getEvent: (id: string) => call<Event>(`/events/${encodeURIComponent(id)}`),
};
