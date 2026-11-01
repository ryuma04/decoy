"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, HttpError } from "@/lib/api";
import { StreamProvider, useStream, useStreamStatus } from "@/lib/stream";
import type { Incident, Overview, User } from "@/lib/types";
import {
  LayoutDashboard,
  Activity,
  Users,
  ShieldAlert,
  Compass,
  KeyRound,
  Server,
  Sliders,
  LogOut,
  Sparkles,
  Search,
  AlertTriangle,
  Shuffle,
} from "@/components/icons";

export default function SocLayout({ children }: { children: React.ReactNode }) {
  return (
    <StreamProvider>
      <SocShell>{children}</SocShell>
    </StreamProvider>
  );
}

function SocShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [toast, setToast] = useState<{ id: string; title: string; severity: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    api.me()
      .then((r) => setUser(r.user))
      .catch((e) => {
        if (e instanceof HttpError && e.status === 401 && process.env.NEXT_PUBLIC_USE_MOCKS !== "1") {
          router.replace("/login");
        }
      });

    api.getOverview().then(setOverview).catch(() => undefined);
  }, [router]);

  // Listen for critical incidents via SSE for the demo toast
  useStream<Incident>("incident", (inc) => {
    if (inc.severity === "critical" || inc.severity === "high") {
      setToast({ id: inc.incident_id, title: inc.title, severity: inc.severity });
      setTimeout(() => setToast(null), 8000);
    }
  });

  async function handleLogout() {
    await api.logout().catch(() => undefined);
    router.replace("/login");
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    router.push(`/events?q=${encodeURIComponent(searchQuery.trim())}`);
  }

  const navItems = [
    { href: "/", label: "Overview", icon: LayoutDashboard },
    { href: "/events", label: "Live Events", icon: Activity },
    { href: "/actors", label: "Actors", icon: Users },
    { href: "/incidents", label: "Incidents", icon: ShieldAlert },
    { href: "/maze", label: "Deception Maze", icon: Compass },
    { href: "/diversions", label: "Diversions", icon: Shuffle },
    { href: "/honeytokens", label: "Honeytokens", icon: KeyRound },
    { href: "/sensors", label: "Sensors", icon: Server },
    { href: "/scorer", label: "Scorer Engine", icon: Sliders },
  ];

  return (
    <div className="flex min-h-screen bg-canvas text-ink">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-hairline bg-elevated">
        <div className="flex h-14 items-center justify-between border-b border-hairline px-5">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-ink text-canvas font-mono font-bold text-[13px]">
              D
            </div>
            <div>
              <span className="text-[14px] font-semibold tracking-tight text-ink block leading-none">
                Deception SOC
              </span>
              <span className="text-[10px] font-mono text-mute tracking-wider uppercase">
                Lab Environment
              </span>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-3">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 rounded-[8px] px-3 py-2 text-[13px] font-medium transition-colors ${
                  active
                    ? "bg-canvas text-ink font-semibold shadow-2xs border border-hairline"
                    : "text-body hover:bg-hairline-soft hover:text-ink"
                }`}
              >
                <Icon className={`h-4 w-4 ${active ? "text-ink" : "text-mute"}`} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* User footer */}
        <div className="border-t border-hairline p-3">
          <div className="flex items-center justify-between rounded-lg p-2 bg-canvas/60 border border-hairline-soft">
            <div className="flex flex-col">
              <span className="text-[12px] font-medium text-ink truncate max-w-[140px]">
                {user?.email ?? "analyst@soc.local"}
              </span>
              <span className="text-[10px] font-mono text-mute uppercase">
                {user?.role ?? "analyst"}
              </span>
            </div>
            <button
              onClick={handleLogout}
              className="rounded p-1.5 text-mute hover:bg-hairline hover:text-ink"
              title="Log out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex flex-1 flex-col pl-64">
        {/* Topbar */}
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-hairline bg-elevated/90 px-6 backdrop-blur-md">
          {/* Global Search */}
          <form onSubmit={handleSearch} className="relative w-80">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-mute" />
            <input
              type="text"
              placeholder="Search IP, actor (ACT-0007), token..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8.5 w-full rounded-[6px] border border-hairline bg-canvas pl-9 pr-3 text-[12px] font-mono text-ink placeholder:text-mute focus:outline-none focus:ring-2 focus:ring-link"
            />
          </form>

          {/* Badges & Live Status */}
          <div className="flex items-center gap-3">
            {/* ML Status Badge */}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-mono font-medium ${
                overview?.ml_input !== false
                  ? "bg-purple-50 text-purple-700 border-purple-200"
                  : "bg-gray-50 text-gray-500 border-gray-200"
              }`}
              title="Input-risk classifier model state"
            >
              <Sparkles className="h-3 w-3" />
              <span>ML: {overview?.ml_input !== false ? "Active" : "Off"}</span>
            </span>

            {/* Narration Badge */}
            <span
              className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-mono font-medium bg-blue-50 text-blue-700 border-blue-200"
              title="Activity narration pipeline"
            >
              <span>Narration: {overview?.narration === "llm" ? "AI Model" : "Template"}</span>
            </span>

            {/* SSE Live Indicator */}
            <LiveIndicator />
          </div>
        </header>

        {/* Demo Toast Notification */}
        {toast && (
          <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-[12px] border border-red-200 bg-red-50 p-4 shadow-xl animate-in slide-in-from-bottom duration-300">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-red-600 text-white">
              <AlertTriangle className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] uppercase font-bold text-red-700">
                  {toast.severity} Alert Triggered
                </span>
              </div>
              <p className="text-[13px] font-semibold text-ink">{toast.title}</p>
            </div>
            <Link
              href={`/incidents/${toast.id}`}
              className="btn btn-primary ml-2 text-[12px]"
              onClick={() => setToast(null)}
            >
              Inspect
            </Link>
          </div>
        )}

        {/* Page Body */}
        <main className="flex-1 p-6 max-w-[1440px] w-full mx-auto">{children}</main>
      </div>
    </div>
  );
}

function LiveIndicator() {
  const status = useStreamStatus();
  const configs = {
    live: { label: "Live SSE", dot: "bg-emerald-500", text: "text-emerald-700 bg-emerald-50 border-emerald-200" },
    connecting: { label: "Connecting", dot: "bg-amber-500", text: "text-amber-700 bg-amber-50 border-amber-200" },
    reconnecting: { label: "Reconnecting", dot: "bg-red-500", text: "text-red-700 bg-red-50 border-red-200" },
  };

  const current = configs[status] ?? configs.connecting;

  return (
    <div className={`flex items-center gap-2 rounded-full border px-2.5 py-1 text-[11px] font-mono font-medium ${current.text}`}>
      <span className={`h-2 w-2 rounded-full ${current.dot} animate-pulse`} />
      <span>{current.label}</span>
    </div>
  );
}
