"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { api, HttpError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@soc.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(email, password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof HttpError ? err.message : "Could not reach the SOC core");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="card w-full max-w-sm p-8">
        <p className="eyebrow">Deception SOC</p>
        <h1 className="mt-2 text-[32px] font-semibold leading-10 tracking-[-1.28px]">Sign in</h1>
        <p className="mt-1 text-body">Analyst access to the lab environment.</p>
        <label className="mt-6 block text-[14px] font-medium" htmlFor="email">Email</label>
        <input id="email" className="input mt-1" type="email" autoComplete="username" value={email}
          onChange={(e) => setEmail(e.target.value)} required />
        <label className="mt-4 block text-[14px] font-medium" htmlFor="password">Password</label>
        <input id="password" className="input mt-1" type="password" autoComplete="current-password" value={password}
          onChange={(e) => setPassword(e.target.value)} required />
        {error && <p role="alert" className="mt-4 rounded-[6px] bg-error-soft px-3 py-2 text-error">{error}</p>}
        <button className="btn btn-primary mt-6 w-full justify-center" disabled={busy} type="submit">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
