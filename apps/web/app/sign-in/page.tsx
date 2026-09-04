"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { Brand, ErrorText } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";

export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      await dashboardClient().auth.signIn({ email, password });
      router.replace("/app");
    } catch (err) {
      setError(err instanceof Error ? err.message : "sign-in failed");
    } finally { setBusy(false); }
  }
  return (
    <div className="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
      <Brand />
      <h1 className="mt-8 text-3xl font-semibold">Sign in</h1>
      <form className="card mt-6 space-y-4 p-6" onSubmit={onSubmit}>
        <div><label className="label" htmlFor="signin-email">Email</label><input id="signin-email" className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></div>
        <div><label className="label" htmlFor="signin-password">Password</label><input id="signin-password" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} /></div>
        <ErrorText message={error} />
        <button className="btn w-full" disabled={busy} type="submit">{busy ? "Signing in…" : "Sign in"}</button>
      </form>
      <p className="mt-4 text-sm text-stone-500">No account? <Link href="/sign-up">Sign up</Link></p>
    </div>
  );
}
