"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BEEBOX_URL } from "@/lib/env";

export function Brand({ href = "/" }: { href?: string }) {
  return (
    <Link href={href} className="flex items-center gap-2 font-semibold tracking-tight">
      <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-honey text-ink">B</span>
      BeeBox
    </Link>
  );
}

export function ErrorText({ message }: { message?: string }) {
  if (!message) return null;
  return <p className="text-sm text-red-600">{message}</p>;
}

export function Shell({ email, onSignOut, children }: { email?: string; onSignOut?: () => void; children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <Brand href="/app" />
          <div className="flex items-center gap-3 text-sm text-stone-600">
            <span className="hidden sm:inline">{email}</span>
            {onSignOut ? <button className="btn-secondary" onClick={onSignOut} type="button">Sign out</button> : null}
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
    </div>
  );
}

export function ProjectNav({ id }: { id: string }) {
  const pathname = usePathname();
  const items = [
    ["Overview", `/app/projects/${id}`],
    ["Fields", `/app/projects/${id}/fields`],
    ["OAuth", `/app/projects/${id}/oauth`],
    ["Playground", `/app/projects/${id}/playground`],
    ["Data", `/app/projects/${id}/data`],
  ];
  return (
    <nav className="mb-6 flex flex-wrap gap-2">
      {items.map(([label, href]) => (
        <Link key={href} href={href} className={`rounded-full px-3 py-1.5 text-sm ${pathname === href ? "bg-ink text-white" : "bg-white text-stone-600 ring-1 ring-stone-200"}`}>
          {label}
        </Link>
      ))}
    </nav>
  );
}

export function GatewayHint() {
  return <p className="text-xs text-stone-500">Gateway {BEEBOX_URL}</p>;
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="overflow-auto rounded-xl bg-ink p-4 text-xs text-amber-100">{JSON.stringify(value, null, 2)}</pre>;
}
