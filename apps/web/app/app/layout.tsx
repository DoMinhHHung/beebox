"use client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Shell } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [ready, setReady] = useState(false);
  useEffect(() => {
    dashboardClient().auth.me().then((account: { email?: string }) => {
      setEmail(account.email ?? "");
      setReady(true);
    }).catch(() => router.replace("/sign-in"));
  }, [router]);
  async function onSignOut() {
    await dashboardClient().auth.signOut();
    router.replace("/sign-in");
  }
  if (!ready) return <div className="p-10 text-sm text-stone-500">Loading…</div>;
  return <Shell email={email} onSignOut={onSignOut}>{children}</Shell>;
}
