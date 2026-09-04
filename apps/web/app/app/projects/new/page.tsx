"use client";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { ErrorText } from "@/components/ui";
import { dashboardClient, rememberProjectKeys } from "@/lib/clients";

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [plan, setPlan] = useState("free");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      const created = await dashboardClient().projects.create({ name, slug, plan_slug: plan });
      rememberProjectKeys(created.id, created.keys ?? []);
      router.replace(`/app/projects/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "create failed");
    } finally { setBusy(false); }
  }
  return (
    <div className="max-w-lg">
      <h1 className="text-3xl font-semibold">New project</h1>
      <form className="card mt-6 space-y-4 p-6" onSubmit={onSubmit}>
        <div><label className="label">Name</label><input className="input" value={name} onChange={(e) => setName(e.target.value)} required /></div>
        <div><label className="label">Slug</label><input className="input" value={slug} onChange={(e) => setSlug(e.target.value)} required /></div>
        <div>
          <label className="label">Plan</label>
          <select className="input" value={plan} onChange={(e) => setPlan(e.target.value)}>
            <option value="free">free</option>
            <option value="pro">pro</option>
          </select>
        </div>
        <ErrorText message={error} />
        <button className="btn" disabled={busy} type="submit">{busy ? "Creating…" : "Create project"}</button>
      </form>
    </div>
  );
}
