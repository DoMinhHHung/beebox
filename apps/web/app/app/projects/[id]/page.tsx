"use client";
import { useParams, useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { ErrorText, JsonBlock, ProjectNav } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";

type Project = { id: string; name: string; slug: string; plan_slug: string; env: string };
type KeyRow = { id: string; kind: string; env: string; prefix: string };
type OriginRow = { id: string; origin: string };

export default function ProjectOverviewPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [project, setProject] = useState<Project | null>(null);
  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [origins, setOrigins] = useState<OriginRow[]>([]);
  const [modules, setModules] = useState<string[]>([]);
  const [origin, setOrigin] = useState("http://localhost:3000");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");

  async function reload() {
    const client = dashboardClient();
    const [p, k, o, m] = await Promise.all([
      client.projects.get(id), client.projects.keys(id), client.projects.origins.list(id), client.projects.modules.list(id),
    ]);
    setProject(p); setKeys(k.keys ?? []); setOrigins(o.origins ?? []); setModules(m.modules ?? []);
  }
  useEffect(() => { reload().catch((err: Error) => setError(err.message)); }, [id]);

  async function addOrigin(event: FormEvent) {
    event.preventDefault(); setError("");
    try {
      await dashboardClient().projects.origins.add(id, origin);
      await reload();
    } catch (err) { setError(err instanceof Error ? err.message : "origin failed"); }
  }
  async function handleRemoveOrigin(originId: string) {
    setError("");
    try {
      await dashboardClient().projects.origins.remove(id, originId);
      await reload();
    } catch (err) { setError(err instanceof Error ? err.message : "remove origin failed"); }
  }
  async function onDelete(event: FormEvent) {
    event.preventDefault(); setError("");
    try { await dashboardClient().projects.delete(id, confirmation); router.replace("/app"); }
    catch (err) { setError(err instanceof Error ? err.message : "delete failed"); }
  }
  if (error) return <div><ProjectNav id={id} /><ErrorText message={error} /></div>;
  if (!project) return <p className="text-sm text-stone-500">Loading project…</p>;
  return (
    <div>
      <ProjectNav id={id} />
      <div className="mb-6">
        <h1 className="text-3xl font-semibold">{project.name}</h1>
        <p className="text-sm text-stone-500">{project.slug} · {project.plan_slug} · {project.env}</p>
      </div>
      <ErrorText message={error} />
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="card p-5">
          <h2 className="mb-3 font-medium">Keys</h2>
          <p className="mb-3 text-sm text-stone-500">Secret values are shown once after create.</p>
          <ul className="space-y-2 text-sm">{keys.map((key) => <li key={key.id} className="rounded-xl bg-stone-50 px-3 py-2">{key.kind} · {key.env} · {key.prefix}</li>)}</ul>
        </section>
        <section className="card p-5">
          <h2 className="mb-3 font-medium">Allowed origins</h2>
          <form className="mb-3 flex gap-2" onSubmit={addOrigin}>
            <input className="input" value={origin} onChange={(e) => setOrigin(e.target.value)} />
            <button className="btn" type="submit">Add</button>
          </form>
          <ul className="space-y-2 text-sm">
            {origins.map((item) => (
              <li key={item.id} className="flex items-center justify-between rounded-xl bg-stone-50 px-3 py-2">
                <span>{item.origin}</span>
                <button className="text-red-600" type="button" onClick={() => handleRemoveOrigin(item.id)}>Remove</button>
              </li>
            ))}
          </ul>
        </section>
        <section className="card p-5"><h2 className="mb-3 font-medium">Modules</h2>{modules.length ? <JsonBlock value={modules} /> : <p className="text-sm text-stone-500">No modules listed.</p>}</section>
        <section className="card p-5">
          <h2 className="mb-3 font-medium">Delete project</h2>
          <p className="mb-3 text-sm text-stone-500">Type <code>delete project {project.name}</code></p>
          <form className="space-y-3" onSubmit={onDelete}>
            <input className="input" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} />
            <button className="btn w-full bg-red-700 hover:bg-red-800" type="submit">Delete</button>
          </form>
        </section>
      </div>
    </div>
  );
}
