"use client";
import { useParams } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { ErrorText, JsonBlock, ProjectNav } from "@/components/ui";
import { dashboardClient, readPublishableKey, runtimeClient, writePublishableKey } from "@/lib/clients";
import { BEEBOX_URL } from "@/lib/env";

type FieldDef = { name: string; type: string; required?: boolean };
type Config = { fields?: FieldDef[]; auth?: { oauth?: string[] } };

export default function PlaygroundPage() {
  const { id } = useParams<{ id: string }>();
  const [pk, setPk] = useState("");
  const [config, setConfig] = useState<Config | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [dataValues, setDataValues] = useState<Record<string, string>>({});
  const [lastRequest, setLastRequest] = useState<unknown>(null);
  const [lastResponse, setLastResponse] = useState<unknown>(null);
  const [error, setError] = useState("");
  const fields = config?.fields ?? [];
  const oauth = config?.auth?.oauth ?? [];
  useEffect(() => {
    setPk(readPublishableKey(id));
    dashboardClient().projects.fields.list(id).then((res: { fields?: FieldDef[] }) => {
      setConfig((prev) => ({ ...(prev ?? {}), fields: res.fields ?? [] }));
    }).catch(() => undefined);
  }, [id]);
  const client = useMemo(() => (pk.startsWith("pk_") ? runtimeClient(pk) : null), [pk]);
  async function run(label: string, body: unknown, fn: () => Promise<unknown>) {
    setError(""); setLastRequest({ label, body });
    try { setLastResponse((await fn()) ?? { ok: true }); }
    catch (err) {
      const message = err instanceof Error ? err.message : "request failed";
      setError(message); setLastResponse({ error: { message } });
    }
  }
  function dataPayload() {
    const data: Record<string, string | number | boolean> = {};
    for (const field of fields) {
      const raw = dataValues[field.name] ?? "";
      if (field.required && raw === "") {
        throw new Error(`Field ${field.name} is required`);
      }
      if (raw === "") continue;
      data[field.name] = field.type === "number" ? Number(raw) : field.type === "boolean" ? raw === "true" || raw === "1" : raw;
    }
    return data;
  }
  async function loadConfig(event: FormEvent) {
    event.preventDefault();
    writePublishableKey(id, pk);
    if (!client) { setError("publishable key required"); return; }
    const requestedId = id;
    const requestedPk = pk;
    await run("GET /v1/client/config", null, () => client.config());
    try {
      const cfg = await client.config();
      if (requestedId !== id || requestedPk !== pk) return;
      setConfig(cfg);
    } catch { /* shown */ }
  }
  return (
    <div>
      <ProjectNav id={id} />
      <h1 className="mb-2 text-3xl font-semibold">Playground</h1>
      <p className="mb-6 text-sm text-stone-500">Calls gateway with pk_ / sess_. Allow this origin on the project first.</p>
      <ErrorText message={error} />
      <form className="card mb-6 space-y-3 p-5" onSubmit={loadConfig}>
        <label className="label">Publishable key</label>
        <input className="input font-mono" value={pk} onChange={(e) => setPk(e.target.value)} placeholder="pk_..." />
        <button className="btn" type="submit">GET /v1/client/config</button>
      </form>
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="card space-y-4 p-5">
          <h2 className="font-medium">Password auth</h2>
          <div><label className="label">Email</label><input className="input" value={email} onChange={(e) => setEmail(e.target.value)} /></div>
          <div><label className="label">Password</label><input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
          {fields.map((field) => (
            <div key={field.name}>
              <label className="label">{field.name}{field.required ? " *" : ""}</label>
              <input className="input" value={dataValues[field.name] ?? ""} onChange={(e) => setDataValues((current) => ({ ...current, [field.name]: e.target.value }))} />
            </div>
          ))}
          <div className="flex flex-wrap gap-2">
            <button className="btn" type="button" onClick={() => {
              if (!client) return;
              try {
                const payload = dataPayload();
                run("POST /v1/auth/sign-up", { email, password, data: payload }, () => client.auth.signUp({ email, password, data: payload }));
              } catch (err) {
                setError(err instanceof Error ? err.message : "validation failed");
              }
            }}>Sign up</button>
            <button className="btn-secondary" type="button" onClick={() => client && run("POST /v1/auth/sign-in", { email, password }, () => client.auth.signIn({ email, password }))}>Sign in</button>
            <button className="btn-secondary" type="button" onClick={() => client && run("GET /v1/auth/me", null, () => client.auth.me())}>Me</button>
            <button className="btn-secondary" type="button" onClick={() => client && run("POST /v1/auth/sign-out", null, () => client.auth.signOut())}>Sign out</button>
          </div>
        </section>
        <section className="card space-y-4 p-5">
          <h2 className="font-medium">OAuth start</h2>
          <div className="flex flex-wrap gap-2">
            {oauth.length ? oauth.map((slug) => (
              <a key={slug} className="btn-secondary" href={`${BEEBOX_URL}/v1/auth/oauth/${slug}/start?pk=${encodeURIComponent(pk)}`} target="_blank" rel="noreferrer">{slug}</a>
            )) : <p className="text-sm text-stone-500">No OAuth slugs in config yet.</p>}
          </div>
          <div><p className="label">Request</p><JsonBlock value={lastRequest} /></div>
          <div><p className="label">Response</p><JsonBlock value={lastResponse} /></div>
        </section>
      </div>
    </div>
  );
}
