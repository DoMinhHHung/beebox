"use client";
import { useParams } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { ErrorText, ProjectNav } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";
import { extraFields, OAUTH_SLUGS } from "@/lib/oauth";

type OAuthState = { client_id: string; client_secret: string; redirect_uri: string; enabled: boolean; extra: Record<string, string>; configured?: boolean };
const blank = (): OAuthState => ({ client_id: "", client_secret: "", redirect_uri: "", enabled: true, extra: {} });

export default function OAuthPage() {
  const { id } = useParams<{ id: string }>();
  const [slug, setSlug] = useState("google");
  const [form, setForm] = useState<OAuthState>(blank());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  const extras = useMemo(() => extraFields(slug), [slug]);
  useEffect(() => {
    let ignore = false;
    setForm(blank());
    setError("");
    setOk("");
    setLoading(true);
    dashboardClient().projects.oauth.get(id, slug).then((res: OAuthState) => {
      if (ignore) return;
      setForm({ client_id: res.client_id ?? "", client_secret: "", redirect_uri: res.redirect_uri ?? "", enabled: Boolean(res.enabled), extra: res.extra ?? {}, configured: res.configured });
      setLoading(false);
    }).catch(() => {
      if (ignore) return;
      setForm(blank());
      setLoading(false);
    });
    return () => { ignore = true; };
  }, [id, slug]);
  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (loading) return;
    setError(""); setOk("");
    try {
      const res = await dashboardClient().projects.oauth.put(id, slug, form);
      setForm({ ...form, client_secret: "", configured: res.configured, extra: res.extra ?? form.extra });
      setOk("Saved credentials. Secret is never returned.");
    } catch (err) { setError(err instanceof Error ? err.message : "save failed"); }
  }
  return (
    <div>
      <ProjectNav id={id} />
      <h1 className="mb-2 text-3xl font-semibold">OAuth credentials</h1>
      <p className="mb-6 text-sm text-stone-500">Pro plan only. GET never returns the client secret.</p>
      <div className="mb-4 flex flex-wrap gap-2">
        {OAUTH_SLUGS.map((item) => (
          <button key={item} className={`rounded-full px-3 py-1.5 text-sm ${slug === item ? "bg-ink text-white" : "bg-white ring-1 ring-stone-200"}`} type="button" onClick={() => setSlug(item)}>{item}</button>
        ))}
      </div>
      <ErrorText message={error} />
      {ok ? <p className="mb-3 text-sm text-emerald-700">{ok}</p> : null}
      <form className="card max-w-xl space-y-4 p-6" onSubmit={onSubmit}>
        <p className="text-sm text-stone-500">{loading ? "Loading..." : form.configured ? "Secret configured." : "No secret stored yet."}</p>
        <div><label className="label">Client ID</label><input className="input" value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} disabled={loading} /></div>
        <div><label className="label">Client secret</label><input className="input" type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} placeholder="leave blank to keep current" disabled={loading} /></div>
        <div><label className="label">Redirect URI</label><input className="input" value={form.redirect_uri} onChange={(e) => setForm({ ...form, redirect_uri: e.target.value })} disabled={loading} /></div>
        {extras.map((field) => (
          <div key={field.key}>
            <label className="label">{field.label}</label>
            {field.textarea ? (
              <textarea className="input min-h-32 font-mono" value={form.extra[field.key] ?? ""} onChange={(e) => setForm({ ...form, extra: { ...form.extra, [field.key]: e.target.value } })} disabled={loading} />
            ) : (
              <input className="input" value={form.extra[field.key] ?? ""} onChange={(e) => setForm({ ...form, extra: { ...form.extra, [field.key]: e.target.value } })} disabled={loading} />
            )}
          </div>
        ))}
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} disabled={loading} />Enabled</label>
        <button className="btn" type="submit" disabled={loading}>Save {slug}</button>
      </form>
    </div>
  );
}
