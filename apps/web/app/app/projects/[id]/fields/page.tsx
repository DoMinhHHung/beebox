"use client";
import { useParams } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { ErrorText, ProjectNav } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";

type FieldRow = { name: string; type: string; required: boolean; unique_per_project: boolean };
const emptyField = (): FieldRow => ({ name: "", type: "string", required: false, unique_per_project: false });

export default function FieldsPage() {
  const { id } = useParams<{ id: string }>();
  const [fields, setFields] = useState<FieldRow[]>([emptyField()]);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");
  useEffect(() => {
    dashboardClient().projects.fields.list(id).then((res: { fields?: FieldRow[] }) => {
      const next = res.fields ?? [];
      setFields(next.length ? next : [emptyField()]);
    }).catch((err: Error) => setError(err.message));
  }, [id]);
  async function onSubmit(event: FormEvent) {
    event.preventDefault(); setError(""); setOk("");
    try {
      const res = await dashboardClient().projects.fields.replace(id, fields.filter((field) => field.name.trim()));
      setFields(res.fields?.length ? res.fields : [emptyField()]);
      setOk("Saved fields.");
    } catch (err) { setError(err instanceof Error ? err.message : "save failed"); }
  }
  return (
    <div>
      <ProjectNav id={id} />
      <h1 className="mb-2 text-3xl font-semibold">User fields</h1>
      <p className="mb-6 text-sm text-stone-500">Replace-all PUT. Reserved: email, password, id, project_id, env, session.</p>
      <ErrorText message={error} />
      {ok ? <p className="mb-3 text-sm text-emerald-700">{ok}</p> : null}
      <form className="space-y-4" onSubmit={onSubmit}>
        {fields.map((field, index) => (
          <div key={index} className="card grid gap-3 p-4 md:grid-cols-4">
            <div><label className="label">Name</label><input className="input" value={field.name} onChange={(e) => setFields((rows) => rows.map((row, i) => i === index ? { ...row, name: e.target.value } : row))} /></div>
            <div>
              <label className="label">Type</label>
              <select className="input" value={field.type} onChange={(e) => setFields((rows) => rows.map((row, i) => i === index ? { ...row, type: e.target.value } : row))}>
                <option value="string">string</option><option value="number">number</option><option value="boolean">boolean</option><option value="date">date</option>
              </select>
            </div>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={field.required} onChange={(e) => setFields((rows) => rows.map((row, i) => i === index ? { ...row, required: e.target.checked } : row))} />required</label>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={field.unique_per_project} onChange={(e) => setFields((rows) => rows.map((row, i) => i === index ? { ...row, unique_per_project: e.target.checked } : row))} />unique</label>
          </div>
        ))}
        <div className="flex gap-2">
          <button className="btn-secondary" type="button" onClick={() => setFields((rows) => [...rows, emptyField()])}>Add field</button>
          <button className="btn" type="submit">Save fields</button>
        </div>
      </form>
    </div>
  );
}
