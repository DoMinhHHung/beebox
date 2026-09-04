"use client";
import { useParams } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { ErrorText, JsonBlock, ProjectNav } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";

type Collection = { id: string; name: string; slug: string };
type Document = { id: string; data: Record<string, unknown> };

export default function DataPage() {
  const { id } = useParams<{ id: string }>();
  const [collections, setCollections] = useState<Collection[]>([]);
  const [selected, setSelected] = useState("");
  const [documents, setDocuments] = useState<Document[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [json, setJson] = useState('{"title":"hello"}');
  const [error, setError] = useState("");
  const [editingDocs, setEditingDocs] = useState<Record<string, string>>({});

  async function loadCollections() {
    const res = await dashboardClient().projects.collections.list(id);
    const items = res.collections ?? [];
    setCollections(items);
    if (!selected && items[0]) setSelected(items[0].id);
  }
  async function loadDocuments(collectionId: string) {
    if (!collectionId) { setDocuments([]); return; }
    const res = await dashboardClient().projects.documents.list(id, collectionId);
    const docs = res.documents ?? [];
    setDocuments(docs);
    const editing: Record<string, string> = {};
    docs.forEach((doc) => { editing[doc.id] = JSON.stringify(doc.data, null, 2); });
    setEditingDocs(editing);
  }
  async function handleSaveDocument(docId: string) {
    setError("");
    try {
      const draftJson = editingDocs[docId] ?? "{}";
      const parsed = JSON.parse(draftJson);
      await dashboardClient().projects.documents.update(id, selected, docId, parsed);
      await loadDocuments(selected);
    } catch (err) { setError(err instanceof Error ? err.message : "save document failed"); }
  }
  async function handleDeleteDocument(docId: string) {
    setError("");
    try {
      await dashboardClient().projects.documents.delete(id, selected, docId);
      await loadDocuments(selected);
    } catch (err) { setError(err instanceof Error ? err.message : "delete document failed"); }
  }
  useEffect(() => { loadCollections().catch((err: Error) => setError(err.message)); }, [id]);
  useEffect(() => { if (selected) loadDocuments(selected).catch((err: Error) => setError(err.message)); }, [id, selected]);

  async function createCollection(event: FormEvent) {
    event.preventDefault(); setError("");
    try {
      const created = await dashboardClient().projects.collections.create(id, { name, slug });
      setName(""); setSlug(""); await loadCollections(); setSelected(created.id);
    } catch (err) { setError(err instanceof Error ? err.message : "create collection failed"); }
  }
  async function createDocument(event: FormEvent) {
    event.preventDefault(); setError("");
    try {
      await dashboardClient().projects.documents.create(id, selected, JSON.parse(json));
      await loadDocuments(selected);
    } catch (err) { setError(err instanceof Error ? err.message : "create document failed"); }
  }
  return (
    <div>
      <ProjectNav id={id} />
      <h1 className="mb-2 text-3xl font-semibold">Data</h1>
      <p className="mb-6 text-sm text-stone-500">Owner console uses own_. Free 2 collections / 100 docs. Pro 20 / 10000.</p>
      <ErrorText message={error} />
      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        <section className="card p-5">
          <h2 className="mb-3 font-medium">Collections</h2>
          <form className="mb-4 space-y-2" onSubmit={createCollection}>
            <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
            <input className="input" placeholder="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} />
            <button className="btn w-full" type="submit">Create</button>
          </form>
          <ul className="space-y-2">
            {collections.map((item) => (
              <li key={item.id}>
                <button className={`w-full rounded-xl px-3 py-2 text-left text-sm ${selected === item.id ? "bg-ink text-white" : "bg-stone-50"}`} type="button" onClick={() => setSelected(item.id)}>
                  {item.name}<span className="block text-xs opacity-70">{item.slug}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
        <section className="space-y-4">
          <form className="card space-y-3 p-5" onSubmit={createDocument}>
            <h2 className="font-medium">New document</h2>
            <textarea className="input min-h-28 font-mono" value={json} onChange={(e) => setJson(e.target.value)} />
            <button className="btn" disabled={!selected} type="submit">Create document</button>
          </form>
          {documents.map((doc) => (
            <article key={doc.id} className="card space-y-3 p-5">
              <div className="flex items-center justify-between gap-3">
                <code className="text-xs text-stone-500">{doc.id}</code>
                <div className="flex gap-2">
                  <button className="btn-secondary" type="button" onClick={() => handleSaveDocument(doc.id)}>Save</button>
                  <button className="btn-secondary text-red-600" type="button" onClick={() => handleDeleteDocument(doc.id)}>Delete</button>
                </div>
              </div>
              <textarea className="input min-h-32 font-mono text-sm" value={editingDocs[doc.id] ?? ""} onChange={(e) => setEditingDocs((prev) => ({ ...prev, [doc.id]: e.target.value }))} />
            </article>
          ))}
        </section>
      </div>
    </div>
  );
}
