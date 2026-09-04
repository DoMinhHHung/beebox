"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ErrorText, GatewayHint } from "@/components/ui";
import { dashboardClient } from "@/lib/clients";

type Project = { id: string; name: string; slug: string; plan_slug: string };

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    dashboardClient().projects.list().then((res: { projects?: Project[] }) => setProjects(res.projects ?? [])).catch((err: Error) => setError(err.message));
  }, []);
  return (
    <div>
      <div className="mb-6 flex items-end justify-between gap-4">
        <div><h1 className="text-3xl font-semibold">Projects</h1><GatewayHint /></div>
        <Link className="btn" href="/app/projects/new">New project</Link>
      </div>
      <ErrorText message={error} />
      <div className="grid gap-4 md:grid-cols-2">
        {projects.map((project) => (
          <Link key={project.id} href={`/app/projects/${project.id}`} className="card p-5 hover:border-honey">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-medium">{project.name}</h2>
              <span className="rounded-full bg-stone-100 px-2 py-0.5 text-xs uppercase">{project.plan_slug}</span>
            </div>
            <p className="mt-2 text-sm text-stone-500">{project.slug}</p>
          </Link>
        ))}
        {projects.length === 0 && !error ? <p className="text-sm text-stone-500">No projects yet.</p> : null}
      </div>
    </div>
  );
}
