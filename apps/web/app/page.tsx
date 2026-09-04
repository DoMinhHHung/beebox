import Link from "next/link";
import { Brand, GatewayHint } from "@/components/ui";

export default function HomePage() {
  return (
    <div className="mx-auto flex min-h-screen max-w-5xl flex-col px-6 py-10">
      <header className="flex items-center justify-between">
        <Brand />
        <div className="flex gap-3">
          <Link className="btn-secondary" href="/sign-in">Sign in</Link>
          <Link className="btn" href="/sign-up">Sign up</Link>
        </div>
      </header>
      <section className="mt-24 max-w-2xl">
        <p className="mb-3 text-sm font-medium uppercase tracking-[0.2em] text-honey">Control plane</p>
        <h1 className="text-5xl font-semibold leading-tight">Backend ready. You write the frontend.</h1>
        <p className="mt-5 max-w-xl text-lg text-stone-600">
          Create a project, configure fields and OAuth, copy the publishable key, then try runtime auth in the playground.
        </p>
        <div className="mt-8 flex gap-3">
          <Link className="btn" href="/sign-up">Create owner account</Link>
          <Link className="btn-secondary" href="/app">Open dashboard</Link>
        </div>
        <div className="mt-10"><GatewayHint /></div>
      </section>
    </div>
  );
}
