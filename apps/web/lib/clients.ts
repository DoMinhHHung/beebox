"use client";

import { createClient, createDashboardClient } from "@beebox/js";
import { BEEBOX_URL } from "./env";

export function dashboardClient() {
  return createDashboardClient({ baseUrl: BEEBOX_URL });
}

export function runtimeClient(publishableKey: string) {
  return createClient({ publishableKey, baseUrl: BEEBOX_URL });
}

const PK_PREFIX = "beebox.project.pk.";

export function rememberProjectKeys(projectId: string, keys: Array<{ kind?: string; secret?: string }>) {
  if (typeof window === "undefined") return;
  const pk = keys.find((key) => (key.kind === "publishable" || key.secret?.startsWith("pk_")) && key.secret);
  if (pk?.secret) sessionStorage.setItem(PK_PREFIX + projectId, pk.secret);
}

export function readPublishableKey(projectId: string): string {
  if (typeof window === "undefined") return "";
  return sessionStorage.getItem(PK_PREFIX + projectId) ?? "";
}

export function writePublishableKey(projectId: string, key: string) {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(PK_PREFIX + projectId, key);
}
