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
const SECRET_PREFIX = "beebox.project.secrets.";

export function rememberProjectKeys(projectId: string, keys: Array<{ kind?: string; secret?: string }>) {
  if (typeof window === "undefined") return;
  const secrets = keys.filter((key) => key.secret).map((key) => ({ kind: key.kind, secret: key.secret as string }));
  if (secrets.length) sessionStorage.setItem(SECRET_PREFIX + projectId, JSON.stringify(secrets));
  const pk = secrets.find((key) => key.kind === "publishable" || key.secret.startsWith("pk_"));
  if (pk) sessionStorage.setItem(PK_PREFIX + projectId, pk.secret);
}

export function readShownSecrets(projectId: string): Array<{ kind?: string; secret: string }> {
  if (typeof window === "undefined") return [];
  const raw = sessionStorage.getItem(SECRET_PREFIX + projectId);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function readPublishableKey(projectId: string): string {
  if (typeof window === "undefined") return "";
  return sessionStorage.getItem(PK_PREFIX + projectId) ?? "";
}

export function writePublishableKey(projectId: string, key: string) {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(PK_PREFIX + projectId, key);
}
