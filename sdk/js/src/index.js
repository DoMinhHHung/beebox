const SESSION_KEY = "beebox.session";
const OWNER_SESSION_KEY = "beebox.owner.session";

export class BeeBoxError extends Error {
  constructor(code, message, status) {
    super(message);
    this.name = "BeeBoxError";
    this.code = code;
    this.status = status;
  }
}

export function createClient({ publishableKey, baseUrl }) {
  if (!publishableKey) {
    throw new BeeBoxError("invalid_input", "publishableKey is required", 400);
  }
  if (!baseUrl) {
    throw new BeeBoxError("invalid_input", "baseUrl is required", 400);
  }

  const root = String(baseUrl).replace(/\/+$/, "");
  let session = readStored(SESSION_KEY);

  function publicHeaders(extra) {
    const headers = {
      Accept: "application/json",
      "X-BeeBox-Publishable-Key": publishableKey,
    };
    if (String(publishableKey).startsWith("pk_")) {
      headers.Authorization = `Bearer ${publishableKey}`;
    }
    return { ...headers, ...extra };
  }

  async function request(path, options = {}) {
    return jsonRequest(`${root}${path}`, {
      ...options,
      headers: publicHeaders(options.headers),
    });
  }

  async function signUp({ email, password, data } = {}) {
    const body = { email, password };
    if (data !== undefined) {
      body.data = data;
    }
    const result = await request("/v1/auth/sign-up", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    session = persistStored(SESSION_KEY, result && result.session);
    return result;
  }

  async function signIn({ email, password } = {}) {
    const result = await request("/v1/auth/sign-in", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    session = persistStored(SESSION_KEY, result && result.session);
    return result;
  }

  async function signOut() {
    const token = sessionToken(session);
    const headers = {};
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    try {
      await request("/v1/auth/sign-out", { method: "POST", headers });
    } finally {
      session = persistStored(SESSION_KEY, null);
    }
  }

  async function me() {
    const token = sessionToken(session);
    if (!token) {
      throw new BeeBoxError("unauthorized", "missing session", 401);
    }
    return request("/v1/auth/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  async function config() {
    return request("/v1/client/config");
  }

  return {
    auth: { signUp, signIn, signOut, me },
    config,
    getSession() {
      return session;
    },
  };
}

export function createDashboardClient({ baseUrl }) {
  if (!baseUrl) {
    throw new BeeBoxError("invalid_input", "baseUrl is required", 400);
  }

  const root = String(baseUrl).replace(/\/+$/, "");
  let session = readStored(OWNER_SESSION_KEY);

  function ownerHeaders(extra) {
    const headers = { Accept: "application/json" };
    const token = sessionToken(session);
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return { ...headers, ...extra };
  }

  async function request(path, options = {}) {
    return jsonRequest(`${root}${path}`, {
      ...options,
      headers: ownerHeaders(options.headers),
    });
  }

  async function signUp({ email, password } = {}) {
    const result = await request("/v1/owner/sign-up", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    session = persistStored(OWNER_SESSION_KEY, result && result.session);
    return result;
  }

  async function signIn({ email, password } = {}) {
    const result = await request("/v1/owner/sign-in", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    session = persistStored(OWNER_SESSION_KEY, result && result.session);
    return result;
  }

  async function signOut() {
    try {
      await request("/v1/owner/sign-out", { method: "POST" });
    } finally {
      session = persistStored(OWNER_SESSION_KEY, null);
    }
  }

  async function me() {
    const token = sessionToken(session);
    if (!token) {
      throw new BeeBoxError("unauthorized", "missing session", 401);
    }
    return request("/v1/owner/me");
  }

  return {
    auth: { signUp, signIn, signOut, me },
    projects: {
      list: () => request("/v1/projects"),
      get: (id) => request(`/v1/projects/${id}`),
      create: (body) =>
        request("/v1/projects", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      update: (id, body) =>
        request(`/v1/projects/${id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      delete: (id, confirmation) =>
        request(`/v1/projects/${id}`, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirmation }),
        }),
      keys: (id) => request(`/v1/projects/${id}/keys`),
      origins: {
        list: (id) => request(`/v1/projects/${id}/origins`),
        add: (id, origin) =>
          request(`/v1/projects/${id}/origins`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ origin }),
          }),
        remove: (id, originId) =>
          request(`/v1/projects/${id}/origins/${originId}`, { method: "DELETE" }),
      },
      modules: {
        list: (id) => request(`/v1/projects/${id}/modules`),
        replace: (id, modules) =>
          request(`/v1/projects/${id}/modules`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ modules }),
          }),
      },
      fields: {
        list: (id) => request(`/v1/projects/${id}/fields`),
        replace: (id, fields) =>
          request(`/v1/projects/${id}/fields`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ fields }),
          }),
      },
      oauth: {
        get: (id, slug) => request(`/v1/projects/${id}/oauth/${slug}`),
        put: (id, slug, body) =>
          request(`/v1/projects/${id}/oauth/${slug}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          }),
      },
      collections: {
        list: (id) => request(`/v1/projects/${id}/collections`),
        create: (id, body) =>
          request(`/v1/projects/${id}/collections`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          }),
      },
      documents: {
        list: (id, collectionId) =>
          request(`/v1/projects/${id}/collections/${collectionId}/documents`),
        get: (id, collectionId, documentId) =>
          request(`/v1/projects/${id}/collections/${collectionId}/documents/${documentId}`),
        create: (id, collectionId, data) =>
          request(`/v1/projects/${id}/collections/${collectionId}/documents`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ data }),
          }),
        update: (id, collectionId, documentId, data) =>
          request(`/v1/projects/${id}/collections/${collectionId}/documents/${documentId}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ data }),
          }),
        delete: (id, collectionId, documentId) =>
          request(`/v1/projects/${id}/collections/${collectionId}/documents/${documentId}`, {
            method: "DELETE",
          }),
      },
    },
    getSession() {
      return session;
    },
  };
}

async function jsonRequest(url, options = {}) {
  const res = await fetch(url, {
    method: options.method || "GET",
    headers: options.headers,
    body: options.body,
  });
  if (res.status === 204) {
    return null;
  }
  const text = await res.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new BeeBoxError("internal_error", "invalid json response", res.status);
    }
  }
  if (!res.ok) {
    const err = payload && payload.error ? payload.error : {};
    throw new BeeBoxError(err.code || "internal_error", err.message || res.statusText, res.status);
  }
  return payload;
}

function sessionToken(session) {
  if (!session) {
    return "";
  }
  if (typeof session === "string") {
    return session;
  }
  return session.token || "";
}

function storage() {
  try {
    if (typeof localStorage === "undefined") {
      return null;
    }
    return localStorage;
  } catch {
    return null;
  }
}

function readStored(key) {
  const store = storage();
  if (!store) {
    return null;
  }
  const raw = store.getItem(key);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function persistStored(key, next) {
  const store = storage();
  if (!next) {
    if (store) {
      store.removeItem(key);
    }
    return null;
  }
  if (store) {
    store.setItem(key, JSON.stringify(next));
  }
  return next;
}
