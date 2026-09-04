const SESSION_KEY = "beebox.session";

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
  let session = readSession();

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
    const headers = publicHeaders(options.headers);
    const res = await fetch(`${root}${path}`, {
      method: options.method || "GET",
      headers,
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
    session = persistSession(result && result.session);
    return result;
  }

  async function signIn({ email, password } = {}) {
    const result = await request("/v1/auth/sign-in", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    session = persistSession(result && result.session);
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
      session = persistSession(null);
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

function readSession() {
  const store = storage();
  if (!store) {
    return null;
  }
  const raw = store.getItem(SESSION_KEY);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function persistSession(next) {
  const store = storage();
  if (!next) {
    if (store) {
      store.removeItem(SESSION_KEY);
    }
    return null;
  }
  if (store) {
    store.setItem(SESSION_KEY, JSON.stringify(next));
  }
  return next;
}
