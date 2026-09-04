const configuredURL = process.env.NEXT_PUBLIC_BEEBOX_URL;
if (!configuredURL && process.env.NODE_ENV === "production") {
  throw new Error("NEXT_PUBLIC_BEEBOX_URL is required in production");
}
export const BEEBOX_URL = configuredURL ?? "http://127.0.0.1:8080";
