import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: { extend: { colors: { ink: "#12110e", paper: "#f7f3ea", honey: "#e2a100" } } },
  plugins: [],
};
export default config;
