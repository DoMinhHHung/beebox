declare module "@beebox/js" {
  export class BeeBoxError extends Error {
    code: string;
    status: number;
  }
  export function createClient(opts: { publishableKey: string; baseUrl: string }): any;
  export function createDashboardClient(opts: { baseUrl: string }): any;
}
