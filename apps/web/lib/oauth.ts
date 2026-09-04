export const OAUTH_SLUGS = [
  "apple","gitlab","linkedin","slack","twitch","facebook","google","microsoft","github","x","oidc",
] as const;

export function extraFields(slug: string): Array<{ key: string; label: string; textarea?: boolean }> {
  switch (slug) {
    case "apple":
      return [
        { key: "team_id", label: "Team ID" },
        { key: "key_id", label: "Key ID" },
        { key: "p8", label: ".p8 private key", textarea: true },
      ];
    case "microsoft":
      return [{ key: "tenant", label: "Tenant" }];
    case "gitlab":
      return [{ key: "base", label: "GitLab base URL" }];
    case "oidc":
      return [{ key: "issuer", label: "Issuer" }];
    default:
      return [];
  }
}
