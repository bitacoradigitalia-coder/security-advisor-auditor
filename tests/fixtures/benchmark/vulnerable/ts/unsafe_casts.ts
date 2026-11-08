// VULNERABLE: casts inseguros de TypeScript
export function processPayload(payload: unknown): any {
  const data = payload as any;
  const forced = payload as unknown as Record<string, unknown>;
  return { data, forced };
}
