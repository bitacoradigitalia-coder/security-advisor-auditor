// VULNERABLE: Math.random para tokens de sesion
export function createSessionToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}
