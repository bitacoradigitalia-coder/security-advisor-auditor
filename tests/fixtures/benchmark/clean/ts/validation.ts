// Validacion de entrada tipada (codigo limpio)
export function parseUserId(raw: string): number | null {
  const value = Number.parseInt(raw, 10);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}
