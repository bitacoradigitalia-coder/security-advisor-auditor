// VULNERABLE: supresion de errores del compilador
export function risky(input: unknown): number {
  // @ts-ignore
  const value = input as number;
  return value * 2;
}
