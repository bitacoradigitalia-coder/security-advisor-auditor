// Modelo de sesion tipado (codigo limpio)
export interface Session {
  readonly id: string;
  readonly expiresAt: Date;
}

export function isSessionActive(session: Session, now: Date): boolean {
  return session.expiresAt.getTime() > now.getTime();
}
