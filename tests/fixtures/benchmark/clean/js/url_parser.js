// Parseo seguro de URLs con la API estandar (codigo limpio)
export function extractQueryParam(rawUrl, key) {
  const parsed = new URL(rawUrl);
  return parsed.searchParams.get(key);
}
