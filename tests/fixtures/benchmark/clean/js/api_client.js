// Cliente HTTP de referencia (codigo limpio, sin vulnerabilidades)
const BASE_URL = "https://api.example.com/v1";

export async function getUser(userId) {
  const response = await fetch(BASE_URL + "/users/" + encodeURIComponent(userId), {
    method: "GET",
    headers: { "Accept": "application/json" },
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error("Respuesta invalida del servidor");
  }
  return response.json();
}
