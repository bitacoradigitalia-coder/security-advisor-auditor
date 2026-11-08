// VULNERABLE: innerHTML con datos no sanitizados (XSS)
export function showGreeting(name) {
  const banner = document.getElementById("greeting");
  banner.innerHTML = "<strong>Hola " + name + "</strong>";
}
