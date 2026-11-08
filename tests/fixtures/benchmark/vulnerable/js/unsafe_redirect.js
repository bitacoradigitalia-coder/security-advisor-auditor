// VULNERABLE: redireccion con destino controlado por el usuario
export function goToPage(target) {
  window.location.href = target;
}
