// Manejo de formularios con FormData (codigo limpio)
export function setupSubmit(form, onSubmit) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    onSubmit(data);
  });
}
