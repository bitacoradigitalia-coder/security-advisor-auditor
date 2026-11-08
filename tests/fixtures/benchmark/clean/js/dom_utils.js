// Utilidades DOM seguras (codigo limpio)
export function renderUserName(container, name) {
  const heading = document.createElement("h2");
  heading.textContent = name;
  container.replaceChildren(heading);
}

export function clearElement(element) {
  element.replaceChildren();
}
