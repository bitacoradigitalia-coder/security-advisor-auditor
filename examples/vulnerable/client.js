// Deliberately unsafe static fixture; never execute it.
function render(userHtml, element) {
  element.innerHTML = userHtml;
}
