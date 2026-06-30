// SAFE variant of xss.js — textContent never parses markup.
// Negative case: the eval expects ZERO findings for this file.

function showName(name) {
  const el = document.getElementById("greeting");
  // SAFE: textContent treats the value as text, not HTML — no script execution.
  el.textContent = "Hello " + name;
}

module.exports = { showName };
