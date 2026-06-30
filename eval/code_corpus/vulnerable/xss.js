// # INTENTIONALLY VULNERABLE — eval fixture, do not deploy
// DOM XSS — untrusted value written to innerHTML.
// Ground-truth finding: vuln_class=xss on the innerHTML line below.

function showName(name) {
  const el = document.getElementById("greeting");
  // VULN: innerHTML with attacker-controlled string parses & runs markup — XSS sink.
  el.innerHTML = "Hello " + name;
}

module.exports = { showName };
