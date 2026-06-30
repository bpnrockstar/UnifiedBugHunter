// # INTENTIONALLY VULNERABLE — eval fixture, do not deploy
// OS command injection — user input passed to a shell via child_process.exec.
// Ground-truth finding: vuln_class=command-injection on the exec line below.

const { exec } = require("child_process");

function ping(host, cb) {
  // VULN: exec runs the string in a shell — host can inject `; rm -rf /`.
  exec("ping -c 1 " + host, cb);
}

module.exports = { ping };
