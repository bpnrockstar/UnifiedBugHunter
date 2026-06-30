// SAFE variant of command_injection.js — execFile with an argv array, no shell.
// Negative case: the eval expects ZERO findings for this file.

const { execFile } = require("child_process");

function ping(host, cb) {
  // SAFE: execFile passes args directly to the binary; no shell interpretation.
  execFile("ping", ["-c", "1", host], cb);
}

module.exports = { ping };
