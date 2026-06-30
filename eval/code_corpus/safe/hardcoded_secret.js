// SAFE variant of hardcoded_secret.js — token read from the environment.
// Negative case: the eval expects ZERO findings for this file.

function authHeader() {
  // SAFE: credential injected at runtime; nothing sensitive in source.
  return { Authorization: "Bearer " + process.env.API_TOKEN };
}

module.exports = { authHeader };
