// # INTENTIONALLY VULNERABLE — eval fixture, do not deploy
// Hardcoded secret — an API token committed in source.
// Ground-truth finding: vuln_class=hardcoded-secret on the apiToken line below.
// NOTE: this is a fabricated, non-functional token used only as an eval fixture.

// VULN: long-lived credential baked into source — hardcoded secret.
const apiToken = "fake0eval0fixture0DO0NOT0DEPLOY0a1b2c3d4e5f6a7b8c9d0e1f2";

function authHeader() {
  return { Authorization: "Bearer " + apiToken };
}

module.exports = { authHeader };
