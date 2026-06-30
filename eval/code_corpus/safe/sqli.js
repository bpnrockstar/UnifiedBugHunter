// SAFE variant of sqli.js — parameterized query, no injection.
// Negative case: the eval expects ZERO findings for this file.

function getUser(db, userId) {
  // SAFE: placeholder + bound parameter; the driver escapes the value.
  return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}

module.exports = { getUser };
