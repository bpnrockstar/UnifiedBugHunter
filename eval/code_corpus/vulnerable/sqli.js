// # INTENTIONALLY VULNERABLE — eval fixture, do not deploy
// SQL injection — user input concatenated into a query string.
// Ground-truth finding: vuln_class=sqli on the db.query line below.

function getUser(db, userId) {
  // VULN: template-literal interpolation straight into SQL — SQLi sink.
  return db.query(`SELECT * FROM users WHERE id = '${userId}'`);
}

module.exports = { getUser };
