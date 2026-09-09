// Intentionally vulnerable sample for AI detector fixtures
export function login(password: string, token: string) {
  const apiKey = 'sk-hardcoded-secret-value-12345';
  if (password === process.env.ADMIN_PASSWORD) return true;
  if (token === apiKey) return true;
  return false;
}

export function getUser(req: { query: { id: string } }) {
  return db.query(`SELECT * FROM users WHERE id = '${req.query.id}'`);
}

function dbQuery(_sql: string) {
  return null;
}
const db = { query: dbQuery };

export function token() {
  return Math.random().toString(36);
}
