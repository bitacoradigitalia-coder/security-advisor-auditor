// VULNERABLE: consulta SQL concatenada (SQLi)
export function findUser(db, userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.exec(query);
}
