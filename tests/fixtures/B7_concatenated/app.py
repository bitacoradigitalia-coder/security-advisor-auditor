x = input()
q = "SELECT * FROM users WHERE id = " + x
cursor.execute(q)
