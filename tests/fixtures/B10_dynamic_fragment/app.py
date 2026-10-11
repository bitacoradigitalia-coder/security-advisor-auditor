q = input()
cursor.execute(f"SELECT * FROM users ORDER BY {q}")
