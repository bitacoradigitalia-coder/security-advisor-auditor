table = input()
if table not in ("users", "orders"):
    raise ValueError()
cursor.execute(f"SELECT * FROM {table}")
