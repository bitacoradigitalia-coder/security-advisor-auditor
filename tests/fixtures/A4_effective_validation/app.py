x = input()
if x not in ("2 + 2", "3 + 3"):
    raise ValueError()
eval(x)
