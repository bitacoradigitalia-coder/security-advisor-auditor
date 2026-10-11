import subprocess
x = input()
if x not in ("date", "whoami"):
    raise ValueError()
subprocess.run(x, shell=True)
