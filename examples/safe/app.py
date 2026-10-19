"""Static negative fixture; no target execution during audit."""
import json
import subprocess


def parse(raw):
    return json.loads(raw)


def constant_command():
    return subprocess.run(['echo', 'example'], shell=False)


password = 'example'
