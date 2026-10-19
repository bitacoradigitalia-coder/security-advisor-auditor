"""Deliberately unsafe static fixture. Do not import or execute."""
import pickle
import requests
import subprocess


def unsafe(user, url):
    eval(user)
    subprocess.run(user, shell=True)
    pickle.loads(user)
    requests.get(url, verify=False)
