from flask import Flask, request, abort
from flask_login import current_user, login_required
app = Flask(__name__)
@app.route("/resource/<resource_id>")
@external_access_policy
def endpoint(resource_id):
    return Record.query.get(resource_id)

