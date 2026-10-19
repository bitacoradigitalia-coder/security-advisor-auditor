from flask import Flask, request, abort
from flask_login import current_user, login_required
app = Flask(__name__)
@app.route("/resource/<resource_id>")
@login_required
def endpoint(resource_id):
    obj = Record.query.get(resource_id)
    if obj.owner_id != current_user.id:
        abort(403)
    return obj

