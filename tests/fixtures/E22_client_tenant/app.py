from flask import Flask, request, abort
from flask_login import current_user, login_required
app = Flask(__name__)
@app.route("/resource/<resource_id>")
def endpoint(resource_id):
    return Record.query.filter_by(id=resource_id, tenant_id=request.args["tenant"]).first()

