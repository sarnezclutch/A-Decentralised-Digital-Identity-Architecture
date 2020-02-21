import os
import time
import dateutil
from flask import Blueprint, render_template, redirect, url_for, request, flash, json, jsonify
from flask_jwt_extended import jwt_required
from cp.models.PolicyModel import PolicyModel
from cp.models.PolicyPoolModel import PolicyPoolModel
from cp.utils.sig_utils import setup_key_handler, gen_proofs_handler
from cp.utils.ledger_utils import publish_pool
from cp import create_app

main = Blueprint('main', __name__, template_folder='templates')


@main.route('/')
def index():
    app_name = os.getenv("APP_NAME")
    if not app_name:
        app_name = "Certification Provider Interface"

    return render_template('index.html', name=app_name)


@main.route('/gen_policies')
def gen_policies():
    return render_template('generate_policies.html')


@main.route('/gen_policies', methods=['POST'])
def gen_policies_post():
    i = request.form.get('interval')
    life = request.form.get('lifetime')
    ds = request.form.get('description')

    PolicyModel(publication_interval=i, lifetime=life, description=ds).save_to_db()
    flash("Policy has been added", 'gen_policies_success')
    return redirect(url_for('main.gen_policies'))


@main.route('/setup_keys')
@jwt_required
def setup_keys():
    time = request.args.get('time')
    n = request.args.get('number')
    policy = request.args.get('policy')

    if (time is None) or (n is None) or (policy is None):
        resp = jsonify({
            'message': "Bad Request: Required parameters are not set. Please check that you have set "
                       "'time', 'number', and 'policy'"
        })

        return resp, 400
    else:
        try:
            resp = json.dumps(setup_key_handler(timestamp=int(time), number=int(n), policy=int(policy)))
            return resp, 201
        except Exception:
            resp = jsonify({
                'message': "Couldn't find policy"
            })

            return resp, 500


@main.route('/publish_policies')
def publish():
    return render_template('publish.html')


@main.route('/publish_policies', methods=['POST'])
def publish_policies():  # Test method to publish a pool manually
    policy = int(request.form.get('policy'))
    timestamp = int(dateutil.parser.parse(request.form.get('timestamp')).timestamp())

    if publish_pool(policy, timestamp):
        flash("Proofs published", 'pub_policies_success')
        return redirect(url_for('main.publish_policies'))
    else:
        flash("Proofs not published. Possibly because the policy does not exist, incorrect timestamp, or API error",
              'pub_policies_fail')
        return redirect(url_for('main.publish_policies'))


@main.route('/generate_proofs', methods=['POST'])
@jwt_required
def generate_proofs():
    data = json.loads(request.json)

    if not data:  # If no file is submitted flash message
        flash('Please submit file', 'post_keys')
        resp = jsonify({
            'message': "Bad Request"
        })
        return resp, 400
    else:
        es = data.get('es')
        policy = data.get('policy')

        resp = json.dumps(gen_proofs_handler(policy, es))
        return resp, 201


@main.route('/thanks')
@jwt_required
def thanks():
    return render_template('thanks.html')


# Called every 10s to publish pools to the ledger
def publish_policy_pools():
    app = create_app()

    with app.app_context():
        timestamp = int(time.time() // 60 * 60)  # Time rounded down to nearest minute
        policy_pools = PolicyPoolModel.query.filter_by(timestamp=timestamp).all()

        for policy_pool in policy_pools:
            # Publish pool to ledger
            publish_pool(policy_pool.policy, timestamp)
