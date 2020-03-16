import functools
import requests
from charm.toolbox.conversion import Conversion
from flask import Blueprint, render_template, redirect, url_for, request, json, flash
import os
from time import localtime
import dotenv
from user import cp_host, service_host, ap_host
from crypto_utils.conversions import SigConversion
from user.models.keys import KeyModel
from user.models.sessions import SessionModel
from user.utils.utils import handle_challenge, handle_response_hashes, prove_owner, validate_block, \
    handle_challenge_ap, validate_proof
import dateutil.parser

from time import process_time 



main = Blueprint('main', __name__, template_folder='templates')

dotenv.load_dotenv('../.env')


def token_required(func):
    """
    Helper wrapper that injects the access token that is needed for authentication into the protected methods.
    :param func: JWT protected function.
    :return:
    """
    @functools.wraps(func)
    def decorator_token_required(*args, **kwargs):
        # Get access_token
        first = SessionModel.query.first()
        headers = {}
        if first:
            access_token = SessionModel.query.first().access_token
            headers = {
                'Authorization': "Bearer " + access_token
            }
        return func(headers)
    return decorator_token_required


@main.route('/')
def index():
    """
    Renders the user main page.
    :return:
    """
    # Use os.getenv("key") to get environment variables
    app_name = os.getenv("APP_NAME")
    if not app_name:
        app_name = "User Interface"

    return render_template('index.html', name=app_name)


# TODO add expiry checking
@main.route('/generate_keys')
@token_required
def gen_keys(headers):
    """
    Renders the generate_keys.html page.
    :param headers:
    :return:
    """
    access_token = SessionModel.query.first()
    if access_token is None:
        return redirect(url_for('auth.login'))
    return render_template('generate_keys.html', now=localtime())


# TODO Save keys on the user side
@main.route("/generate_keys", methods=['POST'])
@token_required
def challenge_response_post(headers):

    """
    This method is called by the user frontend when the generate keys form has been filled out. It then initiates the
    blinding process with the CP. It receives the the proof hashes from the CP and saves them in the database.

    This is the first step the user must take to create credentials.
    """
    # Get the number of requested keys from the form, then generate the required number
    params = {
        'number': int(request.form.get('number')),
        'time': int(dateutil.parser.parse(request.form.get('time')).timestamp()),
        'policy': int(request.form.get('policy'))
    }


    """
    The user must initiate the interaction with the CP in order to blind the signatures. It sends a GET request
    to the following endpoint in order to receive (rnd, a, b1, b2) and the CP public key for the corresponding policy
    and time interval.
    """
    setup_keys_start = process_time()

    res = requests.get("http://%s:5000/setup_keys" % cp_host, params=params, headers=headers)

    setup_keys_end = process_time()

    f = open("time.txt", "a")
    f.write("setup_keys time:" + str(setup_keys_end - setup_keys_start)+ "\n")
    f.close()


    if res.status_code == 401:
        return redirect(url_for('auth.login'))

    try:
        # Generates the challenge response

        challenge_response_start = process_time()

        es = handle_challenge(res.json(), params.get('policy'))

        challenge_response_end = process_time()

        f = open("time.txt", "a")
        f.write("challenge_response time:" + str(challenge_response_end - challenge_response_start) + "\n")

        f.close()

        # Post keys to CP
        try:

            post_to_cp_start = process_time()


            res = requests.post("http://%s:5000/generate_proofs" % cp_host, json=json.dumps(es), headers=headers)

            post_to_cp_end = process_time()
            f = open("time.txt", "a")
            f.write("post_to_cp time:" + str(post_to_cp_end - post_to_cp_start) + "\n")
            f.close()



            if res.status_code == 201:
                # TODO remove hardcoded CP
                data = res.json()
                # The response hashes need to be saved with the corresponding policy at a given timestamp
                save_hash_start = process_time()

                handle_response_hashes(data, 2000, data.get('policy'))

                save_hash_end = process_time()


                f = open("time.txt", "a")
                f.write("save_hash  time:" + str(save_hash_end - save_hash_start) + "\n")
                f.close()

                flash("Keys have been generated", 'keygen_success')
                return render_template('generate_keys.html')
            else:
                return render_template('generate_keys.html')
        except Exception as e:
            flash(str(e), "post_keys")
            return render_template('generate_keys.html')
    except Exception as e:
        flash(str(e), "post_keys")
        return render_template('generate_keys.html')


@main.route("/access_service", methods=['GET'])
def access_service():
    """
    Renders the service_authenticate.html page.
    :return:
    """
    return render_template('service_authenticate.html')


@main.route("/access_service", methods=['POST'])
def access_service_post():
    # Get nonce from service
    res = requests.get('http://%s:5000/request' % service_host).json()
    service_y = res.get('y')

    # Setup parameters that are sent to the AP
    params = {
        'cp': int(request.form.get('cp')),
        'timestamp': int(dateutil.parser.parse(request.form.get('timestamp')).timestamp()),
        'policy': int(request.form.get('policy'))
    }

    # Request-certs CP_i

    request_certs_start = process_time()
    
    res = requests.get('http://%s:5000/request_certs' % ap_host, params=params)

    request_certs_end = process_time()

    f = open("time.txt", "a")
    f.write("request_certs time:" + str(request_certs_end - request_certs_start) + "\n")
    f.close()

    if res.status_code == 500:
        flash(res.json().get('message'), "access_service_error")
        return render_template('service_authenticate.html')
    


    # Get data from response and find corresponding keymodel
    data = res.json()
    key_model = KeyModel.query.filter_by(provider_type_=1, p_id_=params.get('cp'), policy_=params.get('policy'),
                                         interval_timestamp_=params.get('timestamp')).first()

    # Validate that block has not been altered


    try:

        validate_block_start = process_time()

        validate_block(data)

        validate_block_end = process_time()

        f = open("time.txt", "a")
        f.write("validate_block time:" + str(validate_block_end - validate_block_start) + "\n")
        f.close()
        
    except Exception as e:
        flash(str(e), "access_service_error")
        return render_template('service_authenticate.html')

    pubk = {
        'pubk': Conversion.OS2IP(key_model.public_key)
    }

    # Get the challenge from the AP in order to prove that the user owns a specific keypair
    request_challenge_own_keypair_start = process_time()

    res = requests.get('http://%s:5000/prove_owner' % ap_host, params=pubk)

    request_challenge_own_keypair_end = process_time()

    f = open("time.txt", "a")
    f.write("request_challenge_own_keypair time:" + str(request_challenge_own_keypair_end - request_challenge_own_keypair_start) + "\n")
    f.close()
    
    y = res.json().get('y')

    # Prove the user owns the private key corresponding to a set of proofs in the block
    # Proof consists of the signature of the private key on the nonce y and the blind signature on the public key
    try:
        (proof, proof_owner) = prove_owner(y, data, key_model.proof_hash)
        blind_signature = key_model.generate_blind_signature(proof.get('proofs'))

        proof_resp = json.dumps({
            'y': y,
            'signature': proof_owner[1],
            'blind_signature': json.dumps(SigConversion.convert_dict_strlist(blind_signature))
        })

        # Post the proofs

        post_proofs_start = process_time()


        res = requests.post('http://%s:5000/prove_owner' % ap_host, json=proof_resp, params=params)


        post_proofs_end = process_time()

        f = open("time.txt", "a")
        f.write("get_challenge_own_keypair time:" + str(post_proofs_end - post_proofs_start) + "\n")
        f.close()

        # Receive access token for AP
        access_info = res.json()
        headers = {
            'Authorization': "Bearer " + access_info.get('access')
        }

        # Request challenge from AP to issue blind signature
        request_challenge_issue_blind_signiture_start = process_time()

        challenge = requests.get('http://%s:5000/init_sig' % ap_host, headers=headers).json()

        request_challenge_issue_blind_signiture_end = process_time()

        f = open("time.txt", "a")
        f.write("request_challenge_issue_blind_signiture_ time:" + str(request_challenge_issue_blind_signiture_end - request_challenge_issue_blind_signiture_start) + "\n")
        f.close()

        # Handle challenge
        try:
            challenge['timestamp'] = params.get('timestamp')

            ap_challenge_response_start = process_time()

            e = json.dumps(handle_challenge_ap(challenge, params.get('policy'), service_y))

            ap_challenge_response_end = process_time()

            f = open("time.txt", "a")
            f.write("ap_challenge_response time:" + str(ap_challenge_response_end - ap_challenge_response_start) + "\n")

            f.close()
            # Send Response


            send_ap_challenge_response_start = process_time()
            
            proof_response = requests.post('http://%s:5000/generate_proof' % ap_host, json=e, headers=headers)

            send_ap_challenge_response_end = process_time()

            f = open("time.txt", "a")
            f.write("send_ap_challenge_response time:" + str(send_ap_challenge_response_end - send_ap_challenge_response_start) + "\n")

            f.close()

            proofs = proof_response.json()

            # Validate Response
            try:
                validate_proof_start = process_time()

                validate_proof(proofs)

                validate_proof_end = process_time()

                f = open("time.txt", "a")
                f.write("validate_proof time:" + str(validate_proof_end - validate_proof_start) + "\n")

                f.close()

            except Exception as e:
                flash(str(e), "access_service_error")
                return render_template('service_authenticate.html')

            # Get AP Keymodel
            ap_key_model = KeyModel.query.filter_by(p_id_=2000, provider_type_=2).first()

            # Build signature
            build_signature_start = process_time()

            blind_signature = ap_key_model.generate_blind_signature(proofs.get('proof'))

            build_signature_end = process_time()

            f = open("time.txt", "a")

            f.write("build_signature_time:" + str(build_signature_end - build_signature_start) + "\n")

            f.close()

            # Send signature on service_y to service


            resp_service = {
                'y': service_y,
                'sig': json.dumps(SigConversion.convert_dict_strlist(blind_signature)),
                'policy': params.get('policy'),
                'timestamp': params.get('timestamp')
            }




            # Get access to service

            access_to_service_start = process_time()

            res = requests.post('http://%s:5000/response' % service_host, json=json.dumps(resp_service))

            access_to_service_end = process_time()

            f = open("time.txt", "a")
            f.write("access_to_service_time:" + str(access_to_service_end - access_to_service_start) + "\n")
            f.close()


            if res.status_code == 200:
                return render_template('thanks.html')
            else:
                message = res.json().get('message')
                flash(message, "access_service_error")
                return render_template('service_authenticate.html')
        except Exception as e:
            flash(str(e), "access_service_error")
            return render_template('service_authenticate.html')
    except Exception as e:
        flash(str(e), "access_service_error")
        return render_template('service_authenticate.html')


@main.route('/thanks')
def thanks():
    return render_template('thanks.html')
