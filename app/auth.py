from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn import options_to_json
from webauthn.helpers import parse_authentication_credential_json
from webauthn.helpers.parse_registration_credential_json import parse_registration_credential_json
from webauthn.helpers.structs import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, RegistrationCredential, \
    PublicKeyCredentialDescriptor, UserVerificationRequirement
from .db import users
import json

def get_registration_options(username):
    options = generate_registration_options(
        rp_id="localhost",
        rp_name="Passkey demo app",
        user_name=username
    )

    users[username] = {"challenge": options.challenge}
    return json.loads(options_to_json(options))

def verify_registration(username, response):

    # Parse the response into a structured object
    credential = parse_registration_credential_json(response)

    expected = users[username]["challenge"]
    verification = verify_registration_response(
        credential = credential,
        expected_challenge=expected,
        expected_origin="http://localhost:8080",  # Must match frontend origin
        expected_rp_id="localhost"
    )

    # Save credential info for future authentication
    users[username]["credential_id"] = verification.credential_id
    users[username]["public_key"] = verification.credential_public_key
    users[username]["sign_count"] = verification.sign_count

    return True

def get_authentication_options(username):

    credential_id = users[username]["credential_id"]
    public_key = users[username]["public_key"]
    prev_sign_count = users[username]["sign_count"]

    options = generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=credential_id)
        ],
        user_verification=UserVerificationRequirement.REQUIRED
    )
    users[username]["challenge"] = options.challenge

    return json.loads(options_to_json(options))

def verify_authentication(username, response):
    # Parse the frontend response into a structured object
    credential = parse_authentication_credential_json(response)

    # Retrieve stored values for this user
    expected_challenge = users[username]["challenge"]
    public_key = users[username]["public_key"]
    prev_sign_count = users[username]["sign_count"]

    # Verify the authentication response
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id="localhost",
        expected_origin="http://localhost:8080",
        credential_public_key=public_key,
        credential_current_sign_count=prev_sign_count,
        require_user_verification=True
    )

    # Update sign count to prevent replay attacks
    users[username]["sign_count"] = verification.new_sign_count

    return True