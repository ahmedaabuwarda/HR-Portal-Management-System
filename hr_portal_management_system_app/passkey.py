import json

from django.urls import reverse
from .models import Passkey, User, normalize_email

from MySQLdb import IntegrityError
from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseNotAllowed, JsonResponse

from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .helper_functions import begin_session, clean_transports, current_user, decode_b64url, decode_stored_credential_id, encode_b64url, flash_attendance_result, json_options, passkey_authentication_options, record_attendance, relying_party, verify_passkey_assertion


# ---------- Fingerprint enrollment (add new) ----------


def passkey_register_begin(request):
    """Return WebAuthn registration options and store the challenge."""
    # Only POST is allowed: this endpoint is called by JavaScript.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    # Guard: JavaScript calls this endpoint, so answer with JSON 403, not a redirect.
    user = current_user(request)

    if user is None:
        return JsonResponse({'error': 'Not authenticated.'}, status=403)

    rp_id, _ = relying_party(request)

    # Tell the authenticator which fingerprints are already enrolled.
    excluded = [
        PublicKeyCredentialDescriptor(
            id=decode_stored_credential_id(passkey.credential_id)
        )
        for passkey in user.passkeys.all()
    ]

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name='HR Portal',
        user_id=str(user.id).encode(),
        user_name=user.email,
        user_display_name=f"{user.first_name} {user.last_name}",
        exclude_credentials=excluded,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    request.session['passkey_challenge'] = encode_b64url(options.challenge)

    return json_options(options)


def passkey_register_complete(request):
    """Verify and persist a newly enrolled passkey."""
    # Only POST is allowed: this endpoint is called by JavaScript.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    # Guard: JavaScript calls this endpoint, so answer with JSON 403, not a redirect.
    user = current_user(request)

    if user is None:
        return JsonResponse({'error': 'Not authenticated.'}, status=403)

    # The challenge is single use: drop it before verifying.
    challenge = request.session.pop('passkey_challenge', None)

    if not challenge:
        return JsonResponse({'error': 'Registration session expired.'}, status=400)

    # Read the JSON body the browser posted.
    try:
        payload = json.loads(request.body or '{}')
    except (TypeError, ValueError):
        return JsonResponse({'error': 'Invalid request body.'}, status=400)

    rp_id, origin = relying_party(request)

    # A label is optional: default it, trim it, cap it at 100 characters.
    label = str(payload.get('label') or 'Fingerprint').strip()[:100]

    if not label:
        label = 'Fingerprint'

    try:
        verified = verify_registration_response(
            credential=payload['credential'],
            expected_challenge=decode_b64url(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception:
        return JsonResponse({'error': 'Fingerprint registration failed.'}, status=400)

    try:
        Passkey.objects.create(
            user=user,
            label=label,
            credential_id=encode_b64url(verified.credential_id),
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            transports=clean_transports(payload.get('transports')),
        )
    except IntegrityError:
        return JsonResponse({'error': 'This fingerprint is already registered.'}, status=400)

    return JsonResponse({'ok': True, 'label': label})


def passkey_delete(request, passkey_id):
    """Delete one of the signed-in user's passkeys."""
    # Only POST is allowed: this endpoint is a form submitted by JavaScript-free HTML.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    # Guard: must be signed in.
    user = current_user(request)

    if user is None:
        messages.error(request, "You must log in first!")
        return redirect('login')

    passkey = user.passkeys.filter(id=passkey_id).first()

    if not passkey:
        messages.error(request, "Fingerprint not found.")
        return redirect('settings')

    passkey.delete()
    messages.success(request, "Fingerprint removed.")

    return redirect('settings')


# ---------- Fingerprint login ----------


def passkey_login_begin(request):
    """Return authentication options, optionally scoped to an email."""
    # Only POST is allowed: this endpoint is called by JavaScript.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    # Read the JSON body the browser posted.
    try:
        payload = json.loads(request.body or '{}')
    except (TypeError, ValueError):
        return JsonResponse({'error': 'Invalid request body.'}, status=400)

    email = normalize_email(payload.get('email'))
    user = None
    passkeys = []

    if email:
        user = User.objects.filter(email=email).first()

        if user is None or not user.passkeys.exists():
            return JsonResponse(
                {'error': 'Fingerprint login is not available for this account.'},
                status=400,
            )

        passkeys = user.passkeys.all()

    options = passkey_authentication_options(request, passkeys)

    request.session['passkey_auth_challenge'] = encode_b64url(options.challenge)
    request.session['passkey_auth_user'] = user.id if user else None

    return json_options(options)


def passkey_login_complete(request):
    """Verify a passkey assertion, sign in and record attendance."""
    # Only POST is allowed: this endpoint is called by JavaScript.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    challenge = request.session.pop('passkey_auth_challenge', None)
    user_id = request.session.pop('passkey_auth_user', None)

    if not challenge:
        return JsonResponse({'error': 'Login session expired. Try again.'}, status=400)

    passkeys = Passkey.objects.select_related('user')

    if user_id:
        passkeys = passkeys.filter(user_id=user_id)

    # Check the scan. On failure we get a plain error message back.
    passkey, error = verify_passkey_assertion(request, passkeys, challenge)

    if error:
        return JsonResponse({'error': error}, status=400)

    begin_session(request, passkey.user)

    # A rejected check-in still signs the user in — the rules only decide
    # whether the scan counts as attendance, not whether they may enter.
    status, reason = record_attendance(passkey.user, passkey)
    flash_attendance_result(request, status, user=passkey.user, reason=reason)

    return JsonResponse({
        'ok': True,
        'status': status,
        'redirect': reverse('dashboard'),
    })
