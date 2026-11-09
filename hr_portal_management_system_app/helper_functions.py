# A real bcrypt hash, used to time-check an unknown email so a login attempt
# takes about the same time whether the account exists or not.
import ast
import base64
import json

from django.contrib import messages
from django.contrib.sessions.models import Session
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.utils import timezone

from webauthn import generate_authentication_options, options_to_json, verify_authentication_response
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from .attendance_rules import evaluate_check_in, settings_timezone

from .models import Attendance, AttendanceSettings, Holiday, User


DUMMY_PASSWORD_HASH = '$2b$12$HZAl9cTJ9PPgPlcA/H18he6oB5WzVtIAVwXseSS7Zz3MwfTfkF6/y'
ALLOWED_TRANSPORTS = frozenset({'usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'})


# Rotate before writing identity so a pre-login session key cannot be reused.
def begin_session(request, user):
    """Rotate the session key and store the signed-in user."""
    request.session.cycle_key()
    request.session['user_id'] = user.id
    request.session['user_first_name'] = user.first_name


# Return the signed-in user for this request, or None when nobody is logged in.
def current_user(request):
    user_id = request.session.get('user_id')

    if not user_id:
        return None

    return User.objects.filter(id=user_id).first()


# Revoke all other sessions for this user, except the current one.
def revoke_other_sessions(user, current_key):
    for session in Session.objects.filter(expire_date__gte=timezone.now()):
        try:
            data = session.get_decoded()
        except Exception:
            continue

        if data.get('user_id') == user.id and session.session_key != current_key:
            session.delete()


def relying_party(request):
    """Return the WebAuthn relying-party id and origin for this request."""
    host = request.get_host().split(':')[0]
    origin = f"{request.scheme}://{request.get_host()}"

    return host, origin


def encode_b64url(value):
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(value).decode()


def json_options(options):
    """Serialize WebAuthn options into a JSON response."""
    return JsonResponse(json.loads(options_to_json(options)))


def clean_transports(value):
    """Keep only WebAuthn-recognized transport values."""
    if not isinstance(value, list):
        return []

    return sorted({item for item in value if isinstance(item, str) and item in ALLOWED_TRANSPORTS})


def decode_b64url(value):
    """Decode a base64url value into bytes."""
    # base64url strips the '=' padding; add it back for the decoder.
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def decode_stored_credential_id(value):
    """Decode a stored credential ID, including the repr format used previously."""
    if value.startswith(("b'", 'b"')):
        credential_id = ast.literal_eval(value)

        if isinstance(credential_id, bytes):
            return credential_id

        raise ValueError('Stored credential ID is not bytes.')

    return decode_b64url(value)


def passkey_authentication_options(request, passkeys):
    """Build WebAuthn authentication options for the given passkeys."""

    rp_id, _ = relying_party(request)

    return generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=decode_stored_credential_id(passkey.credential_id)
            )
            for passkey in passkeys
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )


def verify_passkey_assertion(request, passkeys, challenge):
    """Verify a fingerprint scan and update the matched sign count.

    Returns ``(passkey, None)`` when the scan is valid, or
    ``(None, error_message)`` with a plain error string when it is not —
    the calling view turns that string into a JSON response.

    Callers must scope ``passkeys`` to the session user before calling.
    """
    # Read the JSON body the browser posted.
    try:
        payload = json.loads(request.body or '{}')
    except (TypeError, ValueError):
        return None, 'Invalid request body.'

    try:
        credential = payload['credential']
        credential_id = decode_b64url(credential['rawId'])
    except (KeyError, TypeError):
        return None, 'Invalid request body.'

    passkey = passkeys.filter(
        credential_id=encode_b64url(credential_id)
    ).first()

    if passkey is None:
        passkey = next(
            (
                candidate
                for candidate in passkeys
                if decode_stored_credential_id(candidate.credential_id) == credential_id
            ),
            None,
        )

    if passkey is None:
        return None, 'Fingerprint not recognized.'

    rp_id, origin = relying_party(request)

    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=decode_b64url(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True,
        )
    except Exception:
        return None, 'Fingerprint verification failed.'

    # A replayed assertion would not advance the sign count.
    if passkey.sign_count > 0 and verified.new_sign_count <= passkey.sign_count:
        return None, 'Fingerprint verification failed.'

    passkey.sign_count = verified.new_sign_count
    passkey.last_used_at = timezone.now()
    passkey.save(update_fields=['sign_count', 'last_used_at'])

    return passkey, None


def close_stale_attendance(today):
    """Mark days that ended without a clock-out as absent.

    Only days before ``today`` are touched: a fingerprint scan can only ever
    clock out *today's* row, so a past day with no clock-out is final.
    """

    Attendance.objects.filter(
        check_out__isnull=True,
        work_date__lt=today,
    ).update(status=Attendance.STATUS_ABSENT)


def flash_attendance_result(request, status, user=None, reason=None):
    """Flash a message describing the recorded attendance result."""

    if status == 'rejected':
        messages.error(request, reason or "This check-in is not allowed.")
    elif status == 'in':
        if user is None:
            messages.success(request, "You're clocked in. Have a good shift!")
        else:
            messages.success(request, f"Good to see you, {user.first_name}. You're clocked in.")
    elif status == 'out':
        messages.success(request, "You're clocked out. Have a good one!")
    else:
        messages.info(request, "Your attendance is already complete for today.")


def record_attendance(user, passkey):
    """Record a fingerprint scan as check-in, check-out, or a rule rejection.

    Returns ``(action, reason)``: ``('in' | 'out' | 'done', None)`` when a row
    was written or closed, or ``('rejected', message)`` when the configured
    attendance rules block this scan. The rules are evaluated in the
    admin-configured time zone against the server clock only.
    """

    rules = AttendanceSettings.objects.load()
    now = timezone.now()
    local = now.astimezone(settings_timezone(rules))
    today = local.date()

    # Yesterday and earlier: no clock-out means the day counts as absent.
    close_stale_attendance(today)

    with transaction.atomic():
        # Lock the day's row so two scans in the same second can't both clock in.
        attendance = (
            Attendance.objects.select_for_update()
            .filter(user=user, work_date=today)
            .first()
        )

        if attendance is None:
            holidays = dict(Holiday.objects.filter(date=today).values_list('date', 'name'))
            counted, outcome = evaluate_check_in(rules, local, holidays)

            if not counted:
                return 'rejected', outcome

            # The savepoint lets the unique constraint resolve a concurrent first scan.
            try:
                with transaction.atomic():
                    Attendance.objects.create(
                        user=user,
                        work_date=today,
                        check_in=now,
                        status=outcome,
                        method=Attendance.METHOD_PASSKEY,
                        passkey=passkey,
                    )
                return 'in', None
            except IntegrityError:
                attendance = (
                    Attendance.objects.select_for_update()
                    .filter(user=user, work_date=today)
                    .first()
                )

        if attendance is not None and attendance.check_out is None:
            # Check-out has no window: only check-ins are governed by the rules.
            attendance.check_out = now
            attendance.passkey = passkey
            attendance.save(update_fields=['check_out', 'passkey'])
            return 'out', None

        return 'done', None
