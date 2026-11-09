from django.http import HttpResponseNotAllowed, JsonResponse
from django.urls import reverse

from .helper_functions import current_user, encode_b64url, flash_attendance_result, json_options, passkey_authentication_options, record_attendance, verify_passkey_assertion

# ---------- Dashboard Check in/out ----------

def attendance_begin(request):
    """Return an assertion challenge for the signed-in user's time clock."""
    # Only POST is allowed: this endpoint is called by JavaScript.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    # Guard: JavaScript calls this endpoint, so answer with JSON 403, not a redirect.
    user = current_user(request)

    if user is None:
        return JsonResponse({'error': 'Not authenticated.'}, status=403)

    passkeys = list(user.passkeys.all())

    if not passkeys:
        return JsonResponse(
            {'error': 'Add a fingerprint in Settings before clocking in.'},
            status=400,
        )

    options = passkey_authentication_options(request, passkeys)

    request.session['passkey_attendance_challenge'] = encode_b64url(options.challenge)
    request.session['passkey_attendance_user'] = user.id

    return json_options(options)


def attendance_complete(request):
    """Verify a dashboard fingerprint scan and record attendance."""
    # Only POST is allowed: this endpoint is called by JavaScript.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    # Guard: JavaScript calls this endpoint, so answer with JSON 403, not a redirect.
    user = current_user(request)

    if user is None:
        return JsonResponse({'error': 'Not authenticated.'}, status=403)

    challenge = request.session.pop('passkey_attendance_challenge', None)
    challenge_user = request.session.pop('passkey_attendance_user', None)

    if not challenge or challenge_user != user.id:
        return JsonResponse({'error': 'Clock session expired. Try again.'}, status=400)

    # Check the scan. On failure we get a plain error message back.
    passkey, error = verify_passkey_assertion(request, user.passkeys.all(), challenge)

    if error:
        return JsonResponse({'error': error}, status=400)

    status, reason = record_attendance(user, passkey)

    # Rules rejected the scan: tell the button why (app.js shows `error`).
    if status == 'rejected':
        return JsonResponse({'error': reason}, status=400)

    flash_attendance_result(request, status, reason=reason)

    return JsonResponse({
        'ok': True,
        'status': status,
        'redirect': reverse('dashboard'),
    })

