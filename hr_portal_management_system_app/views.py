import base64
import json
import random
import bcrypt

from datetime import timedelta

from django.conf import settings as django_settings
from django.contrib import messages
from django.contrib.sessions.models import Session
from django.core.mail import EmailMultiAlternatives
from django.db import IntegrityError
from django.http import HttpResponseNotAllowed, JsonResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from .models import Passkey, PasswordResetToken, User, normalize_email

# WebAuthn imports
from webauthn import generate_registration_options, options_to_json, verify_registration_response

from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# Create your views here.

# A real bcrypt hash, used to time-check an unknown email so a login attempt
# takes about the same time whether the account exists or not.
DUMMY_PASSWORD_HASH = '$2b$12$HZAl9cTJ9PPgPlcA/H18he6oB5WzVtIAVwXseSS7Zz3MwfTfkF6/y'
ALLOWED_TRANSPORTS = frozenset({'usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'})



# ---------- Helper functions ----------

def begin_session(request, user):
    """Rotate the session key and store the signed-in user."""
    # Rotate before writing identity so a pre-login session key cannot be reused.
    request.session.cycle_key()
    request.session['user_id'] = user.id
    request.session['user_first_name'] = user.first_name


# This method check if the user currently logged in , and return user object
def current_user(request):
    # get user id from current session
    user_id = request.session.get('user_id')
    # if no user id in session, return None
    if not user_id:
        return None
    # else, find the user and return user information
    return User.objects.filter(id=user_id).first()


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


# ---------- Public pages ----------

def home(request):
    """Render the public landing page."""
    return render(request, 'home.html')


def about_us(request):
    """Render the public About Us page."""
    return render(request, 'about_us.html')


def contact_us(request):
    """Render the public Contact Us page."""
    return render(request, 'contact_us.html')


# ---------- Login / Register / Logout ----------

def login(request):
    """Render the login form or authenticate a password sign-in."""

    # GET: show the form, or send an already signed-in visitor to the dashboard.
    if request.method == 'GET':
        if "user_id" in request.session:
            return redirect('dashboard')

        return render(request, 'auth/login.html')

    # POST: validate the credentials.
    if "user_id" in request.session:
        messages.error(request, "You already logged in!")
        return redirect('dashboard')

    errors = User.objects.login_validator(request.POST)

    if errors:
        for key, val in errors.items():
            messages.error(request, val)

        return redirect('login')

    email = normalize_email(request.POST.get('email'))
    password = request.POST.get('password') or ''
    user = User.objects.filter(email=email).first()

    # Unknown email: run a dummy check so the timing matches a wrong password.
    if user is None:
        bcrypt.checkpw(password.encode(), DUMMY_PASSWORD_HASH.encode())
        messages.error(request, "Invalid email or password")
        return redirect('login')

    # A corrupted stored hash raises ValueError; treat it as a wrong password.
    try:
        if not bcrypt.checkpw(password.encode(), user.password.encode()):
            messages.error(request, "Invalid email or password")
            return redirect('login')
    except ValueError:
        messages.error(request, "Invalid email or password")
        return redirect('login')

    messages.success(request, "Logged in successfully!")

    # add user id to session
    begin_session(request, user)

    return redirect('dashboard')


def register(request):
    """Render the registration form or create a new account."""

    # GET: show the form.
    if request.method == 'GET':
        if "user_id" in request.session:
            return redirect('dashboard')

        return render(request, 'auth/register.html')

    # POST: create the account.
    if "user_id" in request.session:
        messages.error(request, "You already logged in!")
        return redirect('dashboard')

    errors = User.objects.register_validator(request.POST)

    if errors:
        for key, val in errors.items():
            messages.error(request, val)

        return redirect('register')

    user = User.objects.create(
        first_name=(request.POST.get('first_name') or '').strip(),
        last_name=(request.POST.get('last_name') or '').strip(),
        email=normalize_email(request.POST.get('email')),
        password=bcrypt.hashpw(
            request.POST['password'].encode(),
            bcrypt.gensalt()
        ).decode()
    )

    messages.success(request, "Registration done successfully!")

    # add user id to session
    begin_session(request, user)

    return redirect('dashboard')


def logout(request):
    """Clear the session and return to the landing page."""
    # Only POST is allowed, so a stray link can never log someone out.
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    request.session.flush()  # Clear the session data
    messages.error(request, "You logged out!")
    return redirect('home')


# ------------- Password reset flow -------------

def forget_password(request):
    """Show the form, or email a 6-digit reset code to the given address."""

    # GET: show the form.
    if request.method == 'GET':
        return render(request, 'auth/forget.html')

    # POST: find the user and send them a code.
    email = normalize_email(request.POST.get('email'))
    user = User.objects.filter(email=email).first()

    # Always answer the same way so nobody can tell which emails are registered.
    done_message = "If that email exists, a code has been sent."

    if user is None:
        messages.error(request, done_message)
        return redirect('forget_password')

    # Make a 6-digit code and save it. Old codes stop working.
    code = str(random.randint(100000, 999999))
    PasswordResetToken.objects.filter(user=user, used=False).update(used=True)
    PasswordResetToken.objects.create(user=user, code=code)

    # Remember which email the code was sent to, so the next page knows.
    request.session['reset_email'] = user.email

    subject = "Your HR Portal password reset code"
    text_content = (
        f"Your verification code is: {code}\n\n"
        "It is valid for 10 minutes.\n\n"
        "If you are having any issues with your account, please don't hesitate to contact us by replying to this mail.\n\n"
        "Thank you,\nHR Portal team"
    )
    html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #1f2937;">
            <p>Hello,</p>
            <p>Your verification code is: <strong>{code}</strong></p>
            <p>It is valid for 10 minutes.</p>
            <p>If you are having any issues with your account, please don't hesitate to contact us by replying to this mail.</p>
            <p>Thank you,<br>HR Portal team</p>
        </body>
        </html>
    """

    email = EmailMultiAlternatives(
        subject,
        text_content,
        django_settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )
    email.attach_alternative(html_content, "text/html")
    email.send(fail_silently=False)

    messages.success(request, done_message)
    return redirect('verification')


def verification(request):
    """Check the code the user typed, then let them set a new password."""

    # Guard: someone must have asked for a code first.
    if 'reset_email' not in request.session:
        messages.error(request, "Please request a reset code first.")
        return redirect('forget_password')

    # GET: show the code form.
    if request.method == 'GET':
        return render(request, 'auth/verification.html')

    # POST: check the code.
    code = (request.POST.get('verification_code') or '').strip()
    user = User.objects.filter(email=request.session['reset_email']).first()

    token = None
    if user is not None and code:
        token = PasswordResetToken.objects.filter(
            user=user,
            code=code,
            used=False,
            created_at__gte=timezone.now() - timedelta(minutes=10),
        ).first()

    if token is None:
        messages.error(request, "Invalid or expired verification code.")
        return redirect('verification')

    # Mark the code as used so it cannot be reused.
    token.used = True
    token.save()

    messages.success(request, "Verification successful!")
    request.session['reset_user_id'] = user.id

    return redirect('reset_password')


def reset_password(request):
    """Save the new password once the code has been verified."""

    # Guard: the code must have been verified in this session.
    user_id = request.session.get('reset_user_id')
    user = User.objects.filter(id=user_id).first() if user_id else None

    if user is None:
        messages.error(request, "Please request a reset code first.")
        return redirect('forget_password')

    # GET: show the form.
    if request.method == 'GET':
        return render(request, 'auth/reset.html')

    # POST: validate and save the new password.
    password = request.POST.get('password') or ''
    confirm_password = request.POST.get('confirm_password') or ''

    if len(password) < 8:
        messages.error(request, "Password must be at least 8 characters!")
        return redirect('reset_password')

    if password != confirm_password:
        messages.error(request, "Password and confirm password must match!")
        return redirect('reset_password')

    user.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user.save()

    # The reset is finished: forget the email and the verified user.
    request.session.pop('reset_email', None)
    request.session.pop('reset_user_id', None)

    # Sign out every other device.
    revoke_other_sessions(user, request.session.session_key)

    messages.success(request, "Password reset successfully! Please log in.")
    return redirect('login')


# ---------- user dashboard and settings ----------

def dashboard(request):
    if "user_id" not in request.session:
        messages.error(request, "You must log in first!")
        return redirect('home')
    
    user_id = request.session['user_id']
    today = timezone.localdate()

    # history = Attendance.objects.filter(
    #     user_id=user_id,
    # ).select_related('passkey')

    # context = {
    #     'passkey_count': Passkey.objects.filter(user_id=user_id).count(),
    #     'page_obj': Paginator(history, 20).get_page(request.GET.get('page')),
        # 'open_attendance': Attendance.objects.filter(
        #     user_id=user_id,
        #     work_date=today,
        #     check_out__isnull=True,
        # ).count(),
        # 'today_attendance': Attendance.objects.filter(
        #     user_id=user_id,
        #     work_date=today,
        # ).first(),
    # }

    return render(request, 'user/dashboard.html')


def settings(request):
    user = current_user(request)
    if user is None:
        messages.error(request, "You must log in first!")
        return redirect('login')
        # POST: update the profile or the password.
    if request.method == 'POST':

        action = request.POST.get('action')

        if action == 'profile':
            errors = User.objects.profile_validator(request.POST, user.id)

            if errors:
                for key, val in errors.items():
                    messages.error(request, val)

                return redirect('settings')

            user.first_name = request.POST['first_name'].strip()
            user.last_name = request.POST['last_name'].strip()
            user.email = normalize_email(request.POST.get('email'))
            user.save()

            request.session['user_first_name'] = user.first_name
            messages.success(request, "Profile updated successfully!")

        elif action == 'password':
            errors = User.objects.password_change_validator(request.POST, user)

            if errors:
                for key, val in errors.items():
                    messages.error(request, val)

                return redirect('settings')

            user.password = bcrypt.hashpw(
                request.POST['new_password'].encode(),
                bcrypt.gensalt()
            ).decode()
            user.save()

            revoke_other_sessions(user, request.session.session_key)

            messages.success(request, "Password updated successfully!")

        else:
            messages.error(request, "Unknown settings action.")

        return redirect('settings')

    # GET: show the account.
    context = {
        'account': user,
        'passkeys': user.passkeys.all(),
    }
    return render(request, 'user/settings.html', context)


# ---------- Fingerprint enrollment ----------


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
            id=base64.urlsafe_b64decode(passkey.credential_id)
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
            credential_id=verified.credential_id,
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
