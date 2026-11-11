from datetime import timedelta
import random

import bcrypt
from django.conf import settings
from django.contrib import messages
from django.core.mail import EmailMultiAlternatives
from django.http import HttpResponseNotAllowed
from django.shortcuts import redirect, render
from django.utils import timezone
from .models import PasswordResetToken, User
from .utils import normalize_email

from .helper_functions import begin_session, DUMMY_PASSWORD_HASH, revoke_other_sessions

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
        return render(request, 'auth/forget_password.html')

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
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )
    email.attach_alternative(html_content, "text/html")
    email.send(fail_silently=False)

    messages.success(request, done_message)
    return redirect('code_verification')


def code_verification(request):
    """Check the code the user typed, then let them set a new password."""

    # Guard: someone must have asked for a code first.
    if 'reset_email' not in request.session:
        messages.error(request, "Please request a reset code first.")
        return redirect('forget_password')

    # GET: show the code form.
    if request.method == 'GET':
        return render(request, 'auth/code_verification.html')

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
        return redirect('code_verification')

    # Mark the code as used so it cannot be reused.
    token.used = True
    token.save()

    messages.success(request, "Verification successful!")
    request.session['reset_user_id'] = user.id

    return redirect('reset_password')


def send_password_changed_email(user):
    """Tell the account owner that their password was just changed."""

    subject = "Your HR Portal password was changed"
    text_content = (
        "Your password was changed just now.\n\n"
        "If you made this change, no further action is needed.\n"
        "If you did not change it, reply to this email immediately so we can secure your account.\n\n"
        "Thank you,\nHR Portal team"
    )
    html_content = """
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #1f2937;">
            <p>Hello,</p>
            <p>Your password was changed just now.</p>
            <p>If you made this change, no further action is needed.</p>
            <p><strong>If you did not change it, reply to this email immediately</strong> so we can secure your account.</p>
            <p>Thank you,<br>HR Portal team</p>
        </body>
        </html>
    """

    email = EmailMultiAlternatives(
        subject,
        text_content,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )
    email.attach_alternative(html_content, "text/html")
    email.send(fail_silently=False)


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
        return render(request, 'auth/reset_password.html')

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

    # Tell the owner their password changed. The new password is already
    # saved, so a failed send only changes the message, never the outcome.
    try:
        send_password_changed_email(user)
        messages.success(request, "Password reset successfully! Please log in.")
    except Exception:
        messages.warning(
            request,
            "Password changed, but we couldn't send the confirmation email.",
        )

    return redirect('login')
