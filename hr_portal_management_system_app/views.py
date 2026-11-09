import bcrypt

from . import auth, passkey, attendance
from .helper_functions import close_stale_attendance, current_user, revoke_other_sessions
from .attendance_rules import local_now
from .models import Attendance, Passkey, User, normalize_email

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import render, redirect


# Create your views here.


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


# 404 page
def not_found(request, unmatched):
    """Render the branded not-found page for unmatched URLs, including in debug mode."""
    return render(request, '404.html', status=404)


# ---------- Login / Register / Logout ----------

def login(request):
    return auth.login(request)


def register(request):
    return auth.register(request)


def logout(request):
    return auth.logout(request)


# ------------- Password reset flow -------------

def forget_password(request):
    return auth.forget_password(request)


def code_verification(request):
    return auth.code_verification(request)


def reset_password(request):
    return auth.reset_password(request)


# ---------- user dashboard and settings ----------

def dashboard(request):
    """Render the signed-in user's attendance summary and history."""
    # Guard: must be signed in.
    if "user_id" not in request.session:
        messages.error(request, "You must log in first!")
        return redirect('home')

    user_id = request.session['user_id']
    # "Today" is the admin-configured zone's date, not the server's.
    today = local_now().date()

    # Any past day still open (no clock-out) counts as absent.
    close_stale_attendance(today)

    history = Attendance.objects.filter(
        user_id=user_id,
    ).select_related('passkey')

    context = {
        'passkey_count': Passkey.objects.filter(user_id=user_id).count(),
        'page_obj': Paginator(history, 20).get_page(request.GET.get('page')),
        'open_attendance': Attendance.objects.filter(
            user_id=user_id,
            work_date=today,
            check_out__isnull=True,
        ).count(),
        'today_attendance': Attendance.objects.filter(
            user_id=user_id,
            work_date=today,
        ).first(),
    }

    return render(request, 'user/dashboard.html', context)


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

            # Same security notice as a password reset: a failed send only
            # changes the message, the new password is already saved.
            try:
                auth.send_password_changed_email(user)
                messages.success(request, "Password updated successfully!")
            except Exception:
                messages.warning(
                    request,
                    "Password updated, but we couldn't send the confirmation email.",
                )

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
    return passkey.passkey_register_begin(request)


def passkey_register_complete(request):
    return passkey.passkey_register_complete(request)


def passkey_delete(request, passkey_id):
    return passkey.passkey_delete(request, passkey_id)


# ---------- Fingerprint login ----------

def passkey_login_begin(request):
    return passkey.passkey_login_begin(request)


def passkey_login_complete(request):
    return passkey.passkey_login_complete(request)


# ---------- Dashboard Check in/out ----------

def attendance_begin(request):
    return attendance.attendance_begin(request)


def attendance_complete(request):
    return attendance.attendance_complete(request)
