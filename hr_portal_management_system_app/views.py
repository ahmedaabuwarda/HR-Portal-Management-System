import bcrypt

from django.contrib import messages
from django.http import HttpResponseNotAllowed
from django.shortcuts import render, redirect
from django.utils import timezone
from .models import User, normalize_email

# Create your views here.

# A real bcrypt hash, used to time-check an unknown email so a login attempt
# takes about the same time whether the account exists or not.
DUMMY_PASSWORD_HASH = '$2b$12$HZAl9cTJ9PPgPlcA/H18he6oB5WzVtIAVwXseSS7Zz3MwfTfkF6/y'


# ---------- Helper functions ----------

def begin_session(request, user):
    """Rotate the session key and store the signed-in user."""
    # Rotate before writing identity so a pre-login session key cannot be reused.
    request.session.cycle_key()
    request.session['user_id'] = user.id
    request.session['user_first_name'] = user.first_name


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
    return render(request, 'user/settings.html')