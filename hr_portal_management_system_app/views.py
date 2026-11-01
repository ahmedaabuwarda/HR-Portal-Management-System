import bcrypt

from django.contrib import messages
from django.http import HttpResponseNotAllowed
from django.shortcuts import render, redirect

from .models import User, normalize_email

# Create your views here.

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
    return render(request, 'auth/login.html')


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
    return render(request, 'user/dashboard.html')


def settings(request):
    return render(request, 'user/settings.html')