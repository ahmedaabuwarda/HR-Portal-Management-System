import re
import bcrypt

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import models

# Create your models here.

EMAIL_RE = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


def normalize_email(value):
    """Return a trimmed, lowercase email address."""
    return str(value or '').strip().lower()


class UserManager(models.Manager):
    """Manager exposing validators for the custom user model."""

    def register_validator(self, postData):
        """Validate registration data and return field-keyed errors."""

        errors = {}

        first_name = (postData.get('first_name') or '').strip()
        last_name = (postData.get('last_name') or '').strip()
        email = normalize_email(postData.get('email'))
        password = postData.get('password') or ''
        confirm_password = postData.get('confirm_password') or ''

        if first_name == '':
            errors['first_name.required'] = "First name field is required!"
        elif len(first_name) < 2:
            errors['first_name.min'] = "First name must be at least 2 characters!"

        if last_name == '':
            errors['last_name.required'] = "Last name field is required!"
        elif len(last_name) < 2:
            errors['last_name.min'] = "Last name must be at least 2 characters!"

        if email == '':
            errors['email.required'] = "Email field is required!"
        elif not EMAIL_RE.match(email):
            errors['email.email'] = "Invalid email address"
        elif User.objects.filter(email__iexact=email).exists():
            errors['email.unique'] = "Email address is taken!"

        if password == '':
            errors['password.required'] = "Password field is required!"
        elif len(password) < 8:
            errors['password.min'] = "Password must be at least 8 characters!"
        else:
            try:
                validate_password(password)
            except ValidationError as exc:
                errors['password.strong'] = " ".join(exc.messages)

        if confirm_password == '':
            errors['confirm_password.required'] = "Confirm password field is required!"
        elif confirm_password != password:
            errors['password.match'] = "Password and confirm password must match!"

        return errors

    def login_validator(self, postData):
        """Validate the shape of login credentials."""

        errors = {}

        email = normalize_email(postData.get('email'))
        password = postData.get('password') or ''

        if email == '':
            errors['email.required'] = "Email field is required!"
        else:
            if len(email) < 5:
                errors['email.min'] = "Email should be at least 5 characters"

            if not EMAIL_RE.match(email):
                errors['email.email'] = "Invalid email address"

        if password == '':
            errors['password.required'] = "Password field is required!"
        elif len(password) < 8:
            errors['password.min'] = "Password should be at least 8 characters"

        return errors

    def profile_validator(self, postData, user_id):
        """Validate profile updates for the user identified by ``user_id``."""

        errors = {}

        first_name = (postData.get('first_name') or '').strip()
        last_name = (postData.get('last_name') or '').strip()
        email = normalize_email(postData.get('email'))

        if first_name == '':
            errors['first_name.required'] = "First name field is required!"
        elif len(first_name) < 2:
            errors['first_name.min'] = "First name must be at least 2 characters!"

        if last_name == '':
            errors['last_name.required'] = "Last name field is required!"
        elif len(last_name) < 2:
            errors['last_name.min'] = "Last name must be at least 2 characters!"

        if email == '':
            errors['email.required'] = "Email field is required!"
        elif not EMAIL_RE.match(email):
            errors['email.email'] = "Invalid email address"
        elif User.objects.filter(email__iexact=email).exclude(id=user_id).exists():
            errors['email.unique'] = "Email address is taken!"

        return errors

    def password_change_validator(self, postData, user):
        """Validate the current password and the replacement password."""

        errors = {}

        current_password = postData.get('current_password') or ''
        new_password = postData.get('new_password') or ''
        confirm_password = postData.get('confirm_password') or ''

        if current_password == '':
            errors['current_password.required'] = "Current password is required!"
        else:
            try:
                if not bcrypt.checkpw(current_password.encode(), user.password.encode()):
                    errors['current_password.invalid'] = "Current password is incorrect!"
            except ValueError:
                errors['current_password.invalid'] = "Current password is incorrect!"

        if new_password == '':
            errors['new_password.required'] = "New password field is required!"
        elif len(new_password) < 8:
            errors['new_password.min'] = "New password must be at least 8 characters!"
        else:
            try:
                validate_password(new_password, user)
            except ValidationError as exc:
                errors['new_password.strong'] = " ".join(exc.messages)

        if confirm_password == '':
            errors['confirm_password.required'] = "Confirm password field is required!"
        elif confirm_password != new_password:
            errors['new_password.match'] = "Password and confirm password must match!"

        return errors


class User(models.Model):
    """Application user authenticated with bcrypt and session keys."""

    first_name = models.CharField(max_length=255, default=None)
    last_name = models.CharField(max_length=255, default=None)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()