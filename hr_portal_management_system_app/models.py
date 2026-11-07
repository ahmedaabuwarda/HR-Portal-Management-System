from datetime import datetime, time
import re
import zoneinfo
import bcrypt

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import models

# Create your models here.

EMAIL_RE = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Sun-Thu (Django weekday(): 0 = Monday ... 6 = Sunday), matching the local week.
DEFAULT_WORKING_DAYS = [6, 0, 1, 2, 3]
OUT_OF_WINDOW_REJECT = 'reject'
OUT_OF_WINDOW_LATE = 'late'
OUT_OF_WINDOW_CHOICES = [
    (OUT_OF_WINDOW_REJECT, 'Reject the check-in'),
    (OUT_OF_WINDOW_LATE, 'Record it as late'),
]


# helper functions
def normalize_email(value):
    """Return a trimmed, lowercase email address."""
    return str(value or '').strip().lower()


def default_working_days():
    """Return a fresh copy of the default working-day list (migration-safe)."""
    return list(DEFAULT_WORKING_DAYS)


def parse_time(value):
    """Parse ``HH:MM`` (or ``HH:MM:SS``) into a ``datetime.time``, else ``None``."""

    if isinstance(value, time):
        return value

    parts = str(value or '').strip().split(':')

    if len(parts) not in (2, 3):
        return None

    try:
        hour, minute = int(parts[0]), int(parts[1])
        second = int(parts[2]) if len(parts) == 3 else 0
    except ValueError:
        return None

    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        return None

    return time(hour, minute, second)


def parse_datetime_local(value):
    """Parse ``YYYY-MM-DDTHH:MM`` from an ``<input type="datetime-local">``.

    Naive values are returned as-is; callers pair them with the configured
    attendance timezone before comparing.
    """

    if not isinstance(value, str) or len(value) < 16:
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None



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


class PasswordResetToken(models.Model):
    """A one-time code sent by email so a user can reset a forgotten password."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reset_tokens')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)

    def __str__(self):
        """Return a readable token label."""

        return f"{self.user.email} - {self.code}"


class Passkey(models.Model):
    """WebAuthn credential metadata; biometric data never leaves the device."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='passkeys')
    label = models.CharField(max_length=100, default='Fingerprint')
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.BinaryField()
    sign_count = models.PositiveIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        """Newest passkeys first."""

        ordering = ['-created_at']

    def __str__(self):
        """Return a readable passkey label."""

        return f"{self.user.email} - {self.label}"


class AttendanceManager(models.Manager):
    """Manager exposing the validator for admin record corrections."""

    def correction_validator(self, postData):
        """Validate an admin correction of one attendance record."""

        errors = {}

        check_in_raw = (postData.get('check_in') or '').strip()
        check_out_raw = (postData.get('check_out') or '').strip()
        status = (postData.get('status') or '').strip()
        note = (postData.get('note') or '').strip()

        check_in = parse_datetime_local(check_in_raw)
        check_out = parse_datetime_local(check_out_raw) if check_out_raw else None

        if check_in_raw == '':
            errors['check_in.required'] = "Check-in time is required!"
        elif check_in is None:
            errors['check_in.invalid'] = "Check-in must be a valid date and time!"

        if check_out_raw != '' and check_out is None:
            errors['check_out.invalid'] = "Check-out must be a valid date and time!"

        if check_in is not None and check_out is not None:
            # Compare wall-clock values: posted input may carry an offset.
            if check_out.replace(tzinfo=None) < check_in.replace(tzinfo=None):
                errors['check_out.order'] = "Check-out cannot be before check-in!"

        if status not in dict(Attendance.STATUS_CHOICES):
            errors['status.invalid'] = "Status must be present or late!"

        if note == '':
            errors['note.required'] = "An audit note is required for every correction!"

        return errors


class Attendance(models.Model):
    """One attendance record per user per workday."""

    METHOD_PASSKEY = 'passkey'
    METHOD_CHOICES = [
        (METHOD_PASSKEY, 'Fingerprint'),
    ]
    STATUS_PRESENT = 'present'
    STATUS_LATE = 'late'
    STATUS_CHOICES = [
        (STATUS_PRESENT, 'Present'),
        (STATUS_LATE, 'Late'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attendance')
    work_date = models.DateField()
    check_in = models.DateTimeField()
    check_out = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PRESENT)
    method = models.CharField(max_length=20, choices=METHOD_CHOICES, default=METHOD_PASSKEY)
    passkey = models.ForeignKey(Passkey,on_delete=models.SET_NULL,null=True,blank=True,related_name='attendance')
    created_at = models.DateTimeField(auto_now_add=True)
    objects = AttendanceManager()

    class Meta:
        """Newest attendance first, with one row per user per workday."""

        ordering = ['-work_date', '-check_in']
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'work_date'],
                name='unique_attendance_per_user_day',
            ),
        ]
        indexes = [
            # Reports and record browsing filter by day first, then by status.
            models.Index(fields=['work_date', 'status'], name='attendance_date_status_idx'),
            models.Index(fields=['user', 'work_date'], name='attendance_user_date_idx'),
        ]

    def __str__(self):
        """Return a readable attendance label."""

        return f"{self.user.email} - {self.work_date}"

    @property
    def duration_display(self):
        """Format the worked duration, or ``In progress`` while open."""

        if self.check_out is None:
            return "In progress"

        seconds = int((self.check_out - self.check_in).total_seconds())

        if seconds < 60:
            return "<1m"

        hours, minutes = divmod(seconds // 60, 60)

        if hours:
            return f"{hours}h {minutes}m"

        return f"{minutes}m"


class AttendanceSettingsManager(models.Manager):
    """Manager for the singleton attendance rules row and its validator."""

    def load(self):
        """Return the singleton settings row, creating it with defaults."""

        row, _created = self.get_or_create(pk=1)
        return row

    @staticmethod
    def working_days_value(postData):
        """Read the ``working_days`` field from a QueryDict or a plain dict.

        Values come back as integers so templates can compare them with the
        checkbox values directly; unparseable input is kept for the validator
        to reject.
        """

        if hasattr(postData, 'getlist'):
            raw = postData.getlist('working_days')
        else:
            value = postData.get('working_days') or []
            raw = value if isinstance(value, list) else [value]

        days = []

        for day in raw:
            try:
                days.append(int(day))
            except (TypeError, ValueError):
                days.append(day)

        return days

    def settings_validator(self, postData):
        """Validate the attendance rules form and return field-keyed errors."""

        errors = {}

        days = self.working_days_value(postData)

        try:
            days = sorted({int(day) for day in days})
        except (TypeError, ValueError):
            days = []

        if not days:
            errors['working_days.required'] = "Pick at least one working day!"
        elif any(day < 0 or day > 6 for day in days):
            errors['working_days.invalid'] = "Working days must be numbers from 0 to 6!"

        start = parse_time(postData.get('start_time'))
        end = parse_time(postData.get('end_time'))
        earliest = parse_time(postData.get('earliest_check_in'))
        latest = parse_time(postData.get('latest_check_in'))

        for field, label, value in (
            ('start_time', 'Scheduled start', start),
            ('end_time', 'Scheduled end', end),
            ('earliest_check_in', 'Earliest check-in', earliest),
            ('latest_check_in', 'Latest check-in', latest),
        ):
            raw = (postData.get(field) or '').strip()

            if raw == '':
                errors[f'{field}.required'] = f"{label} time is required!"
            elif value is None:
                errors[f'{field}.invalid'] = f"{label} must be a valid time (HH:MM)!"

        if start and end and start >= end:
            errors['end_time.order'] = "Scheduled end must be after the scheduled start!"

        if earliest and latest and earliest > latest:
            errors['latest_check_in.order'] = "Latest check-in cannot be before the earliest check-in!"

        if earliest and start and earliest > start:
            errors['start_time.window'] = "Scheduled start must fall inside the check-in window!"

        if latest and start and latest < start:
            errors['start_time.window'] = "Scheduled start must fall inside the check-in window!"

        timezone_name = (postData.get('timezone_name') or '').strip()

        if timezone_name == '':
            errors['timezone_name.required'] = "A time zone is required!"
        elif timezone_name not in zoneinfo.available_timezones():
            errors['timezone_name.invalid'] = "Unknown time zone!"

        policy = (postData.get('out_of_window') or '').strip()

        if policy not in dict(OUT_OF_WINDOW_CHOICES):
            errors['out_of_window.invalid'] = "Choose what happens after the check-in window!"

        return errors


class AttendanceSettings(models.Model):
    """Singleton row holding every configurable attendance rule."""

    working_days = models.JSONField(default=default_working_days)
    start_time = models.TimeField(default=time(9, 0))
    end_time = models.TimeField(default=time(17, 0))
    earliest_check_in = models.TimeField(default=time(7, 0))
    latest_check_in = models.TimeField(default=time(10, 0))
    timezone_name = models.CharField(max_length=64, default='Asia/Gaza')
    out_of_window = models.CharField(
        max_length=10,
        choices=OUT_OF_WINDOW_CHOICES,
        default=OUT_OF_WINDOW_LATE,
    )
    allow_non_working = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    objects = AttendanceSettingsManager()

    def __str__(self):
        """Return a readable settings label."""

        return "Attendance settings"

    @property
    def working_days_label(self):
        """Return the configured weekday numbers as a compact string."""

        names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        days = sorted(int(day) for day in (self.working_days or []) if 0 <= int(day) <= 6)

        return ", ".join(names[day] for day in days) or "None"


class HolidayManager(models.Manager):
    """Manager exposing the holiday CRUD validator."""

    def holiday_validator(self, postData, holiday_id=None):
        """Validate a holiday create/edit, de-duplicating dates by id."""

        errors = {}

        name = (postData.get('name') or '').strip()
        raw_date = (postData.get('date') or '').strip()
        holiday_date = None

        if name == '':
            errors['name.required'] = "Holiday name is required!"

        if raw_date == '':
            errors['date.required'] = "Holiday date is required!"
        else:
            try:
                holiday_date = datetime.strptime(raw_date, '%Y-%m-%d').date()
            except ValueError:
                errors['date.invalid'] = "Date must be formatted YYYY-MM-DD!"

        if holiday_date is not None:
            duplicate = self.filter(date=holiday_date)

            if holiday_id:
                duplicate = duplicate.exclude(id=holiday_id)

            if duplicate.exists():
                errors['date.unique'] = "That date is already a holiday!"

        return errors


class Holiday(models.Model):
    """A date on which check-ins are blocked unless the admin allows them."""

    name = models.CharField(max_length=100)
    date = models.DateField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = HolidayManager()

    class Meta:
        """Calendar order."""

        ordering = ['date']

    def __str__(self):
        """Return a readable holiday label."""

        return f"{self.name} ({self.date})"
