"""Server-side attendance rules: working days, check-in windows and holidays.

Every decision about whether a scan counts as attendance is made here, from
the configured ``AttendanceSettings`` and the *server's* clock in the
configured time zone. Pure functions only — no request, no session, no
rendering — so the rules are testable without an HTTP round trip.
"""

from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from .models import AttendanceSettings, Holiday, OUT_OF_WINDOW_LATE

# Python weekday(): 0 = Monday ... 6 = Sunday.
DAY_NAMES = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']


def settings_timezone(settings):
    """Return the configured zoneinfo, falling back to Django's own setting."""

    try:
        return ZoneInfo(settings.timezone_name)
    except Exception:
        from django.conf import settings as django_settings
        return ZoneInfo(django_settings.TIME_ZONE)


def local_now(settings=None):
    """Return the current wall-clock ``datetime`` in the attendance time zone."""

    from django.utils import timezone

    if settings is None:
        settings = AttendanceSettings.objects.load()

    return timezone.now().astimezone(settings_timezone(settings))


def is_working_day(settings, work_date):
    """Return ``True`` when the date is a configured working day."""

    days = [int(day) for day in (settings.working_days or [])]

    return work_date.weekday() in days


def holiday_on(work_date, holiday_dates=None):
    """Return the holiday name for a date, or ``None`` when there is none."""

    if holiday_dates is None:
        holiday = Holiday.objects.filter(date=work_date).first()
        return holiday.name if holiday else None

    return holiday_dates.get(work_date)


def evaluate_check_in(settings, local_dt, holiday_dates=None):
    """Decide whether a candidate check-in counts.

    Returns ``(True, 'present')`` / ``(True, 'late')`` when the scan may be
    recorded, or ``(False, reason)`` with a message safe to show the user.

    Order of the rules:
      1. holiday or non-working day — blocked unless the admin allows it;
      2. before the earliest permitted check-in — never counts, whatever the
         out-of-window policy says;
      3. after the latest permitted check-in — the configured policy decides;
      4. after the scheduled start but inside the window — recorded as late.
    """

    work_date = local_dt.date()
    clock = local_dt.timetz().replace(tzinfo=None)

    if holiday_dates is None:
        holiday_dates = {}

    holiday_name = holiday_on(work_date, holiday_dates)

    if holiday_name is not None and not settings.allow_non_working:
        return False, f"{work_date.strftime('%Y-%m-%d')} is a holiday ({holiday_name}). Check-ins are not allowed."

    if not is_working_day(settings, work_date) and not settings.allow_non_working:
        day_name = DAY_NAMES[work_date.weekday()]
        return False, f"{day_name} is not a working day. Check-ins are not allowed."

    if clock < settings.earliest_check_in:
        opens = settings.earliest_check_in.strftime('%H:%M')
        return False, f"The check-in window opens at {opens}. Check-ins before that time are not counted."

    if clock > settings.latest_check_in:
        if settings.out_of_window != OUT_OF_WINDOW_LATE:
            closes = settings.latest_check_in.strftime('%H:%M')
            return False, f"The check-in window closed at {closes}. This check-in is not counted."

        return True, 'late'

    if clock > settings.start_time:
        return True, 'late'

    return True, 'present'


def add_minutes(some_time, minutes):
    """Return ``some_time`` shifted by ``minutes`` (used to build test windows)."""
    base = datetime.combine(datetime(2000, 1, 1).date(), some_time)
    return (base + timedelta(minutes=minutes)).time()
