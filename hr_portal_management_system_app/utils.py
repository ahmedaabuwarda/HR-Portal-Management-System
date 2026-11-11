"""Input-parsing helpers shared by the models and the forms that post to them.

This module deliberately imports nothing from the rest of the app: the
models import from it, so importing them back would be circular.
"""

from datetime import datetime, time

# Sun-Thu (Django weekday(): 0 = Monday ... 6 = Sunday), matching the local week.
DEFAULT_WORKING_DAYS = [6, 0, 1, 2, 3]


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
