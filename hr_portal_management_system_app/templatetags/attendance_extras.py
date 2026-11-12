"""Template filters for attendance display formatting."""

from django import template

register = template.Library()


@register.filter
def duration(record):
    """Format the worked duration, or a placeholder while the day is open."""

    if record.check_out is None:
        # The day closed without a clock-out: it was marked absent.
        if record.status == record.STATUS_ABSENT:
            return "No check-out"

        return "In progress"

    seconds = int((record.check_out - record.check_in).total_seconds())

    if seconds < 60:
        return "<1m"

    hours, minutes = divmod(seconds // 60, 60)

    if hours:
        return f"{hours}h {minutes}m"

    return f"{minutes}m"
