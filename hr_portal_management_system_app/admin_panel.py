"""Admin section: the user list and the attending-hours rules.

Every view here is guarded by ``require_admin``; nothing in this module
runs for a visitor who is not signed in as an admin. Django's own admin
site is not used at all.
"""

from zoneinfo import available_timezones

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import redirect, render

from .helper_functions import current_user
from .models import OUT_OF_WINDOW_CHOICES, Attendance, AttendanceSettings, User
from .utils import parse_time, working_days_value

# Weekday numbers with the names used by the working-days checkboxes.
WORKING_DAYS = [
    (0, 'Monday'),
    (1, 'Tuesday'),
    (2, 'Wednesday'),
    (3, 'Thursday'),
    (4, 'Friday'),
    (5, 'Saturday'),
    (6, 'Sunday'),
]


def require_admin(request):
    """Return ``(admin, None)`` for an admin, or ``(None, response)`` otherwise."""

    user = current_user(request)

    if user is None:
        messages.error(request, "You must log in first!")
        return None, redirect('login')

    if not user.is_admin:
        messages.error(request, "Admin access only!")
        return None, redirect('dashboard')

    return user, None


def admin_users(request):
    """List every account in the portal."""

    _admin, denied = require_admin(request)

    if denied is not None:
        return denied

    users = User.objects.annotate(
        attendance_count=Count('attendance', distinct=True),
    ).order_by('id')

    # Same 20-per-page pattern as the dashboard history table.
    page_obj = Paginator(users, 20).get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'total_users': page_obj.paginator.count,
        'admin_count': User.objects.filter(is_admin=True).count(),
        'record_count': Attendance.objects.count(),
    }
    return render(request, 'admin/users.html', context)


def admin_attendance_hours(request):
    """Show the attending-hours rules, or save the submitted ones."""

    _admin, denied = require_admin(request)

    if denied is not None:
        return denied

    rules = AttendanceSettings.objects.load()

    # GET: show the form filled with the current rules.
    if request.method == 'GET':
        context = {
            'rules': rules,
            'working_days': WORKING_DAYS,
            'out_of_window_choices': OUT_OF_WINDOW_CHOICES,
            'timezones': sorted(available_timezones()),
        }
        return render(request, 'admin/settings.html', context)

    # POST: validate first, then write the new rules. Each card of the page
    # saves on its own; ``section`` says which one was submitted.
    section = (request.POST.get('section') or '').strip() or None

    if section not in ('schedule', 'window'):
        section = None

    errors = AttendanceSettings.objects.settings_validator(request.POST, section=section)

    if errors:
        for _key, message in errors.items():
            messages.error(request, message)

        return redirect('admin_attendance_hours')

    if section != 'window':
        rules.working_days = working_days_value(request.POST)
        rules.start_time = parse_time(request.POST.get('start_time'))
        rules.end_time = parse_time(request.POST.get('end_time'))
        rules.earliest_check_in = parse_time(request.POST.get('earliest_check_in'))
        rules.latest_check_in = parse_time(request.POST.get('latest_check_in'))
        rules.timezone_name = (request.POST.get('timezone_name') or '').strip()

    if section != 'schedule':
        rules.out_of_window = (request.POST.get('out_of_window') or '').strip()
        rules.allow_non_working = request.POST.get('allow_non_working') == 'on'

    rules.save()

    messages.success(request, {
        'schedule': "Schedule updated!",
        'window': "Window rules updated!",
    }.get(section, "Attending hours updated!"))
    return redirect('admin_attendance_hours')
