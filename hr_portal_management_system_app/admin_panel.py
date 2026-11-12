"""Admin section: the user list and the attending-hours rules.

Every view here is guarded by ``require_admin``; nothing in this module
runs for a visitor who is not signed in as an admin. Django's own admin
site is not used at all.
"""

import json
import urllib.request
from zoneinfo import available_timezones

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
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


def _ask_gemini(prompt):
    """Send one prompt to Gemini and return its reply (stdlib only)."""

    if not settings.GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set")

    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"max_output_tokens": 1000},
    }).encode()

    call = urllib.request.Request(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": settings.GEMINI_API_KEY,
        },
    )

    with urllib.request.urlopen(call, timeout=30) as reply:
        data = json.loads(reply.read().decode())

    # Skip any thought parts and return the first real text part.
    parts = data["candidates"][0]["content"].get("parts", [])
    text = next((part["text"] for part in parts if "text" in part), None)

    if not text:
        raise RuntimeError("Gemini returned no text")

    return text


def admin_ai_analysis(request):
    """Show one employee's attendance counts, or a short AI write-up of them."""

    _admin, denied = require_admin(request)

    if denied is not None:
        return denied

    raw_id = request.GET.get('user') or ''
    target = User.objects.filter(pk=raw_id).first() if raw_id.isdigit() else None

    if target is None:
        messages.error(request, "That user does not exist!")
        return redirect('admin_users')

    stats = target.attendance.aggregate(
        total=Count('id'),
        present=Count('id', filter=Q(status=Attendance.STATUS_PRESENT)),
        late=Count('id', filter=Q(status=Attendance.STATUS_LATE)),
        absent=Count('id', filter=Q(status=Attendance.STATUS_ABSENT)),
    )

    analysis = None

    # POST: ask Gemini for a short paragraph about these numbers.
    if request.method == 'POST':
        prompt = (
            "You are an HR assistant. In 3-4 plain sentences analyze this "
            f"employee's attendance: {stats['total']} recorded days - "
            f"{stats['present']} present, {stats['late']} late, "
            f"{stats['absent']} absent. Comment on reliability and give "
            "one short suggestion."
        )

        try:
            analysis = _ask_gemini(prompt)
        except Exception:
            messages.error(request, "AI analysis failed - check the key and try again.")

    context = {'target': target, 'stats': stats, 'analysis': analysis}
    return render(request, 'admin/analysis.html', context)
