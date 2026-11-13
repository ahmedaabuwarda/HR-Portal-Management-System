"""One-off factory seeding: 10 demo members + passkeys + attendance."""

import random
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import bcrypt

from hr_portal_management_system_app.models import Attendance, Passkey, User

Gaza = ZoneInfo('Asia/Gaza')
WORK_WEEK = {6, 0, 1, 2, 3}  # Sun-Thu (Django weekday numbers)
random.seed(42)

NAMES = [
    ('Sara', 'Ali'), ('Mona', 'Hassan'), ('Ahmed', 'Yousef'), ('Lina', 'Kareem'),
    ('Omar', 'Nabil'), ('Dina', 'Salem'), ('Fares', 'Amin'), ('Rana', 'Tarek'),
    ('Khaled', 'Mansour'), ('Nour', 'Faris'),
]

# Behaviour archetypes: (late chance, absent chance, check-in window)
ARCHETYPES = [
    (0.05, 0.00, (7, 40, 8, 50)),  # demo01..demo06 punctual
    (0.05, 0.00, (7, 40, 8, 50)),
    (0.05, 0.00, (7, 40, 8, 50)),
    (0.05, 0.00, (7, 40, 8, 50)),
    (0.05, 0.00, (7, 40, 8, 50)),
    (0.05, 0.00, (7, 40, 8, 50)),
    (0.80, 0.05, (9, 5, 9, 45)),   # demo07, demo08 often late
    (0.80, 0.05, (9, 5, 9, 45)),
    (0.25, 0.35, (7, 45, 8, 30)),  # demo09 troublemaker: frequent absences
    (0.20, 0.10, (7, 45, 8, 30)),  # demo10 balanced
]


def aware(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi, tzinfo=Gaza)


# --- Clean previous demo rows only (safe to re-run) ---
old = User.objects.filter(email__endswith='@hrportal.com', email__regex=r'^demo\d+@')
print('removing previous demo users:', old.count())
old.delete()

# --- 10 members ---
users = []
for index, (first, last) in enumerate(NAMES, start=1):
    user = User.objects.create(
        first_name=first,
        last_name=last,
        email=f'demo{index:02d}@hrportal.com',
        password=bcrypt.hashpw(b'Password123', bcrypt.gensalt()).decode(),
    )
    users.append(user)

# Staggered registration dates, oldest first (auto_now_add ignores values at create).
today = date.today()
for offset, user in enumerate(users):
    registered = today - timedelta(days=70 - offset * 3)
    User.objects.filter(pk=user.pk).update(
        created_at=aware(registered.year, registered.month, registered.day, 10, 15)
    )

# --- One passkey each (fabricated credential; password login still works) ---
passkeys = []
for user in users:
    credential = random.randbytes(32)
    public_key = b'\xa5\x01\x03\x03\xa1\x01\x03\x20\x01' + random.randbytes(60)
    passkeys.append(Passkey.objects.create(
        user=user,
        label='Fingerprint',
        credential_id=credential.hex(),
        public_key=public_key,
        sign_count=0,
        transports=['internal'],
    ))

# --- Attendance: last 4 working weeks (working days only) ---
created = 0
for user, (late_chance, absent_chance, (h1, m1, h2, m2)) in zip(users, ARCHETYPES):
    user_passkey = Passkey.objects.get(user=user)

    for days_back in range(28, 0, -1):
        day = today - timedelta(days=days_back)

        if day.weekday() not in WORK_WEEK:
            continue

        roll = random.random()
        in_minute = random.randint(0, (h2 - h1) * 60 + (m2 - m1))
        in_time = aware(day.year, day.month, day.day, h1, m1) + timedelta(minutes=in_minute)

        if roll < absent_chance:
            # The day closed without a clock-out: recorded absent.
            Attendance.objects.create(
                user=user, work_date=day, check_in=in_time,
                status=Attendance.STATUS_ABSENT, method='passkey', passkey=user_passkey,
            )
        else:
            is_late = roll < absent_chance + late_chance
            out_time = aware(day.year, day.month, day.day, 16, random.randint(0, 55))
            Attendance.objects.create(
                user=user, work_date=day, check_in=in_time, check_out=out_time,
                status=Attendance.STATUS_LATE if is_late else Attendance.STATUS_PRESENT,
                method='passkey', passkey=user_passkey,
            )
        created += 1

    # Today: a couple of punctual users are clocked in right now.
    if user in users[:3] and today.weekday() in WORK_WEEK:
        Attendance.objects.get_or_create(
            user=user, work_date=today,
            defaults={
                'check_in': aware(today.year, today.month, today.day, 8, random.randint(5, 45)),
                'status': Attendance.STATUS_PRESENT,
                'method': 'passkey', 'passkey': user_passkey,
            },
        )
        created += 1

print('users created :', len(users))
print('passkeys      :', Passkey.objects.filter(user__email__regex=r'^demo\d+@').count())
print('attendance    :', created)
print('login with    : demo01@hrportal.com .. demo10@hrportal.com / Password123')
