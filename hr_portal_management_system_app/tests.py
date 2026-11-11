import bcrypt
import base64
import json
import re

from datetime import date, datetime, time, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .attendance_rules import evaluate_check_in, local_now
from .helper_functions import record_attendance
from .models import Attendance, AttendanceSettings, Holiday, Passkey, PasswordResetToken, User


class NotFoundPageTests(TestCase):

    @override_settings(DEBUG=True)
    def test_unknown_url_renders_custom_not_found_page(self):
        response = self.client.get('/this-page-does-not-exist/')

        self.assertEqual(response.status_code, 404)
        self.assertContains(response, 'Page not found', status_code=404)
        self.assertContains(response, 'Back to home', status_code=404)


def make_user(email='sara@example.com'):
    """Create a user with a known password."""
    return User.objects.create(
        first_name='Sara',
        last_name='Ali',
        email=email,
        password=bcrypt.hashpw(b'Password123', bcrypt.gensalt()).decode(),
    )


def request_code(client, email):
    """Ask for a reset code and return the code that was emailed."""
    client.post(reverse('forget_password'), {'email': email})
    return re.search(r'\d{6}', mail.outbox[-1].body).group()


class ForgetPasswordTests(TestCase):

    def test_forget_page_loads(self):
        response = self.client.get(reverse('forget_password'))
        self.assertEqual(response.status_code, 200)

    def test_code_is_emailed_to_known_user(self):
        make_user()
        response = self.client.post(reverse('forget_password'), {'email': 'sara@example.com'})

        self.assertRedirects(response, reverse('code_verification'))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['sara@example.com'])

    def test_unknown_email_sends_no_mail(self):
        response = self.client.post(reverse('forget_password'), {'email': 'nobody@example.com'})

        self.assertRedirects(response, reverse('forget_password'))
        self.assertEqual(len(mail.outbox), 0)


class VerificationTests(TestCase):

    def test_wrong_code_is_rejected(self):
        make_user()
        code = request_code(self.client, 'sara@example.com')
        wrong_code = '000000' if code != '000000' else '111111'

        response = self.client.post(reverse('code_verification'), {'verification_code': wrong_code})

        self.assertRedirects(response, reverse('code_verification'))
        self.assertNotIn('reset_user_id', self.client.session)

    def test_right_code_opens_reset_page(self):
        user = make_user()
        code = request_code(self.client, 'sara@example.com')

        response = self.client.post(reverse('code_verification'), {'verification_code': code})

        self.assertRedirects(response, reverse('reset_password'))
        self.assertEqual(self.client.session['reset_user_id'], user.id)

    def test_expired_code_is_rejected(self):
        make_user()
        code = request_code(self.client, 'sara@example.com')

        # Backdate every token so it is older than 10 minutes.
        PasswordResetToken.objects.update(
            created_at=timezone.now() - timedelta(minutes=11)
        )

        response = self.client.post(reverse('code_verification'), {'verification_code': code})

        self.assertRedirects(response, reverse('code_verification'))
        self.assertNotIn('reset_user_id', self.client.session)

    def test_verification_page_needs_a_requested_code(self):
        response = self.client.get(reverse('code_verification'))
        self.assertRedirects(response, reverse('forget_password'))

    def test_verification_page_shows_after_requesting_a_code(self):
        make_user()
        request_code(self.client, 'sara@example.com')

        response = self.client.get(reverse('code_verification'))

        self.assertEqual(response.status_code, 200)

    def test_code_cannot_be_used_twice(self):
        make_user()
        code = request_code(self.client, 'sara@example.com')
        self.client.post(reverse('code_verification'), {'verification_code': code})

        response = self.client.post(reverse('code_verification'), {'verification_code': code})

        self.assertRedirects(response, reverse('code_verification'))


class ResetPasswordTests(TestCase):

    def do_reset(self, password, confirm_password):
        return self.client.post(
            reverse('reset_password'),
            {'password': password, 'confirm_password': confirm_password},
        )

    def logged_in_session(self, user_id):
        """Put a verified reset into the session, like verification would."""
        session = self.client.session
        session['reset_user_id'] = user_id
        session.save()

    def test_password_is_changed(self):
        user = make_user()
        self.logged_in_session(user.id)

        response = self.do_reset('NewPassword1', 'NewPassword1')

        self.assertRedirects(response, reverse('login'))
        user.refresh_from_db()
        self.assertTrue(bcrypt.checkpw(b'NewPassword1', user.password.encode()))

    def test_password_change_sends_a_notification_email(self):
        user = make_user()
        self.logged_in_session(user.id)

        self.do_reset('NewPassword1', 'NewPassword1')

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['sara@example.com'])
        self.assertIn('password was changed', mail.outbox[0].subject)

    def test_reset_succeeds_even_when_the_email_fails(self):
        user = make_user()
        self.logged_in_session(user.id)

        with patch(
            'hr_portal_management_system_app.auth.EmailMultiAlternatives.send',
            side_effect=Exception('SMTP is down'),
        ):
            response = self.do_reset('NewPassword1', 'NewPassword1')

        # The password is already saved, so the flow still finishes.
        self.assertRedirects(response, reverse('login'))
        user.refresh_from_db()
        self.assertTrue(bcrypt.checkpw(b'NewPassword1', user.password.encode()))

    def test_short_password_is_rejected(self):
        user = make_user()
        self.logged_in_session(user.id)

        response = self.do_reset('short', 'short')

        self.assertRedirects(response, reverse('reset_password'))
        user.refresh_from_db()
        self.assertFalse(bcrypt.checkpw(b'short', user.password.encode()))

    def test_mismatched_passwords_are_rejected(self):
        user = make_user()
        self.logged_in_session(user.id)

        response = self.do_reset('NewPassword1', 'OtherPassword1')

        self.assertRedirects(response, reverse('reset_password'))
        user.refresh_from_db()
        self.assertTrue(bcrypt.checkpw(b'Password123', user.password.encode()))

    def test_reset_page_needs_a_verified_code(self):
        response = self.client.get(reverse('reset_password'))
        self.assertRedirects(response, reverse('forget_password'))

    def test_reset_page_shows_after_the_code_is_verified(self):
        user = make_user()
        self.logged_in_session(user.id)

        response = self.client.get(reverse('reset_password'))

        self.assertEqual(response.status_code, 200)


class PasskeyLoginOptionsTests(TestCase):

    def test_login_options_decode_legacy_and_base64url_credential_ids(self):
        user = make_user()
        credential_id = b'\x01\x02credential-id'
        encoded_id = base64.urlsafe_b64encode(credential_id).decode().rstrip('=')

        for stored_id in (str(credential_id), encoded_id):
            with self.subTest(stored_id=stored_id):
                Passkey.objects.create(
                    user=user,
                    credential_id=stored_id,
                    public_key=b'public-key',
                )

                response = self.client.post(
                    reverse('passkey_login_begin'),
                    data=json.dumps({'email': user.email}),
                    content_type='application/json',
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.json()['allowCredentials'][0]['id'],
                    encoded_id,
                )

                Passkey.objects.filter(user=user).delete()


class CheckInWindowTests(TestCase):
    """The window is strict: no scans before it opens or after it closes."""

    def rules(self, out_of_window='reject'):
        rules = AttendanceSettings.objects.load()
        # Every day is a working day here, so the date never decides the outcome.
        rules.working_days = list(range(7))
        rules.out_of_window = out_of_window
        rules.save()
        return rules

    def test_scan_before_window_opens_is_rejected(self):
        counted, reason = evaluate_check_in(
            self.rules(), datetime(2026, 11, 9, 6, 30)
        )

        self.assertFalse(counted)
        self.assertIn('opens at 07:00', reason)

    def test_scan_after_window_closes_is_rejected(self):
        # 6 PM used to be accepted as 'late' because the old default was 'late'.
        counted, reason = evaluate_check_in(
            self.rules(), datetime(2026, 11, 9, 18, 0)
        )

        self.assertFalse(counted)
        self.assertIn('closed at 10:00', reason)

    def test_scan_after_start_but_inside_window_is_late(self):
        counted, outcome = evaluate_check_in(
            self.rules(), datetime(2026, 11, 9, 9, 30)
        )

        self.assertTrue(counted)
        self.assertEqual(outcome, 'late')

    def test_scan_before_start_counts_as_present(self):
        counted, outcome = evaluate_check_in(
            self.rules(), datetime(2026, 11, 9, 8, 0)
        )

        self.assertTrue(counted)
        self.assertEqual(outcome, 'present')

    def test_late_policy_still_allows_an_evening_scan(self):
        # The option stays available for an admin who wants it.
        counted, outcome = evaluate_check_in(
            self.rules('late'), datetime(2026, 11, 9, 18, 0)
        )

        self.assertTrue(counted)
        self.assertEqual(outcome, 'late')


class AbsentAttendanceTests(TestCase):
    """A day with a clock-in but no clock-out ends absent, not 'in progress'."""

    def open_record(self, work_date):
        return Attendance.objects.create(
            user=make_user(),
            work_date=work_date,
            check_in=timezone.now(),
            status=Attendance.STATUS_PRESENT,
        )

    def open_dashboard(self):
        self.client.post(
            reverse('login'),
            {'email': 'sara@example.com', 'password': 'Password123'},
        )
        return self.client.get(reverse('dashboard'))

    def test_past_day_without_clock_out_is_marked_absent(self):
        record = self.open_record(local_now().date() - timedelta(days=1))

        response = self.open_dashboard()

        record.refresh_from_db()
        self.assertEqual(record.status, Attendance.STATUS_ABSENT)
        self.assertContains(response, 'Absent')

    def test_today_without_clock_out_stays_in_progress(self):
        record = self.open_record(local_now().date())

        response = self.open_dashboard()

        record.refresh_from_db()
        self.assertEqual(record.status, Attendance.STATUS_PRESENT)
        self.assertContains(response, 'In progress')


class RejectedScanAbsentTests(TestCase):
    """A rejected scan after the window closes leaves an absent record."""

    gaza = ZoneInfo('Asia/Gaza')

    def rules(self, working_days=None):
        rules = AttendanceSettings.objects.load()
        rules.timezone_name = 'Asia/Gaza'
        rules.out_of_window = 'reject'
        # Every day is a working day here unless a test says otherwise,
        # so the date never decides the outcome by accident.
        rules.working_days = list(range(7)) if working_days is None else working_days
        rules.save()
        return rules

    def signed_up_user(self):
        user = make_user()
        passkey = Passkey.objects.create(
            user=user,
            credential_id='scan-credential',
            public_key=b'public-key',
        )
        return user, passkey

    def scan_at(self, user, passkey, when):
        """Run one fingerprint scan at a fixed wall-clock moment."""
        with patch(
            'hr_portal_management_system_app.helper_functions.timezone.now',
            return_value=when,
        ):
            return record_attendance(user, passkey)

    def test_late_scan_is_rejected_and_recorded_as_absent(self):
        rules = self.rules()
        user, passkey = self.signed_up_user()

        status, reason = self.scan_at(
            user, passkey, datetime(2026, 11, 10, 11, 0, tzinfo=self.gaza),
        )

        self.assertEqual(status, 'rejected')
        self.assertIn('recorded as absent', reason)

        record = Attendance.objects.get(user=user, work_date=date(2026, 11, 10))
        self.assertEqual(record.status, Attendance.STATUS_ABSENT)
        self.assertIsNone(record.check_out)
        # check_in is NOT NULL: it carries the window close, not a real scan.
        self.assertEqual(
            record.check_in.astimezone(self.gaza),
            datetime(2026, 11, 10, rules.latest_check_in.hour,
                     rules.latest_check_in.minute, tzinfo=self.gaza),
        )

    def test_early_rejection_leaves_no_row_and_a_later_scan_still_counts(self):
        self.rules()
        user, passkey = self.signed_up_user()

        status, _reason = self.scan_at(
            user, passkey, datetime(2026, 11, 10, 6, 0, tzinfo=self.gaza),
        )

        self.assertEqual(status, 'rejected')
        self.assertFalse(Attendance.objects.filter(user=user).exists())

        status, _reason = self.scan_at(
            user, passkey, datetime(2026, 11, 10, 8, 0, tzinfo=self.gaza),
        )

        self.assertEqual(status, 'in')
        record = Attendance.objects.get(user=user)
        self.assertEqual(record.status, Attendance.STATUS_PRESENT)

    def test_repeat_scan_after_the_absent_record_stays_rejected(self):
        self.rules()
        user, passkey = self.signed_up_user()
        self.scan_at(
            user, passkey, datetime(2026, 11, 10, 11, 0, tzinfo=self.gaza),
        )

        status, reason = self.scan_at(
            user, passkey, datetime(2026, 11, 10, 12, 0, tzinfo=self.gaza),
        )

        self.assertEqual(status, 'rejected')
        self.assertIn('recorded as absent', reason)

        record = Attendance.objects.get(user=user, work_date=date(2026, 11, 10))
        self.assertEqual(record.status, Attendance.STATUS_ABSENT)
        self.assertIsNone(record.check_out)

    def test_rejection_on_a_non_working_day_records_nothing(self):
        # 2026-11-07 is a Saturday, which is not a working day here.
        self.rules(working_days=[0, 1, 2, 3, 6])
        user, passkey = self.signed_up_user()

        status, reason = self.scan_at(
            user, passkey, datetime(2026, 11, 7, 11, 0, tzinfo=self.gaza),
        )

        self.assertEqual(status, 'rejected')
        self.assertIn('not a working day', reason)
        self.assertFalse(Attendance.objects.filter(user=user).exists())

    def test_rejection_on_a_holiday_records_nothing(self):
        self.rules()
        Holiday.objects.create(name='Company day', date=date(2026, 11, 10))
        user, passkey = self.signed_up_user()

        status, reason = self.scan_at(
            user, passkey, datetime(2026, 11, 10, 11, 0, tzinfo=self.gaza),
        )

        self.assertEqual(status, 'rejected')
        self.assertIn('holiday', reason)
        self.assertFalse(Attendance.objects.filter(user=user).exists())

    def test_dashboard_does_not_offer_a_clock_out_for_an_absent_day(self):
        user, _passkey = self.signed_up_user()
        Attendance.objects.create(
            user=user,
            work_date=local_now().date(),
            check_in=timezone.now(),
            status=Attendance.STATUS_ABSENT,
        )

        self.client.post(
            reverse('login'),
            {'email': 'sara@example.com', 'password': 'Password123'},
        )
        response = self.client.get(reverse('dashboard'))

        self.assertTrue(response.context['today_absent'])
        self.assertEqual(response.context['open_attendance'], 0)
        self.assertContains(response, 'Absent today')
        self.assertContains(response, 'data-attendance-action="done"')
        self.assertContains(response, '<span class="fg-2">—</span>')


class SettingsPasswordChangeTests(TestCase):
    """Changing the password from Settings sends the same notice."""

    def change_password(self):
        return self.client.post(
            reverse('settings'),
            {
                'action': 'password',
                'current_password': 'Password123',
                'new_password': 'NewPassword1',
                'confirm_password': 'NewPassword1',
            },
        )

    def signed_in_client(self):
        make_user()
        self.client.post(
            reverse('login'),
            {'email': 'sara@example.com', 'password': 'Password123'},
        )

    def test_password_change_sends_a_notification_email(self):
        self.signed_in_client()

        response = self.change_password()

        self.assertRedirects(response, reverse('settings'))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['sara@example.com'])
        self.assertIn('password was changed', mail.outbox[0].subject)

    def test_password_change_survives_a_failed_email(self):
        self.signed_in_client()

        with patch(
            'hr_portal_management_system_app.auth.EmailMultiAlternatives.send',
            side_effect=Exception('SMTP is down'),
        ):
            response = self.change_password()

        self.assertRedirects(response, reverse('settings'))
        user = User.objects.get(email='sara@example.com')
        self.assertTrue(bcrypt.checkpw(b'NewPassword1', user.password.encode()))


class AdminSectionTests(TestCase):
    """The admin section is closed to everyone who is not an admin."""

    def sign_in(self, is_admin=False, email='sara@example.com'):
        user = make_user(email)

        if is_admin:
            User.objects.filter(pk=user.pk).update(is_admin=True)

        self.client.post(
            reverse('login'),
            {'email': email, 'password': 'Password123'},
        )
        return user

    def hours_form(self, **overrides):
        form = {
            'working_days': ['0', '1', '2', '3', '4'],
            'start_time': '08:30',
            'end_time': '16:30',
            'earliest_check_in': '08:00',
            'latest_check_in': '09:30',
            'timezone_name': 'Asia/Gaza',
            'out_of_window': 'reject',
            'allow_non_working': 'on',
        }
        form.update(overrides)
        return form

    def test_visitor_is_sent_to_login(self):
        response = self.client.get(reverse('admin_users'))

        self.assertRedirects(response, reverse('login'))

    def test_member_is_sent_to_dashboard(self):
        self.sign_in()

        response = self.client.get(reverse('admin_users'))

        self.assertRedirects(response, reverse('dashboard'))

    def test_admin_sees_every_user(self):
        self.sign_in(is_admin=True)
        make_user('mona@example.com')

        response = self.client.get(reverse('admin_users'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'sara@example.com')
        self.assertContains(response, 'mona@example.com')

    def test_users_page_shows_the_stats(self):
        self.sign_in(is_admin=True)
        make_user('mona@example.com')

        response = self.client.get(reverse('admin_users'))

        self.assertContains(response, 'Total users')
        self.assertContains(response, 'Admins')
        self.assertContains(response, 'Attendance records')
        self.assertContains(response, 'Registered accounts.')

    def test_users_list_is_paginated(self):
        self.sign_in(is_admin=True)
        for index in range(21):
            make_user(f'page{index}@example.com')

        first_page = self.client.get(reverse('admin_users'))

        # 22 accounts (sara + 21) means a second page exists.
        self.assertContains(first_page, 'Page 1 of 2')
        self.assertNotContains(first_page, 'page20@example.com')

        second_page = self.client.get(reverse('admin_users'), {'page': 2})

        self.assertContains(second_page, 'Page 2 of 2')
        self.assertContains(second_page, 'page20@example.com')

    def test_menu_shows_the_admin_link_to_admins(self):
        self.sign_in(is_admin=True)

        response = self.client.get(reverse('dashboard'))

        self.assertContains(response, reverse('admin_users'))

    def test_menu_hides_the_admin_link_from_members(self):
        self.sign_in()

        response = self.client.get(reverse('dashboard'))

        self.assertNotContains(response, reverse('admin_users'))

    def test_hours_page_prefills_the_current_rules(self):
        self.sign_in(is_admin=True)

        response = self.client.get(reverse('admin_attendance_hours'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'value="07:00"')  # earliest check-in
        self.assertContains(response, 'value="10:00"')  # latest check-in

    def test_hours_page_uses_bootstrap_6_form_classes(self):
        self.sign_in(is_admin=True)

        response = self.client.get(reverse('admin_attendance_hours'))

        self.assertContains(response, 'class="check theme-primary"')
        self.assertContains(response, 'class="radio theme-primary"')
        self.assertContains(response, '<select class="form-control"')
        # Bootstrap 5 classes were removed in B6, so they style nothing.
        self.assertNotContains(response, 'form-check')
        self.assertNotContains(response, 'form-select')

    def test_admin_can_save_the_attending_hours(self):
        self.sign_in(is_admin=True)

        response = self.client.post(
            reverse('admin_attendance_hours'),
            self.hours_form(),
        )

        self.assertRedirects(response, reverse('admin_attendance_hours'))
        rules = AttendanceSettings.objects.load()
        self.assertEqual(rules.working_days, [0, 1, 2, 3, 4])
        self.assertEqual(rules.start_time, time(8, 30))
        self.assertEqual(rules.end_time, time(16, 30))
        self.assertEqual(rules.earliest_check_in, time(8, 0))
        self.assertEqual(rules.latest_check_in, time(9, 30))
        self.assertEqual(rules.out_of_window, 'reject')
        self.assertTrue(rules.allow_non_working)

    def test_invalid_hours_are_rejected(self):
        self.sign_in(is_admin=True)
        before = AttendanceSettings.objects.load()

        # Latest check-in earlier than the earliest one is not allowed.
        response = self.client.post(
            reverse('admin_attendance_hours'),
            self.hours_form(latest_check_in='07:00'),
        )

        self.assertRedirects(response, reverse('admin_attendance_hours'))
        rules = AttendanceSettings.objects.load()
        self.assertEqual(rules.latest_check_in, before.latest_check_in)
        self.assertEqual(rules.working_days, before.working_days)

    def test_member_cannot_save_the_attending_hours(self):
        self.sign_in()
        before = AttendanceSettings.objects.load()

        response = self.client.post(
            reverse('admin_attendance_hours'),
            self.hours_form(),
        )

        self.assertRedirects(response, reverse('dashboard'))
        rules = AttendanceSettings.objects.load()
        self.assertEqual(rules.start_time, before.start_time)

    def test_hours_page_marks_the_saved_policy_checked(self):
        rules = AttendanceSettings.objects.load()
        rules.out_of_window = 'late'
        rules.save()
        self.sign_in(is_admin=True)

        response = self.client.get(reverse('admin_attendance_hours'))

        # The radio for the saved policy renders checked; the others do not.
        self.assertContains(response, 'id="id_late" checked')
        self.assertNotContains(response, 'id="id_reject" checked')

    def test_hours_page_selects_the_saved_timezone(self):
        rules = AttendanceSettings.objects.load()
        rules.timezone_name = 'Asia/Tokyo'
        rules.save()
        self.sign_in(is_admin=True)

        response = self.client.get(reverse('admin_attendance_hours'))

        # Without the fix no option was ever selected, so the dropdown always
        # fell back to the first zone (Africa/Abidjan).
        self.assertContains(response, '<option value="Asia/Tokyo" selected>')

    def test_schedule_section_saves_only_the_schedule(self):
        rules = AttendanceSettings.objects.load()
        rules.out_of_window = 'late'
        rules.save()
        self.sign_in(is_admin=True)

        # No window fields in the post: a schedule save must neither
        # validate nor touch the window card.
        form = self.hours_form(section='schedule')
        del form['out_of_window']
        del form['allow_non_working']

        response = self.client.post(reverse('admin_attendance_hours'), form)

        self.assertRedirects(response, reverse('admin_attendance_hours'))
        rules.refresh_from_db()
        self.assertEqual(rules.start_time, time(8, 30))
        self.assertEqual(rules.out_of_window, 'late')

    def test_window_section_saves_only_the_window(self):
        rules = AttendanceSettings.objects.load()
        rules.start_time = time(8, 45)
        rules.save()
        self.sign_in(is_admin=True)

        # No schedule fields in the post: a window save must neither
        # validate nor touch the schedule card.
        response = self.client.post(
            reverse('admin_attendance_hours'),
            {'section': 'window', 'out_of_window': 'late'},
        )

        self.assertRedirects(response, reverse('admin_attendance_hours'))
        rules.refresh_from_db()
        self.assertEqual(rules.out_of_window, 'late')
        self.assertEqual(rules.start_time, time(8, 45))

    def test_hours_page_renders_a_save_button_per_card(self):
        self.sign_in(is_admin=True)

        response = self.client.get(reverse('admin_attendance_hours'))

        self.assertContains(response, 'name="section" value="schedule"')
        self.assertContains(response, 'name="section" value="window"')
        self.assertContains(response, 'Save schedule')
        self.assertContains(response, 'Save window rules')
