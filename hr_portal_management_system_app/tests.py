import bcrypt
import base64
import json
import re

from datetime import timedelta

from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Passkey, PasswordResetToken, User


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
