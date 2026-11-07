from django.urls import path
from . import views

urlpatterns = [
    # static pages urls: index, contact-us, about-us
    path('', views.home, name='home'),
    path('contact_us', views.contact_us, name='contact_us'),
    path('about_us', views.about_us, name='about_us'),
    # authentication urls: login, logout, register
    path('login', views.login, name='login'),
    path('register', views.register, name='register'),
    path('logout', views.logout, name='logout'),
    # login using passkey + check in
    path("passkeys/login/begin", views.passkey_login_begin, name="passkey_login_begin"),
    path("passkeys/login/complete", views.passkey_login_complete, name="passkey_login_complete"),
    # forget password flow 
    path('forget_password', views.forget_password, name='forget_password'),
    path('code_verification', views.code_verification, name='code_verification'),
    path('reset_password', views.reset_password, name='reset_password'),
    # pages only for auth users/admins 
    path('dashboard', views.dashboard, name='dashboard'),
    path('settings', views.settings, name='settings'),
    # add new passkey /delete passkey flow
    path("passkeys/register/begin", views.passkey_register_begin, name="passkey_register_begin"),
    path("passkeys/register/complete", views.passkey_register_complete, name="passkey_register_complete"),
    path("passkeys/<int:passkey_id>/delete", views.passkey_delete, name="passkey_delete"),
    # attendence check in/out using fingerprint
    path("attendance/begin", views.attendance_begin, name="attendance_begin"),
    path("attendance/complete", views.attendance_complete, name="attendance_complete"),
    # 404 page for the wrong endpoints  
    path('<path:unmatched>', views.not_found, name='not_found'),
]
