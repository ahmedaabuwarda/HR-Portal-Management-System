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

    path('dashboard', views.dashboard, name='dashboard'),
    path('settings', views.settings, name='settings'),
    path("user/passkeys/register/begin", views.passkey_register_begin, name="passkey_register_begin"),
    path("user/passkeys/register/complete", views.passkey_register_complete, name="passkey_register_complete"),

]