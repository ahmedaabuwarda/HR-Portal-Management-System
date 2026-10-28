from django.urls import path
from . import views

urlpatterns = [
    # static pages urls: index, contact-us, about-us
    path('', views.index, name='index'),
    path('contact_us/', views.contact_us, name='contact_us'),
    path('about_us/', views.about_us, name='about_us'),
    # authentication urls: login, logout, register
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),
]