from django.shortcuts import render

# Create your views here.
def home(request):
    return render(request, 'home.html')

def contact_us(request):
    return render(request, 'contact_us.html')

def about_us(request):
    return render(request, 'about_us.html')

def login(request):
    return render(request, 'registration/login.html')

def register(request):
    return render(request, 'registration/register.html')

def logout(request):
    return render(request, 'registration/logout.html')

def dashboard(request):
    return render(request, 'user/dashboard.html')