from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth

# Create your views here.

# https://community.simpleisbetterthancomplex.com/t/forbidden-403-csrf-verification-failed-request-aborted/921/2
def signup(request):
    if request.method == 'POST':
        # The user has info and wants an account
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.get(username = request.POST['username'])
                return render(request, 'accounts/signup.html', {'error':'Username has already been taken'})
            except User.DoesNotExist:
                user = User.objects.create_user(request.POST['username'], password = request.POST['password1'])
                auth.login(request, user)
                return redirect('home')
        else:  # its a request.method == 'GET'
            return render(request, 'accounts/signup.html', {'error':'Passwords must match'})

    else:
        # THe user wants to see the login page
        return render(request, 'accounts/signup.html')
 
def login(request):
    if request.method == 'POST':
        # The user has sent data to be logged in
        user = auth.authenticate(username=request.POST['username'], password=request.POST['password'])
        if user is not None:
            auth.login(request, user)
            return redirect('home')
        else:
            return render(request, 'accounts/login.html', {'error':'Username or password is incorrect'})
    else:
        return render(request, 'accounts/login.html')
        # The user wants the page to enter the data in

def logout(request):
    if request.method == 'POST': # this stops the browser loading this page in the background and logging you out!
        auth.logout(request)           
        return redirect('home')