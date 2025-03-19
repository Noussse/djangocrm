from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from .forms import SignUpForm,AddRecordForm
from .models import Record
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.core.cache import cache
from django.shortcuts import render, redirect
from .models import Record

MAX_ATTEMPTS = 5  # Max login attempts
LOCK_TIME = 300   # Lockout time in seconds (5 minutes)

def home(request):
    # Session hijacking prevention
    if request.user.is_authenticated:
        # Check if the user's IP address has changed since login
        current_ip = request.META.get('REMOTE_ADDR')
        session_ip = request.session.get('user_ip', None)
        user_agent = request.META.get('HTTP_USER_AGENT')
        session_user_agent = request.session.get('user_agent', None)
        
        # If IP or user agent changed, potential session hijacking
        if (session_ip and session_ip != current_ip) or (session_user_agent and session_user_agent != user_agent):
            logout(request)
            messages.error(request, "Your session has expired for security reasons. Please login again.")
            return redirect('home')

        # Check session age for inactivity timeout
        last_activity = request.session.get('last_activity', None)
        if last_activity:
            import time
            current_time = int(time.time())
            # Timeout after 30 minutes of inactivity
            if (current_time - last_activity) > 1800:
                logout(request)
                messages.error(request, "Your session has expired due to inactivity. Please login again.")
                return redirect('home')
        
        # Update last activity timestamp
        request.session['last_activity'] = int(time.time())
    
    records = Record.objects.all()
    
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Validate inputs (prevent injection attacks)
        if not username or not password:
            messages.error(request, "Username and password cannot be empty.")
            return redirect('home')
        
        # Rate limiting: check login attempts
        attempts_key = f"login_attempts_{username}"
        is_locked_key = f"is_locked_{username}"
        
        # Check if user is locked
        if cache.get(is_locked_key):
            messages.error(request, f"Too many failed attempts. Try again in {LOCK_TIME // 60} minutes.")
            return redirect('home')
        
        # Get attempts count
        attempts = cache.get(attempts_key, 0)
        
        # Global rate limiting for the IP to prevent brute force across accounts
        ip_attempts_key = f"ip_attempts_{request.META.get('REMOTE_ADDR')}"
        ip_attempts = cache.get(ip_attempts_key, 0)
        
        if ip_attempts >= MAX_ATTEMPTS * 2:
            messages.error(request, "Too many login attempts from this IP address. Please try again later.")
            return redirect('home')
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Check if user account is active
            if not user.is_active:
                messages.error(request, "This account has been disabled. Please contact support.")
                return redirect('home')
                
            # Reset login attempts after successful login
            cache.delete(attempts_key)
            cache.delete(is_locked_key)
            
            # Log the user in
            login(request, user)
            
            # Store identifying information in session
            request.session['user_ip'] = request.META.get('REMOTE_ADDR')
            request.session['user_agent'] = request.META.get('HTTP_USER_AGENT')
            request.session['last_activity'] = int(time.time())
            
            # Generate a new session key for added security
            request.session.cycle_key()
            
            messages.success(request, "You have been logged in successfully.")
            return redirect('home')
        else:
            # Increment login attempt counter for username
            attempts += 1
            cache.set(attempts_key, attempts, timeout=LOCK_TIME)
            
            # Increment login attempt counter for IP
            cache.set(ip_attempts_key, ip_attempts + 1, timeout=LOCK_TIME)
            
            # If max attempts reached, lock the account
            if attempts >= MAX_ATTEMPTS:
                cache.set(is_locked_key, True, timeout=LOCK_TIME)
                messages.error(request, f"Too many failed attempts. Account locked for {LOCK_TIME // 60} minutes.")
            else:
                messages.error(request, f"Invalid credentials. {MAX_ATTEMPTS - attempts} attempts remaining.")
            
            return redirect('home')
    else:
        # Add CSRF token refresh for better security
        request.META["CSRF_COOKIE_USED"] = True
        return render(request, 'home.html', {'records': records})

def logout_user(request):
    logout(request)
    messages.success(request,"you have been logged out")
    return redirect('home')

def register_user(request):
    if request.method=='POST':
        form=SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username=form.cleaned_data['username']
            password=form.cleaned_data['password1']
            user=authenticate(username=username,password=password)
            login(request,user)
            messages.success(request,"you have registered succesfully")
            return redirect('home')
    else:
        form=SignUpForm()
        return render(request,'register.html',{'form':form})
    return render(request,'register.html',{'form':form})

def customar_record(request,pk):
    if request.user.is_authenticated:
        customer_record=Record.objects.get(id=pk)
        return render(request,'record.html',{'customer_record':customer_record})
    else:
        messages.success(request,"you need to be logged in to view this page")
        return redirect('home')

def delete_record(request,pk):
    if request.user.is_authenticated:
        delete_it=Record.objects.get(id=pk)
        delete_it.delete()
        messages.success(request,"Record deleted successfully")
        return redirect('home')
        redirect('home')
    else:
        messages.success(request,"you need to be logged in to view this page")
        return redirect('home')

def add_record(request):
	form = AddRecordForm(request.POST or None)
	if request.user.is_authenticated:
		if request.method == "POST":
			if form.is_valid():
				add_record = form.save()
				messages.success(request, "Record Added...")
				return redirect('home')
		return render(request, 'add_record.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')
def update_record(request,pk):
    current_record = Record.objects.get(id=pk)
    form = AddRecordForm(request.POST or None,instance=current_record)
    if request.user.is_authenticated:
        if request.method == "POST":
            if form.is_valid():
                add_record = form.save()
                messages.success(request, "Record Updated...")
                return redirect('home')
        return render(request, 'update_record.html', {'form':form})
    else:
        messages.success(request, "You Must Be Logged In...")
        return redirect('home')