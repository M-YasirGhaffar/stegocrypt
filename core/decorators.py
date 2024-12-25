# core/decorators.py
from functools import wraps
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.conf import settings
import time
from django.contrib import messages
from django.shortcuts import redirect

def get_client_ip(request):
    """Get client IP from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def rate_limit(key_prefix, max_attempts, window):
    """Generic rate limiting decorator"""
    def decorator(func):
        @wraps(func)
        def wrapped(request, *args, **kwargs):
            ip = get_client_ip(request)
            user_id = request.user.id if request.user.is_authenticated else 'anonymous'
            cache_key = f"{key_prefix}_{ip}_{user_id}"
            
            # Get current attempts
            attempts = cache.get(cache_key, {'count': 0, 'first_attempt': time.time()})
            
            # Reset if window expired
            if time.time() - attempts['first_attempt'] > window:
                attempts = {'count': 0, 'first_attempt': time.time()}
            
            # Check if exceeded
            if attempts['count'] >= max_attempts:
                if hasattr(request, 'session'):
                    messages.error(request, f"Too many attempts. Please wait {window/60} minutes.")
                return HttpResponseForbidden(f"Rate limit exceeded. Try again in {window/60} minutes.")
            
            # Increment attempts
            attempts['count'] += 1
            cache.set(cache_key, attempts, window)
            
            # Add exponential backoff delay
            if attempts['count'] > 3:
                time.sleep(min(2 ** (attempts['count'] - 3), 8))
            
            return func(request, *args, **kwargs)
        return wrapped
    return decorator

def login_rate_limit(func):
    """Specific decorator for login attempts"""
    @wraps(func)
    @rate_limit('login', max_attempts=5, window=300)  # 5 attempts per 5 minutes
    def wrapped(request, *args, **kwargs):
        return func(request, *args, **kwargs)
    return wrapped

def register_rate_limit(func):
    """Specific decorator for registration attempts"""
    @wraps(func)
    @rate_limit('register', max_attempts=3, window=3600)  # 3 attempts per hour
    def wrapped(request, *args, **kwargs):
        return func(request, *args, **kwargs)
    return wrapped

def api_rate_limit(func):
    """Enhanced API rate limiting with user/IP tracking"""
    @wraps(func)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Authentication required")
        
        ip = get_client_ip(request)
        user_id = request.user.id
        
        # Combined IP + User key to prevent abuse
        key = f"api_limit_{ip}_{user_id}"
        minute_key = f"{key}_minute"
        hour_key = f"{key}_hour"
        
        # Per-minute limit
        minute_calls = cache.get(minute_key, 0)
        if minute_calls >= 100:  # 100 requests per minute
            return HttpResponseForbidden("API rate limit exceeded (per minute)")
        cache.set(minute_key, minute_calls + 1, 60)
        
        # Per-hour limit
        hour_calls = cache.get(hour_key, 0)
        if hour_calls >= 1000:  # 1000 requests per hour
            return HttpResponseForbidden("API rate limit exceeded (per hour)")
        cache.set(hour_key, hour_calls + 1, 3600)
        
        return func(request, *args, **kwargs)
    return wrapped

def upload_rate_limit(func):
    """Limit file uploads"""
    @wraps(func)
    @rate_limit('upload', max_attempts=10, window=60)  # 10 uploads per minute
    def wrapped(request, *args, **kwargs):
        return func(request, *args, **kwargs)
    return wrapped

def require_https(func):
    """Force HTTPS for sensitive operations"""
    @wraps(func)
    def wrapped(request, *args, **kwargs):
        if not request.is_secure() and not settings.DEBUG:
            return HttpResponseForbidden("HTTPS required for this operation")
        return func(request, *args, **kwargs)
    return wrapped