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
    """Generic rate limiting decorator with user-based tracking"""
    def decorator(func):
        @wraps(func)
        def wrapped(request, *args, **kwargs):
            # For login/register, use IP-based tracking
            if key_prefix in ['login', 'register']:
                key = f"{key_prefix}_{get_client_ip(request)}"
            else:
                # For uploads/downloads, use user-based tracking
                if not request.user.is_authenticated:
                    return HttpResponseForbidden("Authentication required")
                key = f"{key_prefix}_user_{request.user.id}"
            
            # Get current attempts
            attempts = cache.get(key, {'count': 0, 'first_attempt': time.time()})
            
            # Reset if window expired
            if time.time() - attempts['first_attempt'] > window:
                attempts = {'count': 0, 'first_attempt': time.time()}
            
            # Check if exceeded
            if attempts['count'] >= max_attempts:
                remaining = int(window - (time.time() - attempts['first_attempt']))
                if hasattr(request, 'session'):
                    messages.error(request, 
                        f"Too many attempts. Please wait {remaining} seconds.")
                return HttpResponseForbidden(
                    f"Rate limit exceeded. Try again in {remaining} seconds.")
            
            # Increment attempts
            attempts['count'] += 1
            cache.set(key, attempts, window)
            
            return func(request, *args, **kwargs)
        return wrapped
    return decorator

def login_rate_limit(func):
    """Login rate limiting - 10 attempts per minute"""
    @wraps(func)
    @rate_limit('login', max_attempts=10, window=60)
    def wrapped(request, *args, **kwargs):
        return func(request, *args, **kwargs)
    return wrapped

def register_rate_limit(func):
    """Registration rate limiting - 10 attempts per minute"""
    @wraps(func)
    @rate_limit('register', max_attempts=10, window=60)
    def wrapped(request, *args, **kwargs):
        return func(request, *args, **kwargs)
    return wrapped

def api_rate_limit(func):
    """API rate limiting - 100 requests per minute per user"""
    @wraps(func)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Authentication required")
        
        user_id = request.user.id
        key = f"api_limit_user_{user_id}"
        
        # Per-minute limit
        minute_calls = cache.get(key, 0)
        if minute_calls >= 100:
            remaining = 60 - int(time.time() % 60)
            return HttpResponseForbidden(
                f"API rate limit exceeded. Try again in {remaining} seconds.")
        cache.set(key, minute_calls + 1, 60)
        
        return func(request, *args, **kwargs)
    return wrapped

def upload_rate_limit(func):
    """Upload rate limiting - 50 uploads per 5 minutes"""
    @wraps(func)
    @rate_limit('upload', max_attempts=50, window=300)
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