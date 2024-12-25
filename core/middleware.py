# core/middleware.py
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.conf import settings
import time
from functools import wraps
from django.http import JsonResponse

class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith((settings.STATIC_URL, settings.MEDIA_URL)):
            return self.get_response(request)

        # Basic request validation
        if len(request.body) > settings.DATA_UPLOAD_MAX_MEMORY_SIZE:
            return HttpResponseForbidden("Request too large")

        return self.get_response(request)