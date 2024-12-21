# core/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Home / index
    path('', views.index, name='index'),
    
    # Auth
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Steganography
    path('encrypt/', views.encrypt_view, name='encrypt'),
    path('decrypt/', views.decrypt_list_view, name='decrypt-list'),    # choose image
    path('decrypt/<int:image_id>/', views.decrypt_detail_view, name='decrypt-detail'),
]
