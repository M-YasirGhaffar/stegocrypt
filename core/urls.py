# core/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),

    # For login, register, logout
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Post routes for encryption/decryption inline
    path('post-encrypt/', views.post_encrypt, name='post-encrypt'),
    path('post-decrypt/<int:image_id>/', views.post_decrypt, name='post-decrypt'),

    # Download stego
    path('download-stego/<int:image_id>/', views.download_stego_image, name='download-stego'),

    # Share route
    path('share-image/<int:image_id>/', views.share_image_view, name='share-image'),

    # External stego upload & pass-key
    path('decrypt-upload/', views.decrypt_upload_view, name='decrypt-upload'),
]
