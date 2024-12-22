# core/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('encrypt/', views.encrypt_view, name='encrypt'),
    path('decrypt/', views.decrypt_list_view, name='decrypt-list'),
    path('decrypt/<int:image_id>/', views.decrypt_detail_view, name='decrypt-detail'),

    path('share/<int:image_id>/', views.share_image_view, name='share-image'),
    path('download/<int:image_id>/', views.download_stego_image, name='download-stego'),

    # Shared gallery for is_public images
    path('shared-gallery/', views.shared_gallery_view, name='shared-gallery'),

    # Optional upload route
    path('decrypt-upload/', views.decrypt_upload_view, name='decrypt-upload'),
]
