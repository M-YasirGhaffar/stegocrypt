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
    path('public-gallery/', views.public_gallery_view, name='public-gallery'),
]
