from django.urls import path
from django.conf.urls import include

from notes import views


urlpatterns = [
    path('auth/', include('rest_framework.urls')),
    path('key/<str:username>/', views.CryptoView.as_view(), name="rsa_keys"),
    path('getnotes/', views.ContentListView.as_view(), name="getnotes"),
    path('note/<int:pk>/', views.ContentView.as_view(), name="note"),
    path('note/', views.ContentCreateView.as_view(), name="note_add"),
    path('note/<int:content_id>/setkey/<str:username>/', views.KeyView.as_view({'put': 'put', 'post': 'post'}), name="aes_keys_set"),
    path('note/<int:content_id>/getkey/<str:username>/', views.KeyView.as_view({'get': 'get'}), name="aes_keys_get"),
    path('note/<int:content_id>/delkey/<str:username>/', views.KeyView.as_view({'delete': 'delete'}), name="aes_keys_del"),
]
