from django.urls import path
from django.conf.urls import include

from notes import views

urlpatterns = [
    path('auth/', include('rest_framework.urls')),
    path('key/<str:username>/', views.CryptoView.as_view(), name="rsa_keys"),
    path('getnotes/', views.ContentListView.as_view(), name="getnotes"),
    path('note/<int:pk>/', views.ContentView.as_view(), name="note_note"),
    path('note/', views.ContentCreateView.as_view(), name="note_note2"),
    path('note/<int:content_id>/setkey/', views.KeyViewP.as_view(), name="aes_keys_set"),
    path('note/<int:content_id>/getkey/', views.KeyView.as_view(), name="aes_keys_get"),
    path('note/<int:content_id>/delkey/<str:username>/', views.KeyViewD.as_view(), name="aes_keys_del"),
]
