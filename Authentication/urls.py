from django.urls import path
from .views import register, LoginView, logout_view,profile_view,CustomUserDetailView,search_user

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),
    path('is_active/user/<int:pk>/', CustomUserDetailView.as_view(), name='user-detail'),
    path('search-user/', search_user, name='search_user'),
]
