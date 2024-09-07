from django.urls import path
from .views import  RoomMessagesView

urlpatterns = [
    path('rooms/messages/<str:room_id>/', RoomMessagesView.as_view(), name='room-messages'),
]
