from django.urls import path
from .views import  RoomMessagesView,RoomListCreateView

urlpatterns = [
    path('rooms/', RoomListCreateView.as_view(), name='room-list-create'),
    path('rooms/messages/<str:room_id>/', RoomMessagesView.as_view(), name='room-messages'),
]
