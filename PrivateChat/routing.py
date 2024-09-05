from django.urls import path
from . import consumers

websocket_urlpatterns = [
   # path('ws/sc/', consumers.PrivateChatConsumer.as_asgi())
   path('ws/sc/<str:room_name>/', consumers.PrivateChatConsumer.as_asgi())

]