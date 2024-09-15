# # consumers.py
# from channels.generic.websocket import SyncConsumer
# from channels.exceptions import StopConsumer
# from asgiref.sync import async_to_sync
# import json

# from .models import Room,Message
# from django.contrib.auth.models import User
# from django.core.exceptions import ValidationError,PermissionDenied

# class PrivateChatConsumer(SyncConsumer):
#     def websocket_connect(self, event):
#         print('User Active', event)

#         # user = self.scope['user']
#         # print(user)

#         # URL থেকে গ্রুপ নাম নেয়া
#         self.room_name = self.scope['url_route']['kwargs']['room_name']
#         self.group_name = f"chat_{self.room_name}"  # ডাইনামিক গ্রুপ নাম
#         # print(self.group_name)

#         # গ্রুপে যোগ করা
#         async_to_sync(self.channel_layer.group_add)(
#             self.group_name,
#             self.channel_name
#         )

#         # সংযোগ গ্রহণ
#         self.send({
#             "type": "websocket.accept",
#         })

#     def websocket_receive(self, event):
#         text_data = event.get('text', '')
#         print(f"Message Received: {text_data}")

#         data = json.loads(event['text'])
        

#         room_id = data.get('room_id')
#         user_name = data.get('user')
#         content = data.get('message')

#         # print('json message', content)
#         # print('json user', user_name)
#         # print('json room_id', room_id)

#         try:
#             room = Room.objects.get(room_id=room_id)
#             user = User.objects.get(username=user_name)
#             # print('kl',user)
#         except Room.DoesNotExist:
#             print("Room does not exist")
#             return
#         except User.DoesNotExist:
#             print("User does not exist")
#             return

#         try:
#             # মেসেজ তৈরি করা এবং রুমের সাথে যুক্ত করা
#             message = Message.objects.create(room=room, sender=user, content=content)
#             print(room, user, content)
#         except ValidationError as e:
#             print(f"Validation error: {e}")
#             return
#         except PermissionDenied as e:
#             print(f"Permission denied: {e}")
#             return

#         # বার্তা গ্রুপে প্রেরণ করা
#         async_to_sync(self.channel_layer.group_send)(
#             self.group_name,
#             {
#                 "type": "chat_message",
#                 "message": text_data
#             }
#         )
    
#     # গ্রুপের মধ্যে বার্তা পাঠানোর জন্য মেথড
#     def chat_message(self, event):
#         message = event['message']

#         # বার্তা ক্লায়েন্টে পাঠানো
#         self.send({
#             'type': 'websocket.send',
#             'text': message
#         })

#     def websocket_disconnect(self, event):
#         print('User Disconnected', event)

#         # গ্রুপ থেকে সরিয়ে ফেলা
#         async_to_sync(self.channel_layer.group_discard)(
#             self.group_name,
#             self.channel_name
#         )

#         raise StopConsumer()





from channels.generic.websocket import SyncConsumer
from channels.exceptions import StopConsumer
from asgiref.sync import async_to_sync
import json
from django.utils import timezone
from .models import Room, Message
from django.contrib.auth import get_user_model

class PrivateChatConsumer(SyncConsumer):
    def websocket_connect(self, event):
        user = self.scope['user']
        if user.is_authenticated:
            user.is_active_now = True
            user.save()

        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.group_name = f"chat_{self.room_name}"

        # গ্রুপে যোগ করা
        async_to_sync(self.channel_layer.group_add)(
            self.group_name,
            self.channel_name
        )

        # সংযোগ গ্রহণ করা
        self.send({
            "type": "websocket.accept",
        })

        # ইউজারকে একটিভ হিসেবে পাঠানো
        async_to_sync(self.channel_layer.group_send)(
            self.group_name,
            {
                "type": "chat_message",
                "message_type": "status",
                "is_active_user": {
                    "username": user.username,
                    "id": user.id,
                    "last_active": user.last_active.strftime('%Y-%m-%d %H:%M:%S') if user.last_active else None
                },
                "status": "connected"
            }
        )

    def websocket_receive(self, event):
        text_data = event.get('text', '')
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            print("Invalid JSON format")
            return

        room_id = data.get('room_id')
        user_name = data.get('user')
        content = data.get('message')

        user_model = get_user_model()
        try:
            room = Room.objects.get(room_id=room_id)
            user = user_model.objects.get(username=user_name)
        except Room.DoesNotExist:
            print("Room does not exist")
            return
        except user_model.DoesNotExist:
            print("User does not exist")
            return

        # মেসেজ তৈরি করা
        message = Message.objects.create(room=room, sender=user, content=content)

        # বার্তা প্রেরণ করা
        async_to_sync(self.channel_layer.group_send)(
            self.group_name,
            {
                "type": "chat_message",
                "message_type": "message",  # এখানে 'message' টাইপ পাঠানো হচ্ছে
                "message": content,
                "user": user.username
            }
        )

    def chat_message(self, event):
        # গ্রুপ থেকে বার্তা গ্রহণ করা
        message_type = event.get('message_type')

        # ক্লায়েন্টে মেসেজ বা স্ট্যাটাস পাঠানো
        if message_type == 'message':
            self.send({
                'type': 'websocket.send',
                'text': json.dumps({
                    'message_type': 'message',
                    'message': event['message'],
                    'user': event['user']
                })
            })
        elif message_type == 'status':
            self.send({
                'type': 'websocket.send',
                'text': json.dumps({
                    'message_type': 'status',
                    'is_active_user': event['is_active_user'],
                    'status': event['status']
                })
            })

    def websocket_disconnect(self, event):
        user = self.scope['user']
        if user.is_authenticated:
            user.is_active_now = False
            user.last_active = timezone.now()
            user.save()

        # গ্রুপ থেকে সরিয়ে ফেলা
        async_to_sync(self.channel_layer.group_discard)(
            self.group_name,
            self.channel_name
        )

        # ইউজার ইন-অ্যাক্টিভ হিসেবে পাঠানো
        async_to_sync(self.channel_layer.group_send)(
            self.group_name,
            {
                "type": "chat_message",
                "message_type": "status",  # এখানে 'status' টাইপ পাঠানো হচ্ছে
                "is_active_user": {
                    "username": user.username,
                    "id": user.id,
                    "last_active": user.last_active.strftime('%Y-%m-%d %H:%M:%S')
                },
                "status": "disconnected"
            }
        )

        raise StopConsumer()
