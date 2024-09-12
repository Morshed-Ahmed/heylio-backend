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


# consumers.py
from channels.generic.websocket import SyncConsumer
from channels.exceptions import StopConsumer
from asgiref.sync import async_to_sync
import json

from .models import Room,Message
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError,PermissionDenied

class PrivateChatConsumer(SyncConsumer):
    def websocket_connect(self, event):
        print('User Active', event)

        # user = self.scope['user']
        # print(user)

        # URL থেকে গ্রুপ নাম নেয়া
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.group_name = f"chat_{self.room_name}"  # ডাইনামিক গ্রুপ নাম

        query_params = self.scope['query_string'].decode()
        self.token = dict(param.split('=') for param in query_params.split('&')).get('token')
        print(self.token)
        # print(self.group_name)

        # গ্রুপে যোগ করা
        async_to_sync(self.channel_layer.group_add)(
            self.group_name,
            self.channel_name
        )

        # সংযোগ গ্রহণ
        self.send({
            "type": "websocket.accept",
        })

    def websocket_receive(self, event):
        text_data = event.get('text', '')
        print(f"Message Received: {text_data}")

        data = json.loads(event['text'])
        

        room_id = data.get('room_id')
        user_name = data.get('user')
        content = data.get('message')

        # print('json message', content)
        # print('json user', user_name)
        # print('json room_id', room_id)

        try:
            room = Room.objects.get(room_id=room_id)
            user = User.objects.get(username=user_name)
            # print('kl',user)
        except Room.DoesNotExist:
            print("Room does not exist")
            return
        except User.DoesNotExist:
            print("User does not exist")
            return

        try:
            # মেসেজ তৈরি করা এবং রুমের সাথে যুক্ত করা
            message = Message.objects.create(room=room, sender=user, content=content)
            print(room, user, content)
        except ValidationError as e:
            print(f"Validation error: {e}")
            return
        except PermissionDenied as e:
            print(f"Permission denied: {e}")
            return

        # বার্তা গ্রুপে প্রেরণ করা
        async_to_sync(self.channel_layer.group_send)(
            self.group_name,
            {
                "type": "chat_message",
                "message": text_data
            }
        )
    
    # গ্রুপের মধ্যে বার্তা পাঠানোর জন্য মেথড
    def chat_message(self, event):
        message = event['message']

        # বার্তা ক্লায়েন্টে পাঠানো
        self.send({
            'type': 'websocket.send',
            'text': message
        })

    def websocket_disconnect(self, event):
        print('User Disconnected', event)

        # গ্রুপ থেকে সরিয়ে ফেলা
        async_to_sync(self.channel_layer.group_discard)(
            self.group_name,
            self.channel_name
        )

        raise StopConsumer()


