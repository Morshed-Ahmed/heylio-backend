from channels.generic.websocket import SyncConsumer
from channels.exceptions import StopConsumer
from asgiref.sync import async_to_sync
import json
from django.utils import timezone
from .models import Room, Message
from django.contrib.auth import get_user_model
from datetime import datetime

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
        is_typing = data.get('is_typing', False)

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
        
        if content:

            # মেসেজ তৈরি করা
            message = Message.objects.create(room=room, sender=user, content=content)

            # বার্তা প্রেরণ করা
            async_to_sync(self.channel_layer.group_send)(
                self.group_name,
                {
                    "type": "chat_message",
                    "message_type": "message",  # এখানে 'message' টাইপ পাঠানো হচ্ছে
                    "message": content,
                    "user": user.username,
                    "timestamp": datetime.now().isoformat()
                }
            )
        elif is_typing is not None:  # is_typing None হলে এটা অবহেলা করা হবে
            print(is_typing)
            print({
                "username": user.username,
                "last_active": user.last_login
            })
            # টাইপিং ইন্ডিকেটর প্রেরণ করা
            async_to_sync(self.channel_layer.group_send)(
                self.group_name,
                {
                    "type": "typing_indicator",
                    "user": user.username,
                    "is_typing": is_typing,  # এখানে is_typing true বা false হবে
                    "is_active_user": {
                        "username": user.username,
                        "last_active": user.last_login.isoformat() if user.last_login else "Never active"
                    }
                }
            )
            

        
    def typing_indicator(self, event):
        # গ্রুপ থেকে টাইপিং স্ট্যাটাস গ্রহণ করা
        self.send({
            'type': 'websocket.send',
            'text': json.dumps({
                'message_type': 'typing',
                'is_typing': event['is_typing'],
                'user': event['user']
            })
        })


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
                    'user': event['user'],
                    'timestamp': event['timestamp']
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
