# consumers.py
from channels.generic.websocket import SyncConsumer
from channels.exceptions import StopConsumer
from asgiref.sync import async_to_sync
import json

class PrivateChatConsumer(SyncConsumer):
    def websocket_connect(self, event):
        print('User Active', event)

        # URL থেকে গ্রুপ নাম নেয়া
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.group_name = f"chat_{self.room_name}"  # ডাইনামিক গ্রুপ নাম
        print(self.group_name)

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
