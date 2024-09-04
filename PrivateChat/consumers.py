# consumers.py
from channels.generic.websocket import SyncConsumer
import json
from channels.exceptions import StopConsumer

class PrivateChatConsumer(SyncConsumer):
    def websocket_connect(self, event):
        print('User Active', event)

        self.send({
            "type": "websocket.accept",
        })
    
    def websocket_receive(self, event):
        text_data = event.get('text', '')
        print(text_data)
        
        # # Process the message and send a response
        self.send({
            'type': 'websocket.send',
            'text': text_data
        })
    
    def websocket_disconnect(self, event):
        print('User Disconnected', event)
        raise StopConsumer()
