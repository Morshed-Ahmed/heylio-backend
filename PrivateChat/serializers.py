from rest_framework import serializers
from .models import Room, Message
from django.contrib.auth.models import User


class MessageSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='sender.username')
    date_time = serializers.DateTimeField(source='timestamp')

    class Meta:
        model = Message
        fields = ['user_name', 'content', 'date_time']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username']  

class RoomSerializer(serializers.ModelSerializer):
    # content = MessageSerializer(many=True, source='messages')
    participants = UserSerializer(many=True)  

    # class Meta:
    #     model = Room
    #     fields = ['room_id', 'content']

    class Meta:
        model = Room
        fields = ['id', 'room_id', 'participants', 'created_at']