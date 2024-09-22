from rest_framework import serializers
from .models import Room, Message
from django.contrib.auth.models import User
from Authentication.models import CustomUser


class MessageSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='sender.username')
    date_time = serializers.DateTimeField(source='timestamp')

    class Meta:
        model = Message
        fields = ['user_name', 'content', 'date_time']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username']  



class RoomSerializer(serializers.ModelSerializer):
    participants = UserSerializer(many=True, read_only=True)
    content = MessageSerializer(many=True, source='messages', read_only=True)  # Assuming 'messages' is the related name for messages in Room model

    class Meta:
        model = Room
        fields = ['id', 'room_id', 'participants', 'content', 'created_at']

    def create(self, validated_data):
        # অংশগ্রহণকারীদের ম্যানুয়ালি যোগ করা হচ্ছে কারণ আমরা read_only=True সেট করেছি
        participants = self.context['request'].data.get('participants', [])
        if len(participants) != 2:
            raise serializers.ValidationError("Exactly two participants are required.")

        user1 = CustomUser.objects.get(username=participants[0]['username'])
        user2 = CustomUser.objects.get(username=participants[1]['username'])

        # একই অংশগ্রহণকারীদের নিয়ে রুম চেক করা
        existing_room = Room.objects.filter(participants=user1).filter(participants=user2).first()
        
        if existing_room:
            return existing_room  # যদি রুম থাকে, সেটাই রিটার্ন করবে

        # নতুন রুম তৈরি করা
        room = Room.objects.create(**validated_data)
        room.participants.add(user1, user2)  # উভয় অংশগ্রহণকারীকে রুমে যোগ করা
        return room



