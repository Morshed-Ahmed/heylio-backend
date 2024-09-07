from django.db import models
from django.conf import settings
import uuid
import random

from django.core.exceptions import PermissionDenied

class Room(models.Model):
    id = models.AutoField(primary_key=True)
    room_id = models.CharField(max_length=15, unique=True, editable=False)
    participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='rooms')
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.room_id:
            # ১৫ ডিজিটের ইউনিক room_id তৈরি করা
            self.room_id = ''.join([str(random.randint(0, 9)) for _ in range(15)])
        super(Room, self).save(*args, **kwargs)

    def __str__(self):
        participants_names = ', '.join(user.username for user in self.participants.all())
        return f"Room {self.room_id} - Participants: {participants_names}"

class Message(models.Model):
    room = models.ForeignKey(Room, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='sent_messages', on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # চেক করুন যে প্রেরক ব্যবহারকারী কি রুমের অংশ
        if not self.room.participants.filter(id=self.sender.id).exists():
            raise PermissionDenied("You are not allowed to send messages in this room.")
        super(Message, self).save(*args, **kwargs)

    def __str__(self):
        return f"Message from {self.sender.username} in Room {self.room.room_id} at {self.timestamp}"

    class Meta:
        ordering = ['timestamp']