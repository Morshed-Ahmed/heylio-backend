from rest_framework import status,generics
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Room, Message
from rest_framework.permissions import IsAuthenticated
from .serializers import RoomSerializer

class RoomMessagesView(APIView):
    permission_classes = [IsAuthenticated]  # নিশ্চিত করুন যে ব্যবহারকারী লগইন করেছে

    def get(self, request, room_id, format=None):
        try:
            # রুম খুঁজে বের করুন
            room = Room.objects.get(room_id=room_id)
            
            # চেক করুন যে বর্তমান ইউজার রুমের অংশ কিনা
            if request.user not in room.participants.all():
                return Response({'error': 'You are not allowed to view messages in this room.'}, status=status.HTTP_403_FORBIDDEN)

            # যদি ইউজার রুমের অংশ হয়, তবে মেসেজ রিটার্ন করুন
            messages = Message.objects.filter(room=room).values('sender__username', 'content', 'timestamp')
            messages_list = list(messages)  # QuerySet কে লিস্টে রূপান্তরিত করা

            return Response(messages_list, status=status.HTTP_200_OK)
        
        except Room.DoesNotExist:
            return Response({'error': 'Room does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Message.DoesNotExist:
            return Response({'error': 'No messages found for this room'}, status=status.HTTP_404_NOT_FOUND)

class RoomListCreateView(generics.ListCreateAPIView):
    serializer_class = RoomSerializer
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get_queryset(self):
        # Get the authenticated user
        user = self.request.user
        # Return only the rooms the user is a participant of
        return Room.objects.filter(participants=user)
    
    def perform_create(self, serializer):
        room = serializer.save()
        room.clean()  # Ensure that only two participants are added