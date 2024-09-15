from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.serializers import AuthTokenSerializer

from .models import CustomUser

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # পাসওয়ার্ড শুধু লেখার জন্য

    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'full_name', 'phone_number']  # প্রয়োজনীয় ফিল্ডস

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            full_name=validated_data.get('full_name', ''),  # যদি না দেয় তাহলে ডিফল্ট ফাঁকা
            phone_number=validated_data.get('phone_number', '')  # যদি না দেয় তাহলে ডিফল্ট ফাঁকা
        )
        return user


@api_view(['POST'])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# লগইন ভিউ
# class LoginView(ObtainAuthToken):
#     def post(self, request, *args, **kwargs):
#         serializer = AuthTokenSerializer(data=request.data)
#         if serializer.is_valid():
#             user = authenticate(username=serializer.validated_data['username'], password=serializer.validated_data['password'])
#             if user is not None:
#                 login(request, user)
#                 token, _ = Token.objects.get_or_create(user=user)
#                 return Response({'token': token.key})
#         return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = AuthTokenSerializer(data=request.data)
        if serializer.is_valid():
            # ইউজারনেম বা ফোন নাম্বার দিয়ে ইউজার অটেনটিকেট করা
            user = authenticate(username=serializer.validated_data['username'], password=serializer.validated_data['password'])
            if user is not None:
                login(request, user)
                token, _ = Token.objects.get_or_create(user=user)
                return Response({'token': token.key}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

# লগআউট ভিউ
@api_view(['POST'])
def logout_view(request):
    request.auth.delete()  # টোকেন মুছে ফেলুন
    logout(request)
    return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)




from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name','full_name','phone_number']

# প্রোফাইল ভিউ
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    serializer = ProfileSerializer(user)
    return Response(serializer.data)


from rest_framework import generics

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username' ,'is_active_now', 'last_active']

class CustomUserDetailView(generics.RetrieveAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer



class SearchUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'username', 'phone_number', 'is_active_now', 'last_active']

@api_view(['GET'])
def search_user(request):
    phone_number = request.query_params.get('phone_number', None)
    username = request.query_params.get('username', None)

    if phone_number and username:
        users = CustomUser.objects.filter(phone_number=phone_number, username=username)
    elif phone_number:
        users = CustomUser.objects.filter(phone_number=phone_number)
    elif username:
        users = CustomUser.objects.filter(username=username)
    else:
        users = CustomUser.objects.none()

    serializer = SearchUserSerializer(users, many=True)
    return Response(serializer.data)