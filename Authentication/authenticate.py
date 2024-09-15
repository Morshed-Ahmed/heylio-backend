from django.contrib.auth.backends import ModelBackend
from django.db.models import Q  # Q ইমপোর্ট করতে হবে
from django.contrib.auth import get_user_model

class UsernameOrPhoneBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # ইউজারনেম বা ফোন নাম্বার দ্বারা ইউজার খুঁজুন
            user = UserModel.objects.get(
                Q(username=username) | Q(phone_number=username)  # Q দিয়ে OR কন্ডিশন
            )
        except UserModel.DoesNotExist:
            return None

        if user.check_password(password):
            return user
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
