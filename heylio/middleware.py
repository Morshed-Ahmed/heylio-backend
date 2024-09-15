# middleware.py
from django.contrib.auth.models import AnonymousUser
from channels.db import database_sync_to_async
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from urllib.parse import parse_qs

User = get_user_model()

@database_sync_to_async
def get_user_from_token(token_key):
    try:
        token = Token.objects.get(key=token_key)
        return token.user
    except Token.DoesNotExist:
        return AnonymousUser()

class TokenAuthMiddleware:
    """
    Custom middleware that takes the token from the query string and authenticates the user.
    """
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        # Get token from query string
        query_string = scope['query_string'].decode()
        params = parse_qs(query_string)
        token_key = params.get('token', [None])[0]

        if token_key:
            # Fetch the user associated with the token
            scope['user'] = await get_user_from_token(token_key)
        else:
            scope['user'] = AnonymousUser()

        # Call the next middleware or the actual consumer
        return await self.inner(scope, receive, send)
