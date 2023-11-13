from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

def get_user_email(backend, details, response, *args, **kwargs):
    User = get_user_model()
    email = details.get('email')
    if email:
        user, created = User.objects.get_or_create(email=email)
        return {'user': user, 'is_new': created}
    return {}

def create_jwt_token(user, *args, **kwargs):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }