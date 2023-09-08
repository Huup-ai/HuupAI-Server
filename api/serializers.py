from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
from .src.helper import get_external_api_token

User = get_user_model()
class InstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Instance
        fields = '__all__'

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    is_provider = serializers.BooleanField(required=True)
    
    class Meta:
        model = User
        fields = ['email','reg_date','company','password','is_provider','ein','address','payment_method'
                  ,'card_number','card_exp','card_name','tax','role']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        if user.is_provider:
        # Step 1: Get the token from the external API
            token = get_external_api_token(user)
            if token:
                user.token = token
                user.save()
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'company', 'ein', 
            'address', 'payment_method', 
            'card_number', 'card_exp', 
            'card_name', 'tax', 'role'
        ]


class VMCreateSerializer(serializers.Serializer):
    metadata = serializers.JSONField()
    spec = serializers.JSONField()
    status = serializers.JSONField()

class VMUpdateSerializer(serializers.Serializer):
    action = serializers.CharField(required=True, max_length=255)
    vmName = serializers.CharField(required=True, max_length=255)