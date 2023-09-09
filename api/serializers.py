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
        fields = ['email','password','is_provider']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user
    

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        read_only_fields = ('email', 'reg_date', 'role', 'invoice_date' , 'is_provider')


class VMCreateSerializer(serializers.Serializer):
    metadata = serializers.JSONField()
    spec = serializers.JSONField()
    status = serializers.JSONField()

class VMUpdateSerializer(serializers.Serializer):
    action = serializers.CharField(required=True, max_length=255)
    vmName = serializers.CharField(required=True, max_length=255)