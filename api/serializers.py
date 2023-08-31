from rest_framework import serializers
from .models import *

class InstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Instance
        fields = '__all__'

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

class InventorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Inventory
        fields = '__all__'

class VMCreateSerializer(serializers.Serializer):
    metadata = serializers.JSONField()
    spec = serializers.JSONField()
    status = serializers.JSONField()

class VMUpdateSerializer(serializers.Serializer):
    action = serializers.CharField(required=True, max_length=255)
    vmName = serializers.CharField(required=True, max_length=255)