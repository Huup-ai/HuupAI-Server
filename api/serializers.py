from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password

User = get_user_model()
class InstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Instance
        fields = [
            'instance_id','cluster', 'vm_name',
            'status', 'usage', 'payment_method','dns','service'
        ]
        depth = 1

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email','password', 'first_name', 'last_name']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user
    
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        read_only_fields = ('email', 'reg_date', 'role', 'invoice_date' , 'is_provider')

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        # validate_password(value)
        return value

class PricingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pricing
        fields = '__all__'

class VMCreateSerializer(serializers.Serializer):
    metadata = serializers.JSONField()
    status = serializers.JSONField()

class VMUpdateSerializer(serializers.Serializer):
    action = serializers.CharField(required=True, max_length=255)
    vm_name = serializers.CharField(required=True, max_length=255)
    vm_namespace = serializers.CharField(required=True, max_length=255)

class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = '__all__'
        depth = 1

class WalletSerializer(serializers.ModelSerializer):

    user = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Wallet
        fields = '__all__'

class ClusterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cluster
        fields = ['item_id', 'region', 'cpu', 'memory', 'pods', 'price', 'provider','virtualization',
        'gpu','configuration','is_audited','service']
