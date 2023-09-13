from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth import get_user_model

class Pricing(models.Model):
    pricing_id = models.AutoField(primary_key=True)
    cluster_id = models.CharField(max_length=255, blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    
    def __str__(self):
        return f"Pricing {self.pricing_id}"

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True, blank=False, null=False)
    reg_date = models.DateTimeField(auto_now_add=True)
    invoice_date = models.DateTimeField(auto_now_add=True)
    company = models.CharField(max_length=255, blank=True, null=True)
    is_provider = models.BooleanField(default=False)
    ein = models.CharField(max_length=15, blank=True, null=True, help_text="Employer Identification Number")
    address = models.TextField(blank=True, null=True)
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    card_number = models.CharField(max_length=16, blank=True, null=True)
    card_exp = models.DateField(blank=True, null=True)
    card_name = models.CharField(max_length=255, blank=True, null=True)
    tax = models.FloatField(blank=True, null=True)
    role = models.CharField(max_length=255, blank=True, null=True)
    token = models.CharField(max_length=255, blank=True, null=True)
    wallet_address = models.CharField(max_length=42, unique=True, null=True, blank=True)
    public_key = models.CharField(max_length=130, null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


class Invoice(models.Model):
    invoice_id = models.AutoField(primary_key=True)
    invoice_time = models.DateTimeField()
    invoice_data = models.TextField(help_text="JSON formatted invoice data")
    user_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    paid = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Invoice {self.invoice_id}"

class Instance(models.Model):
    instance_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='user_instances')
    provider_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='provider_instances', null=True, blank=True)
    cluster = models.CharField(max_length=100, unique=False, null=False)
    vm_name = models.CharField(max_length=100, unique=True, null=False)
    vm_namespace = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=100)
    start_time = models.DateTimeField(blank=True, null=True)
    stop_time = models.DateTimeField(blank=True, null=True)
    usage = models.FloatField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    
    def __str__(self):
        return f"Instance {self.vm_name} created by {self.user_id}"
    
