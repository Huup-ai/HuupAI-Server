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
    is_audit = models.BooleanField(default=False)
    address = models.TextField(blank=True, null=True)
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    credit_card = models.CharField(max_length=4, blank=True, null=True)
    tax = models.FloatField(blank=True, null=True)
    role = models.CharField(max_length=255, blank=True, null=True)
    token = models.CharField(max_length=255, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

class StripeCustomer(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)
    stripe_customer_id = models.CharField(max_length=255)
    stripe_payment = models.CharField(max_length=255, null=True, blank=True)
    stripe_account = models.CharField(max_length=255, null=True, blank=True)

class Cluster(models.Model):
    item_id = models.CharField(max_length=255, unique=True, default='null')
    region = models.CharField(max_length=255, null=True, blank=True)
    cpu = models.CharField(max_length=255, null=True, blank=True)
    memory = models.CharField(max_length=255, null=True, blank=True)
    pods = models.CharField(max_length=255, null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    provider = models.ForeignKey(User, on_delete=models.CASCADE,null=True)
    virtualization = models.BooleanField(default=False)
    is_audited = models.BooleanField(default=False)
    gpu = models.CharField(max_length=255, null=True, blank=True)  # GPU field
    configurations = models.TextField(null=True, blank=True)  # Configurations field

    def __str__(self):
        return f"Cluster {self.item_id} - {self.region}"

class Instance(models.Model):
    instance_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='user_instances')
    provider_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='provider_instances', null=True, blank=True)
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    cluster = models.ForeignKey(Cluster, on_delete=models.CASCADE)
    vm_name = models.CharField(max_length=100, unique=True, null=False)
    vm_namespace = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=100)
    start_time = models.DateTimeField(blank=True, null=True)
    stop_time = models.DateTimeField(blank=True, null=True)
    usage = models.FloatField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    dns = models.CharField(max_length=255, default='huupai@vm-unknown.com')
    def __str__(self):
        return f"Instance {self.vm_name} created by {self.user_id}"

class Invoice(models.Model):
    invoice_id = models.AutoField(primary_key=True)
    instance = models.ForeignKey(Instance, on_delete=models.CASCADE, related_name='invoices', null=True)
    cluster = models.ForeignKey(Cluster, on_delete=models.CASCADE, null=True)
    invoice_time = models.DateTimeField()
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Price of the instance per hour or unit",null = True)
    usage = models.DecimalField(max_digits=10, decimal_places=2, help_text="Number of hours or units used", null = True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Total price including tax", null=True)
    user_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, null=True)
    paid = models.BooleanField(default=False)
    provider_paid = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Invoice {self.invoice_id}"

class Wallet(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    address = models.CharField(max_length=255)
    is_provider = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user}'s wallet"

class APIKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)