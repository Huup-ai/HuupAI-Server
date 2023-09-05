from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
import json

class Pricing(models.Model):
    pricing_id = models.AutoField(primary_key=True)
    gpus = models.CharField(max_length=50)
    vram_per_gpu = models.CharField(max_length=50)
    vcpus = models.CharField(max_length=50)
    ram = models.CharField(max_length=50)
    storage = models.CharField(max_length=50)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return f"Pricing {self.pricing_id}"

class User(AbstractUser):
    email = models.EmailField(unique=True, blank=False, null=False)
    reg_date = models.DateTimeField(auto_now_add=True)
    company = models.CharField(max_length=255, blank=True, null=True)
    ein = models.CharField(max_length=15, blank=True, null=True, help_text="Employer Identification Number")
    address = models.TextField(blank=True, null=True)
    payment_method = models.CharField(max_length=50, blank=True, null=True)
    card_number = models.CharField(max_length=16, blank=True, null=True)
    card_exp = models.DateField(blank=True, null=True)
    card_name = models.CharField(max_length=255, blank=True, null=True)
    tax = models.FloatField(blank=True, null=True)
    role = models.CharField(max_length=255, blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


class Invoice(models.Model):
    invoice_id = models.AutoField(primary_key=True)
    invoice_time = models.DateTimeField()
    invoice_data = models.TextField(help_text="JSON formatted invoice data")
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    paid = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Invoice {self.invoice_id}"

class Instance(models.Model):
    instance_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    pricing_id = models.ForeignKey(Pricing, on_delete=models.CASCADE)
    cluster = models.CharField(max_length=100, unique=True, null=False)
    vm_id = models.CharField(max_length=100, unique=True, null=False)
    vm_name = models.CharField(max_length=100, unique=True, null=False)
    vm_namespace = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=100)
    start_time = models.DateTimeField()
    stop_time = models.DateTimeField()
    usage = models.FloatField()
    
    def __str__(self):
        return f"Instance {self.instance_id}"
    
