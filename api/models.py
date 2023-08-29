from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
import json

class Cluster(models.Model):
    name = models.CharField(max_length=100,unique=True)
    hour_rate = models.DecimalField(max_digits=10, decimal_places=2,null=True)
    gpu = models.CharField(default='0',max_length=100)
    configuration = models.CharField(null=True,max_length=100) #change the default value here
    region = models.CharField(max_length=100,null=True)
    privacy = models.CharField(max_length=100,null=True)

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
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    paid = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Invoice {self.invoice_id}"

class Instance(models.Model):
    instance_id = models.AutoField(primary_key=True)
    pricing = models.ForeignKey(Pricing, on_delete=models.CASCADE)
    status = models.CharField(max_length=100)
    start_time = models.DateTimeField()
    stop_time = models.DateTimeField()
    usage = models.FloatField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    def __str__(self):
        return f"Instance {self.instance_id}"
    

class Inventory(models.Model):
    hostname = models.CharField(max_length=100)
    IP = models.CharField(max_length=15)
    ssh_cert = models.TextField()
    status = models.CharField(max_length=50)
    cluster_name = models.ForeignKey(Cluster, on_delete=models.CASCADE)
    inventory_name = models.CharField(max_length=100)