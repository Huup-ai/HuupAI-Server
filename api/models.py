from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission

class Cluster(models.Model):
    name = models.CharField(max_length=100,unique=True)
    hour_rate = models.DecimalField(max_digits=10, decimal_places=2,null=True)
    gpu = models.CharField(default='0',max_length=100)
    configuration = models.CharField(null=True,max_length=100) #change the default value here
    region = models.CharField(max_length=100,null=True)
    privacy = models.CharField(max_length=100,null=True)

class Instance(models.Model):
    cluster = models.ForeignKey(Cluster, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    num_of_cpu = models.IntegerField()
    num_of_gpu = models.IntegerField()
    size_of_mem = models.IntegerField()
    size_of_disk = models.IntegerField()
    is_running = models.BooleanField(default=True)

class User(AbstractUser):
    inventory = models.ForeignKey('Inventory', on_delete=models.SET_NULL, null=True, blank=True)
    billing_id = models.IntegerField(null=True, blank=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True)
    company = models.CharField(max_length=100, blank=True)
    EIN = models.CharField(max_length=20, blank=True)
    address = models.CharField(max_length=200, blank=True)

class Inventory(models.Model):
    hostname = models.CharField(max_length=100)
    IP = models.CharField(max_length=15)
    ssh_cert = models.TextField()
    status = models.CharField(max_length=50)
    cluster_name = models.ForeignKey(Cluster, on_delete=models.CASCADE)
    inventory_name = models.CharField(max_length=100)