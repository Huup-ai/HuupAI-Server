from django.contrib import admin
from .models import User, Instance, Invoice, Pricing

admin.site.register(User)
admin.site.register(Instance)
admin.site.register(Invoice)
admin.site.register(Pricing)