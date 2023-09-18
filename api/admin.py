from django.contrib import admin
from .models import *

admin.site.register(User)
admin.site.register(Instance)
admin.site.register(Invoice)
admin.site.register(Pricing)
admin.site.register(Wallet)