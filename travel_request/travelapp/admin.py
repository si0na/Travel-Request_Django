from django.contrib import admin
from .models import Employee,Admin,Manager,TravelRequest

admin.site.register(Employee)
admin.site.register(Admin)
admin.site.register(Manager)
admin.site.register(TravelRequest)
