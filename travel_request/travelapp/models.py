from django.db import models

class Admin(models.Model):
    admin_id = models.AutoField(primary_key=True)
    admin_name = models.CharField(max_length=100)
    admin_email = models.EmailField(unique=True)
    admin_password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Manager(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    
    manager_id = models.AutoField(primary_key=True)
    admin = models.ForeignKey(Admin, on_delete=models.CASCADE)
    manager_name = models.CharField(max_length=100)
    manager_email = models.EmailField(unique=True)
    manager_password = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Employee(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    
    employee_id = models.AutoField(primary_key=True)
    employee_email=models.EmailField(unique=True)
    manager = models.ForeignKey(Manager, on_delete=models.SET_NULL, null=True, blank=True)
    employee_name = models.CharField(max_length=100)
    password=models.CharField(max_length=255,default="")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class TravelRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('denied', 'Denied'),
        ('additional_info_requested', 'Additional Info Requested'),
    ]
    MODE_CHOICES = [
        ('flight', 'Flight'),
        ('car', 'Car'),
        ('train', 'Train'),
        ('bus', 'Bus'),
    ]
    LODGING_CHOICES = [
        ('yes', 'Yes'),
        ('no', 'No'),
    ]
    
    id = models.AutoField(primary_key=True)
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)
    manager = models.ForeignKey(Manager, on_delete=models.CASCADE)
    status = models.CharField(max_length=25, choices=STATUS_CHOICES, default='pending')
    origin = models.CharField(max_length=255)
    destination = models.CharField(max_length=255)
    departure_date = models.DateField()
    return_date = models.DateField(null=True, blank=True)
    mode_of_travel = models.CharField(max_length=10, choices=MODE_CHOICES)
    travel_purpose = models.TextField()
    additional_notes = models.TextField(null=True, blank=True)
    needs_lodging = models.CharField(max_length=3, choices=LODGING_CHOICES, default='no')
    lodging_info = models.CharField(max_length=255, null=True, blank=True)
    resubmission_count = models.IntegerField(default=0)
    manager_note = models.TextField(null=True, blank=True)
    is_closed = models.BooleanField(default=False)
    admin_note = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
