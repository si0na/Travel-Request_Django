from rest_framework import serializers
from .models import Employee, Manager, Admin, TravelRequest
from django.contrib.auth.hashers import make_password

class EmployeeSerializer(serializers.ModelSerializer):
    manager_name = serializers.CharField(source="manager.manager_name", read_only=True)

    class Meta:
        model = Employee
        fields = ["employee_id", "employee_name", "employee_email", "manager_name", "status"]


    def validate_password(self, value):
        return make_password(value)

class ManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manager
        fields = '__all__'

class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = '__all__'

class TravelRequestSerializer(serializers.ModelSerializer):
    employee_name = serializers.CharField(source='employee.employee_name', read_only=True)
    manager_name = serializers.CharField(source='manager.manager_name', read_only=True)
    class Meta:
        model = TravelRequest
        fields = '__all__'
        extra_kwargs = {"employee": {"read_only": True},
                        "manager": {"read_only": True},}

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=6)