from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.db.models import Case, When, IntegerField
from .models import TravelRequest, Admin, Manager, Employee
from .serializers import TravelRequestSerializer, EmployeeSerializer, ManagerSerializer, AdminSerializer,LoginSerializer 
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
import logging
from django.core.exceptions import ObjectDoesNotExist
# Configure logging
logger = logging.getLogger(__name__)

def authenticate_user(email: str, password: str) -> dict | None:
    """
    Authenticates the user based on their role (Admin, Manager, Employee).

    Returns a dictionary with user data if authentication is successful, otherwise None.
    """
    email = email.strip().lower()

    try:
        # Check Admin
        admin = Admin.objects.filter(admin_email=email).first()
        if admin and password == admin.admin_password:  #unhashed
            return {
                "id": admin.admin_id,
                "name": admin.admin_name,
                "email": admin.admin_email,
                "role": "admin"
            }

        # Check Manager
        manager = Manager.objects.filter(manager_email=email).first()
        if manager and check_password(password, manager.manager_password):
            return {
                "id": manager.manager_id,
                "name": manager.manager_name,
                "email": manager.manager_email,
                "role": "manager",
                "status": manager.status
            }

        # Check Employee
        employee = Employee.objects.filter(employee_email=email).first()
        if employee and check_password(password, employee.password):
            return {
                "id": employee.employee_id,
                "name": employee.employee_name,
                "email": employee.employee_email,
                "role": "employee",
                "status": employee.status
            }

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")  # Log the error
        return None

    return None


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """
    Handles user login for Admin, Manager, and Employee roles.

    Returns an authentication token and user details upon successful login.
    """
    serializer = LoginSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response({"message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user_data = authenticate_user(email, password)

    if user_data:
        django_user, _ = User.objects.get_or_create(username=email)
        token, _ = Token.objects.get_or_create(user=django_user)
        return Response({"token": token.key, "user": user_data}, status=status.HTTP_200_OK)

    logger.warning(f"Failed login attempt for email: {email}")
    return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_add_manager(request):
    """
    API endpoint for admins to add a new manager.

    Request Body:
    {
        "manager_name": "John Doe",
        "manager_email": "john@example.com",
        "manager_password": "securepassword"
    }
    """
    try:
        data = request.data.copy()
        if "manager_password" not in data or not data["manager_password"]:
            return Response({"error": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)

        data["manager_password"] = make_password(data["manager_password"])
        serializer = ManagerSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Manager added successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error adding manager: {str(e)}")
        return Response({"error": "An error occurred while adding the manager"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["POST", "DELETE"])
@permission_classes([IsAuthenticated])
def admin_add_employee(request, employee_id=None):
    """
    Handles adding and deleting employees.
    - POST: Add an employee with a hashed password.
    - DELETE: Remove an employee.
    """

    if request.method == "POST":
        # Extract employee data
        employee_name = request.data.get("employee_name", "").strip()
        employee_email = request.data.get("employee_email", "").strip()
        manager_name = request.data.get("manager", "").strip()
        password = request.data.get("password", "")

        # Check if manager exists (case-insensitive)
        try:
            manager = Manager.objects.get(manager_name__iexact=manager_name)
        except Manager.DoesNotExist:
            return Response({"error": f"Manager '{manager_name}' not found"}, status=400)

        # Hash the password before saving
        hashed_password = make_password(password)

        # Create employee
        employee = Employee.objects.create(
            employee_name=employee_name,
            employee_email=employee_email,
            manager=manager,
            password=hashed_password,
            status="active",
        )

        serializer = EmployeeSerializer(employee)
        return Response(serializer.data, status=201)

    elif request.method == "DELETE":
        if employee_id is None:
            return Response({"error": "Employee ID is required in the URL"}, status=400)

        # Find and delete employee
        employee = get_object_or_404(Employee, employee_id=employee_id)
        employee.delete()

        return Response({"message": "Employee removed successfully"}, status=200)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def employee_past_requests(request):
    """Retrieve past travel requests for the authenticated employee"""
    try:
        employee = get_object_or_404(Employee, employee_email=request.user.username)
        past_requests = TravelRequest.objects.filter(employee=employee).order_by("-created_at")        
        serializer = TravelRequestSerializer(past_requests, many=True)
        return Response(serializer.data if past_requests else {"message": "No past travel requests found."}, status=status.HTTP_200_OK)

    except ObjectDoesNotExist:
        return Response({"error": "Employee not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": f"Internal Server Error: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_travel_requests(request):
    """Retrieve travel requests based on Admin/Manager roles"""
    try:
        user_email = request.user.username
        is_admin = Admin.objects.filter(admin_email=user_email).exists()
        is_manager = Manager.objects.filter(manager_email=user_email).exists()

        if not (is_admin or is_manager):
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch travel requests
        travel_requests = TravelRequest.objects.filter(manager=Manager.objects.get(manager_email=user_email)) if is_manager else TravelRequest.objects.all()

        # Apply filters
        filters = {
            "employee__employee_name__icontains": request.query_params.get("employee_name"),
            "departure_date__gte": request.query_params.get("start_date"),
            "departure_date__lte": request.query_params.get("end_date"),
            "status": request.query_params.get("status"),  # ✅ Added status filter
        }
        filters = {k: v for k, v in filters.items() if v}
        travel_requests = travel_requests.filter(**filters)

        # Sorting by status order: approved > pending > denied > additional_info_requested
        status_priority = {"approved": 1, "pending": 2, "denied": 3, "additional_info_requested": 4}
        travel_requests = sorted(travel_requests, key=lambda x: (status_priority.get(x.status, 5), -x.created_at.timestamp()))

        serializer = TravelRequestSerializer(travel_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except ObjectDoesNotExist:
        return Response({"error": "Requested data not found."}, status=status.HTTP_404_NOT_FOUND)
    except ValueError:
        return Response({"error": "Invalid input provided."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": f"Internal Server Error: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_view_employees(request):
    """Retrieve a list of all employees (Admin access only)."""
    try:
        # Ensure only Admins can access this endpoint
        if not Admin.objects.filter(admin_email=request.user.username).exists():
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch and serialize employee data
        employees = Employee.objects.all()
        serializer = EmployeeSerializer(employees, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error fetching employees: {str(e)}")
        return Response({"error": "An error occurred while retrieving employees."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def update_travel_request_status(request, travel_request_id):
    """Update the status of a travel request (Admin/Manager access only)."""
    try:
        # Get the travel request
        travel_request = get_object_or_404(TravelRequest, id=travel_request_id)

        # Get the logged-in user and check if they are an Admin or Manager
        user_email = request.user.username
        admin = Admin.objects.filter(admin_email=user_email).first()
        manager = Manager.objects.filter(manager_email=user_email).first()

        # Ensure the user is either an Admin or Manager
        if not admin and not manager:
            return Response({"error": "Unauthorized access."}, status=status.HTTP_403_FORBIDDEN)

        # Get the new status from the request data
        new_status = request.data.get("status")
        valid_statuses = ["approved", "denied", "additional_info_requested"]

        if new_status not in valid_statuses:
            return Response({"error": "Invalid status update."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the status is already set to the same value
        if travel_request.status == new_status:
            return Response({"message": "No changes made. The status is already up-to-date."}, status=status.HTTP_200_OK)

        # If additional_info_requested, require appropriate note
        if new_status == "additional_info_requested":
            if manager:
                manager_note = request.data.get("manager_note", "").strip()
                if not manager_note:
                    return Response({"error": "Manager note is required."}, status=status.HTTP_400_BAD_REQUEST)
                travel_request.manager_note = manager_note
            elif admin:
                admin_note = request.data.get("admin_note", "").strip()
                if not admin_note:
                    return Response({"error": "Admin note is required."}, status=status.HTTP_400_BAD_REQUEST)
                travel_request.admin_note = admin_note

        # Update the travel request status
        travel_request.status = new_status
        travel_request.save()

        logger.info(f"Travel request {travel_request_id} updated to '{new_status}' by {user_email}")

        return Response({"message": "Travel request status updated successfully."}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error updating travel request {travel_request_id}: {str(e)}")
        return Response({"error": "Invalid request", "details": request.data}, status=status.HTTP_400_BAD_REQUEST)

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def close_travel_request(request, travel_request_id):
    """Allows an Admin to close an approved travel request."""
    try:
        # Ensure the requester is an Admin, not a Manager
        admin = get_object_or_404(Admin, admin_email=request.user.username)

        # Retrieve the travel request
        travel_request = get_object_or_404(TravelRequest, id=travel_request_id)

        # Ensure this travel request belongs to a manager under the admin
        manager_admin = getattr(travel_request.manager, "admin", None)  # Avoid attribute errors

        if manager_admin != admin:
            return Response({"error": "You are not authorized to close this travel request."},
                            status=status.HTTP_403_FORBIDDEN)

        # Ensure the request is in a valid state to be closed
        valid_closable_statuses = ["approved"]  # Modify this list if needed
        if travel_request.status not in valid_closable_statuses:
            return Response({"error": "Only approved travel requests can be closed."},
                            status=status.HTTP_400_BAD_REQUEST)

        if travel_request.is_closed:
            return Response({"error": "This travel request is already closed."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Close the request
        travel_request.is_closed = True
        travel_request.save()

        logger.info(f"Admin {admin.admin_email} closed travel request {travel_request_id}")

        return Response({"message": f"Travel request {travel_request_id} has been closed by the Admin."},
                        status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error closing travel request {travel_request_id}: {str(e)}")
        return Response({"error": "An error occurred while closing the travel request."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST', 'PUT'])
@permission_classes([IsAuthenticated])
def create_resubmit_notify(request, request_id=None):
    """
    Handles creation and updating of travel requests.

    - POST: Creates a new request.
    - PUT: Updates an existing request.
    """
    employee = get_object_or_404(Employee.objects.select_related('manager__admin'), employee_email=request.user.username)

    if not employee.manager:
        return Response({"message": "Employee does not have an assigned manager."}, status=status.HTTP_400_BAD_REQUEST)

    admin = employee.manager.admin
    admin_email = admin.admin_email

    # Ensure "manager_name" is provided in the request
    manager_name = request.data.get("manager_name")
    if not manager_name:
        return Response({"message": "Manager name is required."}, status=status.HTTP_400_BAD_REQUEST)

    # Retrieve the Manager object using the name
    try:
        manager = Manager.objects.get(manager_name=manager_name)
    except Manager.DoesNotExist:
        return Response({"message": "Manager not found."}, status=status.HTTP_404_NOT_FOUND)

    manager_email = manager.manager_email

    if request.method == 'POST':
        serializer = TravelRequestSerializer(data=request.data)
        if serializer.is_valid():
            travel_request = serializer.save(employee=employee, manager=manager, status="pending")
            action = "created"
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        if not request_id:
            return Response({"message": "Request ID is required for updating."}, status=status.HTTP_400_BAD_REQUEST)

        travel_request = get_object_or_404(TravelRequest, id=request_id)
        serializer = TravelRequestSerializer(travel_request, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save(manager=manager)  # Ensure manager is updated
            action = "updated"
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Send email notification
    subject = f"Travel Request {action}: ID {travel_request.id}"
    message = f"A travel request has been {action}. Details: {serializer.data}"

    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [admin_email, manager_email], fail_silently=False)
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return Response({"message": f"Travel request {action}, but email failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"message": f"Travel request {action} successfully."}, status=status.HTTP_200_OK)
