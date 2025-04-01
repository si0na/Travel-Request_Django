from django.urls import path
from .views import (
    login_view, employee_past_requests, admin_add_employee, admin_add_manager,
    admin_view_employees,update_travel_request_status,close_travel_request,create_resubmit_notify,update_travel_request_status,get_travel_requests
)

urlpatterns = [
    # Authentication
    path('login/', login_view, name='login'),

    # Admin URLs
    path('admin/add-manager/', admin_add_manager, name='admin-add-manager'),
    path('admin/add-employee/', admin_add_employee, name='admin-add-employee'),
    path('admin/view-employees/', admin_view_employees, name='admin-view-employees'),
    path('admin/remove/<int:employee_id>/', admin_add_employee, name='admin-remove-employee'),

    path('admin/view-requests/', get_travel_requests),
    path('admin/view-requests/update/<int:travel_request_id>/',update_travel_request_status),
    path("admin/view-requests/<int:travel_request_id>/close/",close_travel_request, name="close-travel-request"),
    # Employee URLs
    path('employee/create/', create_resubmit_notify, name="create_resubmit"),
    path('employee/past-requests/resubmit/<int:request_id>/', create_resubmit_notify, name="update_resubmit"), 
    path('employee/past-requests/', employee_past_requests, name='employee-past-requests'),
   

    # Manager URLs
    path('manager/view-requests/',get_travel_requests,name="get-travel-requests"),
    path('manager/view-requests/<int:travel_request_id>/',update_travel_request_status)
    
    
]
