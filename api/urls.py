from django.urls import path,include
from .views import *

urlpatterns = [
    path('users/register/', UserRegistrationAPI.as_view(), name='user-register'),
    path('users/login/', UserLoginAPI.as_view(), name='user-login'),
    path('users/logout/', UserLogoutAPI.as_view(), name='user-logout'),
    
    path('clusters/', getAllCluster, name='cluster-list'),
    path('clusters/<str:cluster_id>/', GetClusterByName, name='cluster-detail'),

    path('VM/<str:cluster_id>/getvmstatus/<str:name_space>/<str:vm_name>',VMGet, name = 'vm-get-status'),
    path('VM/<str:cluster_id>/createvm',VMCreate, name = 'vm-create'),
    path('VM/<str:cluster_id>/updatevm',VMUpdate, name = 'vm-update'),
    path('VM/<str:cluster_id>/vmterminate/<str:name_space>/<str:vm_name>',VMTerminate, name = 'vm-terminate'),

    path('inventory/', InventoryAPI.as_view(), name='inventory-list-create'),
    path('inventory/<int:inventory_id>/download-ssh-cert/', DownloadSSHCertView.as_view(), name='download-ssh-cert'),
]