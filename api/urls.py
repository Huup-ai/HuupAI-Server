from django.urls import path,include
from .views import *

urlpatterns = [
    path('users/register/', UserRegistrationAPI.as_view(), name='user-register'),
    path('users/login/', UserLoginAPI.as_view(), name='user-login'),
    path('users/logout/', UserLogoutAPI.as_view(), name='user-logout'),
    path('clusters/', GetAllCluster.as_view(), name='cluster-list'),
    path('clusters/<str:name>/', GetClusterByName.as_view(), name='cluster-detail'),
    path('clusters/status/<str:name>/',GetClusterStat.as_view(), name='cluster-status'),
    path('instances/', InstanceAPI.as_view(), name='instance-list'),
    path('instances/<str:cluster_name>/<str:vm_name>/', InstanceControlAPI.as_view(), name='vm-detail'),
    path('inventory/', InventoryAPI.as_view(), name='inventory-list-create'),
    path('inventory/<int:inventory_id>/download-ssh-cert/', DownloadSSHCertView.as_view(), name='download-ssh-cert'),
]