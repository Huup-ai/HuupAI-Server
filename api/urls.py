from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import *

urlpatterns = [
    path('users/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('users/login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('users/register/', UserRegistrationAPI.as_view(), name='user-register'),
    path('provider/login/', ProviderLoginOrRegisterView.as_view(), name='provider-login'),
    path('users/info/', UserUpdateRetrieveView.as_view(), name='user-info'),
    
    path('clusters/', getAllCluster, name='cluster-list'),
    path('clusters/cluster_name/<str:cluster_id>/', getClusterByName, name='cluster-detail'),
    path('clusters/my_clusters/', getClusterByUser, name='my-cluster'),
    path('clusters/set_price/', setPrice, name='set-price'),

    path('instances/<str:cluster_id>/getvmstatus/<str:name_space>/<str:vm_name>/',VMGet, name = 'vm-get-status'),
    path('instances/<str:email>/get_instances/', getInstances, name='get-instances'),
    path('instances/<str:cluster_id>/createvm/',VMCreate, name = 'vm-create'),
    path('instances/<str:cluster_id>/updatevm/',VMUpdate, name = 'vm-update'),
    path('instances/<str:cluster_id>/vmterminate/<str:name_space>/<str:vm_name>/',VMTerminate, name = 'vm-terminate'),

    path('Inventory/getsshkey/<str:cluster_id>/', getSshKey, name='get-ssh-key'),
    path('invoices/get_user_invoices/', get_invoices, name='get-invoices'),
    path('invoices/pay/<int:invoice_id>/', pay_invoice, name='pay-invoice'),
    
    path('wallets/get_wallets/', get_wallets, name='get-wallets'),
    path('wallet/add/', add_or_update_wallet, name='add-or-update-wallet'),
    ]