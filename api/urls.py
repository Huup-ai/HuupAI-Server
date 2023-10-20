from django.urls import path,include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import *

urlpatterns = [
    path('users/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('users/login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('users/register/', UserRegistrationAPI.as_view(), name='user-register'),
    path('provider/login/', ProviderLoginOrRegisterView.as_view(), name='provider-login'),
    path('users/info/', UserUpdateRetrieveView.as_view(), name='user-info'),
    path('users/payment_method/', UserPaymentMethodView.as_view(), name='get-payment-method'),
    
    path('clusters/', getAllCluster, name='cluster-list'),
    path('clusters/gpu', getAllGPUCluster, name='cluster-gpu-list'),
    path('clusters/cluster_name/<str:cluster_id>/', getClusterByName, name='cluster-detail'),
    path('clusters/my_clusters/', getClusterByUser, name='my-cluster'),
    path('clusters/set_price/', setPrice, name='set-price'),
    path('clusters/get_price/<str:cluster_id>/', get_cluster_price, name='get-cluster-price'),

    path('instances/<str:cluster_id>/getvmstatus/<str:name_space>/<str:vm_name>/',VMGet, name = 'vm-get-status'),
    path('instances/get_instances/', getInstances, name='get-instances'),
    path('instances/get_usage/', getAllUsage, name='get-usage'),
    
    path('instances/<str:cluster_id>/createvm/',VMCreate, name = 'vm-create'),
    path('instances/<str:cluster_id>/updatevm/',VMUpdate, name = 'vm-update'),
    path('instances/<str:cluster_id>/vmterminate/<str:name_space>/<str:vm_name>/',VMTerminate, name = 'vm-terminate'),

    path('inventory/getsshkey/<str:cluster_id>/', getSshKey, name='get-ssh-key'),
    path('invoices/get_user_invoices/', get_invoices, name='get-invoices'),
    path('invoices/pay/<int:invoice_id>/', pay_invoice, name='pay-invoice'),
    path('invoices/provider/pay/<int:invoice_id>/', provider_pay_invoice, name='provider-pay-invoice'),
    path('invoices/get_provider_invoices/', provider_get_invoice, name='get-provider-invoices'),

    path('invoices/check_payment_auth/', check_payment_auth, name='check-payment-auth'),
    path('invoices/add_payment_auth/', set_stripe_data, name='set-stripe-data'),

    path('wallets/get_wallets/', get_wallets, name='get-wallets'),
    path('wallet/add/', add_or_update_wallet, name='add-or-update-wallet'),
    ]