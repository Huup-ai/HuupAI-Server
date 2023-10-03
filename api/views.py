'''
IMPORTANT:

This is the hard-coded version for internal tests only. Please delete all the hardcoded token
and api endpoints before deployment

The COOKIES IS FOR SUPERUSER ONLY
'''
import os
COOKIES = {'R_SESS':'token-test01:62fwdpv2npks9vb4qbcjstzkrl98m6zc68tqrdmdkrdr4hjmtf98fz'}# DELETE THIS IN PRODUCTION USE
CERT = os.path.join(os.path.dirname(__file__), 'certificate.pem')
STRIPE_API = 'sk_test_51NT86tLM79TglgywZ5DMu5q9nOyWvxzDLbdqLOeAClOAYRa823nz347d4kiNJ6TbTCLL03MQYlGllK0ooGZHcdAG00H48pWjm0'


import requests
import json
import stripe
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from .models import *
from .serializers import *
from .src.helper import *
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes

from django.contrib.auth import login, logout, authenticate
from rest_framework.permissions import IsAuthenticated
from django.db import transaction

from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

###################################   Cluster API   #####################################
@api_view(['GET'])
@permission_classes([AllowAny])
def getAllCluster(request):
        res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',cookies=COOKIES,headers={}, verify=CERT)
        if 200 <= res.status_code <= 299:
            res = res.json()
            items = res.get('data')
        else:
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)

        result_list = []
        Cluster.objects.all().delete()
        for item in items:
            item_id = item.get('id')
            region = item.get('metadata',{}).get('labels',{}).get('region')
            allocatable = item.get('status',{}).get('allocatable',{})
            cpu = allocatable.get('cpu','N/A')
            memory = allocatable.get('memory','N/A')
            pods = allocatable.get('pods','N/A')

            try:
                price_obj = Pricing.objects.get(cluster_id=item_id)
                price = price_obj.price
            except Pricing.DoesNotExist:
                price = 1

            result_dict = {
                "id": item_id,
                "region": region,
                "cpu": cpu,
                "memory": memory,
                "pods": pods,
                "price":price
            }

            # Update the clusters database
            cluster = Cluster.objects.create(
            item_id=item_id,
            region=region,
            cpu=cpu,
            memory=memory,
            pods=pods,
            price=price,
            provider=None
        )
            # Append the dictionary to the result list
            result_list.append(result_dict)
        return JsonResponse(result_list, safe=False)

@api_view(['GET'])
def getClusterByName(requrest,cluster_id):
    try:
        res = requests.get(f"https://edgesphere.szsciit.com/v1/management.cattle.io.clusters/{cluster_id}",cookies=COOKIES,headers={}, verify=CERT)
        if 200 <= res.status_code <= 299:
            return HttpResponse(res.content, status=res.status_code)
        else:
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
def get_cluster_price(request, cluster_id):
    try:
        pricing_instance = Pricing.objects.get(cluster_id=cluster_id)
        return Response({"price": pricing_instance.price}, status=status.HTTP_200_OK)
    except Pricing.DoesNotExist:
        return Response({"error": "Cluster ID not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def setPrice(request):
    # user must be a provider and must be logged in
    user = request.user
    if not user.is_provider:
        return Response({'error': 'Only providers can set prices'}, status=status.HTTP_403_FORBIDDEN)

    cluster_id = request.data.get('cluster_id')
    price = request.data.get('price')

    if cluster_id is None or price is None:
        return Response({'error': 'cluster_id and price are required'}, status=status.HTTP_400_BAD_REQUEST)

    pricing, created = Pricing.objects.update_or_create(
        cluster_id=cluster_id, 
        defaults={'price': price}
    )
    
    serializer = PricingSerializer(pricing)
    return Response(serializer.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

@api_view(['GET'])
def getClusterByUser(request):
    # user must be a provider and must be logged in
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    
    user = request.user
    if not user.is_provider:
        return Response({'error': 'Only providers can get clusters'}, status=status.HTTP_403_FORBIDDEN)
    # try:
    res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',cookies=user.token,headers={}, verify=CERT)
    if 200 <= res.status_code <= 299:
            return HttpResponse(res.content, status=res.status_code)
    else:
        return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)
    # except:
    #     return Response(status=status.HTTP_404_NOT_FOUND)

    
###################################   VM API    #####################################
@api_view(['GET'])
def getInstances(request):
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    

    instances = Instance.objects.filter(user_id=request.user)
    
    # Update the usage field for each instance
    for instance in instances:
        # first check if the instance is already terminated
        if instance.status != 'terminated':
            time_delta = timezone.now() - instance.start_time
            new_usage = time_delta.total_seconds() / 3600  # Calculate usage in hours
            instance.usage += new_usage
            instance.start_time = timezone.now()  # Reset the start_time to now
            instance.save()

    # serialize the updated instances data
    serializer = InstanceSerializer(instances, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def getAllUsage(request):
    instances = Instance.objects.select_related('cluster').filter(user_id=request.user)

    with transaction.atomic():
        # Update the usage and start_time for all instances
        for instance in instances:
            time_delta = timezone.now() - instance.start_time
            instance.usage += round(time_delta.total_seconds() / 3600,2)
            instance.start_time = timezone.now()
            instance.save()

    # Fetch instance IDs for which there are unpaid invoices
    unpaid_instance_ids = Invoice.objects.filter(instance__in=instances, is_paid=False).values_list('instance_id', flat=True)

    result_list = [
        {
            'instance_id': i.id, 
            'usage': i.usage, 
            'cluster': {
                'item_id': i.cluster.item_id,
                'region': i.cluster.region,
                'cpu': i.cluster.cpu,
                'memory': i.cluster.memory,
                'pods': i.cluster.pods,
                'price': i.cluster.price,
            },
            'total_price':i.usage*i.cluster.price
        } 
        for i in instances if i.id in unpaid_instance_ids
    ]

    return JsonResponse(result_list, safe=False)

@api_view(['POST'])
def VMGet(request, cluster_id, vm_name, vm_namespace):
    # Authenticate the user
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Check if the instance is in the database
    instance = Instance.objects.filter(
        user_id=request.user,
        cluster=cluster_id,
        vm_name=vm_name,
        vm_namespace=vm_namespace
    ).first()
    
    if not instance:
        return Response({"error": "Instance not found."}, status=status.HTTP_404_NOT_FOUND)

    # If instance exists, make the API call
    json = {'clusterid': cluster_id, 'vmName': vm_name, 'namespace': vm_namespace}
    try:
        res = requests.post(
            f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine/{vm_namespace}/{vm_name}",
            cookies=COOKIES,
            json=json,
            verify=CERT
        )
        res.raise_for_status()
        return Response(res.content, status=res.status_code)

    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
def VMCreate(request, cluster_id):
    # first check if user is authenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    # feed into the serializer
    serializer = VMCreateSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    metadata = serializer.validated_data['metadata']
    spec = serializer.validated_data['spec']
    status_info = serializer.validated_data['status']
    payload = {'metadata': metadata, 'spec': spec, 'status': status_info}
    # Create an instance in the database
    try:
        instance = start_instance(request.user, metadata, cluster_id)
    except Exception as e:
        return Response({"error": f"Cannot create the instance in the database: {e}"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        # Try to make the API call
        res = requests.post(
            f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine",
            cookies=COOKIES,
            json=payload, 
            verify=CERT
        )
        res.raise_for_status()
        # If the API call was successful, return a success response
        return Response(res.content, status=res.status_code)
    except Exception as err:
        # If the API call was not successful, delete the database instance
        instance.delete()
        return Response(res.content, status=res.status_code)
    

@api_view(['POST'])
def VMUpdate(request, cluster_id, vm_name, vm_namespace):
    #check if user is anthenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    
    serializer = VMUpdateSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=400)
    action = serializer.validated_data['action']

    try:
        res = requests.post(
            f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine/{vm_namespace}/{vm_name}?action={action}",
            cookies=COOKIES,
            json={"cluster_id": cluster_id, "action": action, "vmName":vm_name, "namespace":vm_namespace},
            verify=CERT
        )

        if res.status_code == 200:
            # Retrieve the corresponding instance
            instance = Instance.objects.get(user_id=request.user, vm_name=vm_name)
            
            # Update the instance using src helper function
            update_instance(instance, action)
            
        else:
            Response(res.content, status=res.status_code)
    except Instance.DoesNotExist:
        return Response({"error": "Instance not found."}, status=status.HTTP_404_NOT_FOUND)
    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)

@api_view(['POST'])
def VMTerminate(request, cluster_id, vm_name, vm_namespace):
    # First, ensure the user is authenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        # Check if the instance exists based on the vm_name, vm_namespace, and user.
        instance = Instance.objects.get(
            vm_name=vm_name, 
            vm_namespace=vm_namespace, 
            user_id=request.user
        )

        # if instance exists, send the request to terminate the VM in the cloud
        json = {'clusterid': cluster_id, 'vmName': vm_name, 'namespace': vm_namespace}
        res = requests.post(
            f"wss://edgesphere.szsciit.com/wsproxy/k8s/clusters/{cluster_id}/apis/subresources.kubevirt.io/v1/namespaces/{vm_namespace}/virtualmachineinstances/{vm_name}/vnc",
            cookies=COOKIES,
            json=json,
            verify=CERT
        )
        
        # If the request was successful, update the instance.
        if res.status_code == 200:
            update_instance(instance, "terminated")
            return Response(res.content, status=res.status_code)
        else:
            return HttpResponse(res.content, status=res.status_code)
        
    except Instance.DoesNotExist:
        return Response({"error": "Instance not found for this user."}, status=404)
    except requests.RequestException:  # More specific than a general exception
        return Response({"error": "Failed to terminate VM in the cloud."}, status=status.HTTP_404_NOT_FOUND)


###################################   USER API    #####################################
class UserRegistrationAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class ProviderLoginOrRegisterView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        email = request.data.get('username')
        password = request.data.get('password')
        # Validate the input data
        if not email or not password:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if user exists
            user = User.objects.filter(email=email).first()
            if user:
                if user.is_provider:
                    # Authenticate the user without session login
                    if user.check_password(password):
                        refresh = RefreshToken.for_user(user)
                        return Response({
                            'refresh': str(refresh),
                            'access': str(refresh.access_token),
                        })
                    else:
                        return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"error":"user is not a provider"})

            else:
                # Register the user with the external API
                response = requests.post('https://edgesphere.szsciit.com/v3-public/localProviders/local?action=login', 
                                         data={'username': email, 
                                               'password': password, 
                                               'responseType':'cookie'},
                                               verify=CERT)
                if response.status_code == 200:
                    # Create a new user in your database
                    user = User.objects.create(email=email, is_provider=True)
                    user.set_password(password)
                    cookies = response.headers.get('Set-Cookie')
                    if cookies:
                        token = cookies.split(';')[0].split('=')[1]
                        user.token = token
                    user.save()

                    # Generate JWT tokens for the new user
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        "message": "Registration successful"
                    }, status=status.HTTP_201_CREATED)
                else:
                    return Response(response.content, status=response.status_code)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserUpdateRetrieveView(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserPaymentMethodView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        email = request.query_params.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            return Response({"email": user.email, "payment_method": user.payment_method}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    
    def post(self, request):
        email = request.query_params.get('email')
        payment_method = request.data.get('payment_method')
        if not payment_method:
            return Response({"error": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            user.payment_method = payment_method
            user.save()

            return Response({
                "message": "Payment method updated successfully"
            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
###################################   INVENTORY API    #####################################
@api_view(['POST'])
def getSshKey(request, cluster_id):

    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        json = {"clusterid":cluster_id}
        # Making a GET request to the provided URL
        res = requests.post(f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/cnos.io.sshpublic", cookies=COOKIES, verify=CERT, json = json)
        
        # Return the content and status code
        return HttpResponse(res.content, status=res.status_code)
    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
def get_invoices(request):
    try:
        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        # Get all the invoices for the authenticated user
        invoices = Invoice.objects.filter(user_id=request.user, paid = False)
        
        # Serialize the invoice data
        serializer = InvoiceSerializer(invoices, many=True)
        
        # Return the serialized data in the response
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Invoice.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def pay_invoice(request, invoice_id):
    try:
        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        # Get the invoice to be paid
        invoice = Invoice.objects.get(invoice_id=invoice_id, user_id=request.user)
        
        # Mark the invoice as paid
        invoice.paid = True
        invoice.save()
        
        # Reset the invoice table
        with transaction.atomic():
            Invoice.objects.filter(paid=True).delete()

        return Response({'message': 'Invoice paid and table reset successfully'}, status=status.HTTP_200_OK)
    except Invoice.DoesNotExist:
        return Response({'error': 'Invoice not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

###################################   Web3 API    #####################################
@api_view(['GET'])
def get_wallets(request):
    # the user must be logged in to view his wallets
    if request.user.is_authenticated:
        wallets = Wallet.objects.filter(user=request.user)
        serializer = WalletSerializer(wallets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def add_or_update_wallet(request):
    if request.user.is_authenticated:
        serializer = WalletSerializer(data=request.data)
        if serializer.is_valid():
            is_provider = serializer.validated_data.get('is_provider')
            
            # If the user is a provider, update the existing wallet address
            if is_provider:
                Wallet.objects.filter(user=request.user, is_provider=True).delete()
            else:
                Wallet.objects.filter(address=serializer.validated_data.get('address'), is_provider=False).delete()
            
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

###################################   STRIPE API    #####################################
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_payment_auth(request):
    user = request.user

    # Check if user is in StripeCustomer table
    try:
        stripe_customer = StripeCustomer.objects.get(user=user)
    except StripeCustomer.DoesNotExist:
        return Response({"error": "User is not associated with a Stripe Customer"}, status=status.HTTP_404_NOT_FOUND)

    # Assuming the payment method is stored in stripe_payment
    payment_method_id = stripe_customer.stripe_payment

    if not payment_method_id:
        return Response({"error": "No payment method found for user"}, status=status.HTTP_400_BAD_REQUEST)

    # Now, create a SetupIntent using Stripe API to check if payment can be authorized
    stripe.api_key = STRIPE_API

    try:
        setup_intent = stripe.SetupIntent.create(
            payment_method=payment_method_id,
        )

        if setup_intent.status == "succeeded":
            return Response({"message": "Payment method is valid"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Payment method validation failed"}, status=status.HTTP_400_BAD_REQUEST)

    except stripe.error.StripeError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_stripe_data(request):
    user = request.user
    stripe_payment = request.data.get('stripe_payment')
    stripe.api_key = STRIPE_API

    try:
        stripe_customer = StripeCustomer.objects.get(user=request.user)
    except StripeCustomer.DoesNotExist:
        # If StripeCustomer does not exist, create a new customer in Stripe
        customer = stripe.Customer.create(
            email=request.user.email,
            payment_method=stripe_payment,
            invoice_settings={'default_payment_method': stripe_payment},
        )

        # Create a new StripeCustomer in the local DB
        stripe_customer = StripeCustomer.objects.create(
            user=user,
            stripe_customer_id=customer['id'],
            stripe_payment_method=stripe_payment
        )

    # Check whether the payment method needs to be updated
    if stripe_customer.stripe_payment != stripe_payment and stripe_payment:
        # Attach the new payment method to the customer in Stripe
        stripe.PaymentMethod.attach(
            stripe_payment,
            customer=stripe_customer.stripe_customer_id
        )
        # Update the default payment method in Stripe
        stripe.Customer.modify(
            stripe_customer.stripe_customer_id,
            invoice_settings={'default_payment_method': stripe_payment},
        )
        # Update the payment method in the local DB
        stripe_customer.stripe_payment = stripe_payment
        stripe_customer.save()

    return JsonResponse({'status': 'success'}, status=200)