'''
IMPORTANT:

This is the hard-coded version for internal tests only. Please delete all the hardcoded token
and api endpoints before deployment

The COOKIES IS FOR SUPERUSER ONLY
'''
import os
COOKIES = {'R_SESS':'token-test01:62fwdpv2npks9vb4qbcjstzkrl98m6zc68tqrdmdkrdr4hjmtf98fz'}# DELETE THIS IN PRODUCTION USE
CERT = os.path.join(os.path.dirname(__file__), 'certificate.pem')


import requests
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from django.shortcuts import redirect
from .models import *
from .serializers import *
from .src.helper import *
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes

from django.contrib.auth import login, logout, authenticate
from rest_framework.permissions import IsAuthenticated
from django.db import transaction

from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny

###################################   Cluster API   #####################################
@api_view(['GET'])
@permission_classes([AllowAny])
def getAllCluster(request):
    # try:
        res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',cookies=COOKIES,headers={}, verify=CERT)
        if 200 <= res.status_code <= 299:
            return HttpResponse(res.content, status=res.status_code)
        else:
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)
    # except:
    #     return Response(status=status.HTTP_404_NOT_FOUND)


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
def getInstances(request, email):
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Verify the email parameter matches the authenticated user's email
    if request.user.email.lower() != email.lower():
        return Response({"error": "Email parameter does not match authenticated user's email."}, status=status.HTTP_400_BAD_REQUEST)
    
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
        if 200 <= res.status_code <= 299:
            if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
            return HttpResponse(res.content, status=res.status_code)
        else:
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)
    
    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
def VMCreate(request, cluster_id):
    print('is authorized?')
    # first check if user is authenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    print("yeah!")
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
        return JsonResponse({"error": f"Cannot create the instance in the database: {e}"}, status=status.HTTP_400_BAD_REQUEST)
    
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
        return HttpResponse(res.content, status=res.status_code)
    except Exception as err:
        # If the API call was not successful, delete the database instance
        instance.delete()
        return Response({"error": f"An error occurred: {err}"}, status=status.HTTP_400_BAD_REQUEST)
    

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
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)
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
            return JsonResponse(res.json())
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

class UserLoginAPI(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (SessionAuthentication,)

    def post(self, request):
        email = request.data.get('email')  # Change from username to email
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()  # Change from username to email

        if user and user.check_password(password):
            login(request, user)
            print("User logged in successfully")
            return Response({'message': 'User logged in successfully'})
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
class UserLogoutAPI(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()
    def post(self, request):
        logout(request)
        return Response({'message': 'User logged out successfully'})

@permission_classes([AllowAny])
class ProviderLoginOrRegisterView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')

        # Validate the input data
        if not email or not password:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if user exists
            user = User.objects.filter(email=email).first()
            if user:
                # Authenticate and login the user
                user = authenticate(request, username=email, password=password)
                if user:
                    login(request, user)
                    return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                # Register the user with api
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
                    login(request, user)
                    return Response({"message": "Registration and login successful"}, status=status.HTTP_201_CREATED)
                else:
                    return Response({"error": "External service registration failed"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserUpdateRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

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
        invoices = Invoice.objects.filter(user_id=request.user)
        
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
            
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
