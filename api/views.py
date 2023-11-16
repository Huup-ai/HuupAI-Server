'''
IMPORTANT:

This is the hard-coded version for internal tests only. Please delete all the hardcoded token
and api endpoints before deployment

The COOKIES IS FOR SUPERUSER ONLY
'''
from pathlib import Path
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny
from django.conf import settings
from django.db import transaction
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import login, logout, authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status, permissions
from rest_framework.views import APIView
from .src.helper import *
from .serializers import *
from .models import *
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.http import JsonResponse, HttpResponse
import uuid
import stripe
import json
import requests
import os
from datetime import datetime
from reportlab.pdfgen import canvas
from io import BytesIO
from google.oauth2 import id_token
from google.auth import transport

# DELETE THIS IN PRODUCTION USE
COOKIES = {
    'R_SESS': 'token-test01:62fwdpv2npks9vb4qbcjstzkrl98m6zc68tqrdmdkrdr4hjmtf98fz'}
CERT = os.path.join(os.path.dirname(__file__), 'certificate.pem')
STRIPE_API = 'sk_test_51NT86tLM79TglgywZ5DMu5q9nOyWvxzDLbdqLOeAClOAYRa823nz347d4kiNJ6TbTCLL03MQYlGllK0ooGZHcdAG00H48pWjm0'


###################################   Cluster API   #####################################

@api_view(['GET'])
@permission_classes([AllowAny])
def getAllCluster(request):
    if not settings.TEST_MODE:
        res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',
                           cookies=COOKIES, headers={}, verify=CERT)
        if 200 <= res.status_code <= 299:
            res = res.json()
            items = res.get('data')
        else:
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)

        result_list = []
        Cluster.objects.all().delete()
        for item in items:
            item_id = item.get('id')
            region = item.get('metadata', {}).get('labels', {}).get('region')
            allocatable = item.get('status', {}).get('allocatable', {})
            cpu = allocatable.get('cpu', 'N/A')
            memory = allocatable.get('memory', 'N/A')
            pods = allocatable.get('pods', 'N/A')
            virtualization = item.get('metadata', {}).get('labels', {}).get(
                'clusterType', 'non-virtualization') == 'virtualization'

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
                "price": price,
                "virtualization": virtualization
            }

            # Update the clusters database
            cluster = Cluster.objects.create(
                item_id=item_id,
                region=region,
                cpu=cpu,
                memory=memory,
                pods=pods,
                price=price,
                provider=None,
                virtualization=virtualization
            )
            # Append the dictionary to the result list
            result_list.append(result_dict)
        return JsonResponse(result_list, safe=False)
    else:
        CUR_DIR = Path(__file__).parent.absolute()
        CLUSTER_PATH = CUR_DIR / 'resources/clustersCPU.json'
        # Read data from clustersCPU.json file
        with open(CLUSTER_PATH, 'r') as file:
            clusters_data = json.load(file)

        for data in clusters_data:
            Cluster.objects.update_or_create(
                item_id=data['id'],
                defaults={
                    'region': data['region'],
                    'configuration': data['configuration'],
                    'price': data['price'],
                    'virtualization': data['virtualization'],
                    'is_audited': data['is_audited']
                }
            )
        clusters = clusters = Cluster.objects.filter(gpu__isnull=True)
        serializer = ClusterSerializer(clusters, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def getAllGPUCluster(request):
    CUR_DIR = Path(__file__).parent.absolute()
    CLUSTER_PATH = CUR_DIR / 'resources/clustersGPU.json'
    if not settings.TEST_MODE:
        res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',
                           cookies=COOKIES, headers={}, verify=CERT)
        if 200 <= res.status_code <= 299:
            res = res.json()
            items = res.get('data')
        else:
            return Response({'error': 'Bad Request'}, status=status.HTTP_400_BAD_REQUEST)

        result_list = []
        Cluster.objects.all().delete()
        for item in items:
            item_id = item.get('id')
            region = item.get('metadata', {}).get('labels', {}).get('region')
            allocatable = item.get('status', {}).get('allocatable', {})
            cpu = allocatable.get('gpu', 'N/A')
            memory = allocatable.get('memory', 'N/A')
            pods = allocatable.get('pods', 'N/A')
            virtualization = item.get('metadata', {}).get('labels', {}).get(
                'clusterType', 'non-virtualization') == 'virtualization'

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
                "price": price,
                "virtualization": virtualization
            }

            # Update the clusters database
            cluster = Cluster.objects.create(
                item_id=item_id,
                region=region,
                cpu=cpu,
                memory=memory,
                pods=pods,
                price=price,
                provider=None,
                virtualization=virtualization
            )
            # Append the dictionary to the result list
            result_list.append(result_dict)
        return JsonResponse(result_list, safe=False)
    else:
        CUR_DIR = Path(__file__).parent.absolute()
        CLUSTER_PATH = CUR_DIR / 'resources/clustersGPU.json'
        # Read data from clustersCPU.json file
        with open(CLUSTER_PATH, 'r') as file:
            clusters_data = json.load(file)

        for data in clusters_data:
            Cluster.objects.update_or_create(
                item_id=data['id'],
                defaults={
                    'region': data['region'],
                    'configuration': data['configuration'],
                    'price': data['price'],
                    'gpu': data['gpu'],
                    'is_audited': data['is_audited']
                }
            )
        clusters = Cluster.objects.filter(gpu__isnull=False)
        serializer = ClusterSerializer(clusters, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def getClusterByName(request, cluster_id):
    try:
        res = requests.get(
            f"https://edgesphere.szsciit.com/v1/management.cattle.io.clusters/{cluster_id}", cookies=COOKIES, headers={}, verify=CERT)
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

    cluster_id = request.data.get('item_id')#cluster_id
    price = request.data.get('price')

    if cluster_id is None or price is None:
        return Response({'error': 'cluster_id and price are required'}, status=status.HTTP_400_BAD_REQUEST)

    pricing, created = Pricing.objects.update_or_create(
        cluster_id=cluster_id,
        defaults={'price': price}
    )

    serializer = PricingSerializer(pricing)

    try:
        cluster = Cluster.objects.get(item_id=cluster_id)
        if cluster.provider != user:
            return Response({'error': 'User is not the provider of this cluster'}, status=status.HTTP_403_FORBIDDEN)
        cluster.price = price
        cluster.save()

        serializer = ClusterSerializer(cluster)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Cluster.DoesNotExist:
        return Response({'error': 'Cluster not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def getClusterByUser(request):
    user = request.user

    # Assuming User model has a boolean field named 'is_provider'
    if not user.is_provider:
        return Response({"error": "User is not a provider."}, status=status.HTTP_400_BAD_REQUEST)

    clusters = Cluster.objects.filter(provider=user)
    serializer = ClusterSerializer(clusters, many=True)

    return Response(serializer.data, status=status.HTTP_200_OK)


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
    # Get instances with information relate to cluster
    instances = Instance.objects.select_related(
        'cluster').filter(user_id=request.user)

    with transaction.atomic():
        # Update the usage and start_time for all instances
        for instance in instances:
            time_delta = timezone.now() - instance.start_time
            instance.usage += round(time_delta.total_seconds() / 3600, 2)
            instance.start_time = timezone.now()
            instance.save()

    # Fetch instance IDs for which there are unpaid invoices
    unpaid_instance_ids = Invoice.objects.filter(
        instance__in=instances, paid=False).values_list('instance_id', flat=True)

    result_list = [
        {
            'instance_id': i.instance_id,
            'usage': i.usage,
            'cluster': {
                'item_id': i.cluster.item_id,
                'region': i.cluster.region,
                'cpu': i.cluster.cpu,
                'gpu': i.cluster.gpu,
                'config': i.cluster.configurations,
                'memory': i.cluster.memory,
                'pods': i.cluster.pods,
                'price': i.cluster.price,
            },
            'total_price': i.usage*i.cluster.price
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

    time_delta = timezone.now() - instance.start_time
    instance.usage += round(time_delta.total_seconds() / 3600, 2)
    instance.start_time = timezone.now()
    instance.save()
    if not instance:
        return Response({"error": "Instance not found."}, status=status.HTTP_404_NOT_FOUND)

    # If instance exists, make the API call
    json = {'clusterid': cluster_id,
            'vmName': vm_name, 'namespace': vm_namespace}
    try:
        if settings.TEST_MODE:
            serializer = InstanceSerializer(instance)
            return Response(serializer.data)

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
    # check if the cluster can start a vm
    try:
        cluster = Cluster.objects.get(item_id=cluster_id)
        if not cluster.virtualization:
            return Response({"error": "Virtualization is not enabled for this cluster."}, status=status.HTTP_400_BAD_REQUEST)
    except Cluster.DoesNotExist:
        return Response({"error": "Cluster not found."}, status=status.HTTP_404_NOT_FOUND)

    # feed into the serializer
    serializer = VMCreateSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    metadata = serializer.validated_data['metadata']
    metadata['service'] =  cluster.service
    # Create an instance in the database
    try:
        instance = start_instance(request.user, metadata, cluster)
    except Exception as e:
        return Response({"error": f"Cannot create the instance in the database: {e}"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        # Try to make the API call if not in test mode
        if not settings.TEST_MODE:
            if cluster.service == 'amazon':
                create_instances_helper()
                start_instance_helper(instance.id)
            # If the API call was successful, return a success response
            return Response({'message':'instance created'})
        else:
            return Response({"message": "Instance has been created"}, status=status.HTTP_200_OK)
    except Exception as err:
        # If the API call was not successful, delete the database instance
        instance.delete()
        return Response(err)


@api_view(['POST'])
def VMUpdate(request,instance_id):
    # check if user is anthenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

    action = 'stopped'
    instance = Instance.objects.get(
                user_id=request.user, instance_id=instance_id)
    try:
        if not settings.TEST_MODE:
            if instance.service == 'amazon':
                res = stop_instance_helper(instance_id)
            else:
                pass

        if settings.TEST_MODE or res:

            # Update the instance using src helper function
            update_instance(instance, action)
            return Response({"message": "Update successfully"}, status=status.HTTP_200_OK)

        else:
            return Response(res.content, status=res.status_code)

    except Instance.DoesNotExist:
        return Response({"error": "Instance not found."}, status=status.HTTP_404_NOT_FOUND)
    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
def VMTerminate(request, instance_id):
    # First, ensure the user is authenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        # Check if the instance exists based on the vm_name, vm_namespace, and user.
        instance = Instance.objects.get(
            user_id=request.user,
            instance_id = instance_id
        )

        if not settings.TEST_MODE:
            res = stop_instance_helper(instance.id)

        # If TEST_MODE or the request was successful, update the instance.
        if settings.TEST_MODE or res:
            update_instance(instance, "terminated")
            return Response({"message": "Instance terminate successfully"}, status=status.HTTP_200_OK)
        else:
            return Response(res.content, status=res.status_code)

    except Instance.DoesNotExist:
        return Response({"error": "Instance not found for this user."}, status=404)
    except requests.RequestException:  # More specific than a general exception
        return Response({"error": "Failed to terminate VM in the cloud."}, status=status.HTTP_404_NOT_FOUND)

###################################   USER API    #####################################
CLIENT_ID = settings.GOOGLE_OAUTH2_CLIENT_ID

class UserRegistrationAPI(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GoogleLoginView(APIView):
    def post(self, request, *args, **kwargs):
        token = request.data.get('token_id')
        try:
            # Validate the token
            idinfo = id_token.verify_oauth2_token(token, transport.requests.Request(), settings.GOOGLE_OAUTH2_CLIENT_ID)

            # Extract user info
            email = idinfo.get('email')

            # Create or update user
            user, created = User.objects.get_or_create(email=email)

            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            jwt_token = str(refresh.access_token)

            return Response({'jwt_token': jwt_token}, status=status.HTTP_200_OK)
        
        except ValueError:
            # Invalid token
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class ProviderLoginOrRegisterView(APIView):
    permission_classes = (permissions.AllowAny,)

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
                if user.is_provider:
                    # Authenticate the user without session login
                    if user.check_password(password):
                        refresh = RefreshToken.for_user(user)
                        # Check if the user has a wallet
                        wallet = Wallet.objects.filter(user=user).first()
                        wallet_address = wallet.address if wallet else None

                        return Response({
                            'refresh': str(refresh),
                            'access': str(refresh.access_token),
                            'wallet_address': wallet_address
                        })
                    else:
                        return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"error": "user is not a provider"})
            # if user not exists
            else:
                # Register the user with the external API
                if settings.TEST_MODE:
                    user = User.objects.create(email=email, is_provider=True)
                    user.set_password(password)
                    user.save()
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'wallet_address': None,
                        "message": "Registration successful"
                    }, status=status.HTTP_201_CREATED)
                else:
                    response = requests.post('https://edgesphere.szsciit.com/v3-public/localProviders/local?action=login',
                                             json={
                                                 "description": "test",
                                                 "password": password,
                                                 "responseType": "cookie",
                                                 "username": email
                                             },
                                             verify=CERT,
                                             cookies=COOKIES)
                    if response.status_code == 200:
                        # Create a new user in your database
                        user = User.objects.create(
                            email=email, is_provider=True)
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
                            'wallet_address': None,
                            "message": "Registration successful"
                        }, status=status.HTTP_201_CREATED)
                    else:
                        return Response(response.content, status=response.status_code)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserUpdateRetrieveView(APIView):

    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):

    def post(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            if not user.check_password(old_password):
                return Response({'old_password': 'Wrong password.'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            return Response({'status': 'password set'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPaymentMethodView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user  # Use the user from the request
        return Response({"email": user.email, "payment_method": user.payment_method}, status=status.HTTP_200_OK)

    def post(self, request):
        user = request.user  # Use the user from the request
        payment_method = request.data.get('payment_method')

        if not payment_method:
            return Response({"error": "Payment method is required"}, status=status.HTTP_400_BAD_REQUEST)

        user.payment_method = payment_method
        user.save()

        return Response({
            "message": "Payment method updated successfully"
        }, status=status.HTTP_200_OK)
###################################   INVENTORY API    #####################################


@api_view(['GET'])
def getSshKey(request, cluster_id):
    if not settings.TEST_MODE:
        try:
            json_data = {"clusterid": cluster_id}
            # Making a GET request to the provided URL
            res = requests.post(
                f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/cnos.io.sshpublic", cookies=COOKIES, verify=CERT, json=json_data)

            # Return the content and status code
            return HttpResponse(res.content, status=res.status_code)
        except requests.RequestException as e:
            return Response({"error": str(e)}, status=500)
    else:
        with open('api/resources/sshkey.json', 'r') as json_file:
            data = json.load(json_file)
            return Response(data, status=200)


@api_view(['GET'])
def get_invoices(request):
    try:
        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        # Get all the invoices for the authenticated user
        invoices = Invoice.objects.filter(user_id=request.user, paid=False)

        # Create a PDF document
        pdf_filename = "example.pdf"
        document_title = "Sample PDF Document"
        pdf_buffer = BytesIO()
        # Create a canvas
        pdf_canvas = canvas.Canvas(pdf_filename)

        # Set document title
        pdf_canvas.setTitle(document_title)

        # Add content to the PDF
        pdf_canvas.drawString(100, 750, "Hello, this is a sample PDF document.")
        pdf_canvas.drawString(100, 700, "You can add more content here.")

        # Save the PDF file
        pdf_canvas.save()

        # Serialize the invoice data
        serializer = InvoiceSerializer(invoices,many=True)

        # 获取 PDF 内容
        pdf_content = pdf_buffer.getvalue()
        pdf_buffer.close()

        # 将 PDF 保存到一个临时文件中
        temp_pdf_path = 'temp.pdf'
        with open(temp_pdf_path, 'wb') as temp_pdf:
            temp_pdf.write(pdf_content)

        # Combine the serialized data and PDF content into a dictionary
        response_data = {
            'pdf': open(temp_pdf_path, 'rb'),
            'invoice': serializer.data,
        }

        # Return the serialized data in the response
        return Response(response_data , status=status.HTTP_200_OK)
    except Invoice.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def pay_invoice(request, invoice_id):
    try:
        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        # Get the invoice to be paid
        invoice = Invoice.objects.get(
            invoice_id=invoice_id, user_id=request.user)
        stripe_customer = StripeCustomer.objects.get(user=request.user)

        stripe.api_key = STRIPE_API
        try:
            payment_intent = stripe.PaymentIntent.create(
                amount=int(invoice.total_price * 100),  # Amount in cents
                currency='usd',  # Set to your preferred currency
                customer=stripe_customer.stripe_customer_id,
                payment_method=stripe_customer.stripe_payment
            )

            # Check payment status and update invoices
            if payment_intent.status == "succeeded":
                invoice.paid = True
                invoice.save()
        except StripeCustomer.DoesNotExist:
            print(
                f"User ID {request.user.id} does not have an associated Stripe Customer.")
        except stripe.error.StripeError as e:
            print(f"Stripe error for User ID {request.user.id}: {e}")

        return Response({'message': 'Invoice paid and table reset successfully'}, status=status.HTTP_200_OK)
    except Invoice.DoesNotExist:
        return Response({'error': 'Invoice not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def provider_get_invoice(request):

    if not request.user.is_provider:
        return Response({'error': 'User is not a provider, please use get_invoice api'})

    invoices = Invoice.objects.select_related('instance').filter(
        instance__provider_id=request.user, provider_paid=False)

    data = [{
        'vm_name': invoice.instance.vm_name,
        'usage': invoice.usage,
        'total_price': invoice.total_price
    } for invoice in invoices]

    return Response(data)


@api_view(['POST'])
def provider_pay_invoice(request):
    if not request.user.is_provider:
        return Response({'error': 'User is not a provider, please use get_invoice api'})

    invoice_id = request.data.get('invoice_id')
    if not invoice_id:
        return Response({'error': 'Invoice ID is required'}, status=400)

    try:
        invoice = Invoice.objects.get(
            id=invoice_id, instance__provider_id=request.user, provider_paid=False)
    except Invoice.DoesNotExist:
        return Response({'error': 'Invoice not found or already paid'}, status=404)

    total_price = invoice.total_price

    try:
        stripe_customer = StripeCustomer.objects.get(user=request.user)
    except StripeCustomer.DoesNotExist:
        return Response({'error': 'Stripe customer not found'}, status=404)

    stripe.api_key = STRIPE_API

    # Create a payout
    try:
        payout = stripe.Payout.create(
            amount=int(total_price * 100),  # convert to cents
            currency='usd',
            method='instant',
            destination=stripe_customer.stripe_account
        )
    except stripe.error.StripeError as e:
        return Response({'error': str(e)}, status=400)

    # Update the provider_paid field
    invoice.provider_paid = True
    invoice.save()

    return Response({'status': 'success', 'payout_id': payout.id}, status=200)


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
                Wallet.objects.filter(
                    user=request.user, is_provider=True).delete()
            else:
                Wallet.objects.filter(address=serializer.validated_data.get(
                    'address'), is_provider=False).delete()

            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

###################################   STRIPE API    #####################################


@api_view(['GET'])
def check_payment_auth(request):
    user = request.user
    print(user.email)
    # Check if user is in StripeCustomer table
    try:
        stripe_customer = StripeCustomer.objects.get(user=user)
    except StripeCustomer.DoesNotExist:
        print('User is not associated with a Stripe Customer')
        return Response({"error": "User is not associated with a Stripe Customer"}, status=status.HTTP_404_NOT_FOUND)

    # Assuming the payment method is stored in stripe_payment
    payment_method_id = stripe_customer.stripe_payment

    if not payment_method_id:
        print('No payment method found for user')
        return Response({"error": "No payment method found for user"}, status=status.HTTP_400_BAD_REQUEST)

    if settings.TEST_MODE:
        return Response({"message": "Payment method is valid"}, status=status.HTTP_200_OK)
    # Now, create a SetupIntent using Stripe API to check if payment can be authorized
    stripe.api_key = STRIPE_API

    try:
        setup_intent = stripe.SetupIntent.create(
            payment_method=payment_method_id,
            customer=stripe_customer.stripe_customer_id,
        )

        if setup_intent.status == "succeeded":
            return Response({"message": "Payment method is valid"}, status=status.HTTP_200_OK)
        else:
            print('Payment method validation failed')
            return Response({"error": "Payment method validation failed"}, status=status.HTTP_400_BAD_REQUEST)

    except stripe.error.StripeError as e:
        print('stripe error')
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def set_stripe_data(request):
    user = request.user
    stripe_payment = request.data.get('stripe_payment')
    stripe_account = request.data.get('stripe_account')
    stripe.api_key = STRIPE_API

    if not stripe_payment and not stripe_account:
        return Response({'error': 'Payment token or bank account token is required'}, status=400)

    if stripe_payment:
        user.payment_method = 'credit_card'
        user.save()

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
            stripe_payment=stripe_payment
        )

    # Check whether the payment method needs to be updated
    if stripe_payment and stripe_customer.stripe_payment != stripe_payment:
        # Attach the new payment method to the customer in Stripe
        try:
            stripe.PaymentMethod.attach(
                stripe_payment,
                customer=stripe_customer.stripe_customer_id
            )
            # Update the default payment method in Stripe
            stripe.Customer.modify(
                stripe_customer.stripe_customer_id,
                invoice_settings={'default_payment_method': stripe_payment},
            )
        except:
            return Response({'error': 'Unable to update payment method, use test card and try again'}, status=400)
        # Update the payment method in the local DB
        stripe_customer.stripe_payment = stripe_payment
        stripe_customer.save()

        # Retrieve the last four digits of the card
        payment_method_details = stripe.PaymentMethod.retrieve(stripe_payment)
        last_four = payment_method_details.card.last4

        # Store the last four digits to the User model's credit_card field
        user.credit_card = last_four
        user.save()

    # Update bank account token
    if stripe_account:
        stripe_customer.stripe_account = stripe_account
        stripe_customer.save()

    return JsonResponse({'status': 'success'}, status=200)
