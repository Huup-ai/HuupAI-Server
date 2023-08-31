'''
IMPORTANT:

This is the hard-coded version for internal tests only. Please delete the return statements and 
use the commented out code for the future use.

The COOKIES IS FOR TEST ONLY
'''
COOKIES = {'R_SESS':'token-test01:62fwdpv2npks9vb4qbcjstzkrl98m6zc68tqrdmdkrdr4hjmtf98fz'}# DELETE THIS IN PRODUCTION USE

import requests
from django.http import JsonResponse, HttpResponse
from rest_framework.response import Response
from django.shortcuts import redirect
from .models import *
from .serializers import *
from .src.helper import *
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.decorators import api_view

from django.contrib.auth import login, logout
from rest_framework.permissions import IsAuthenticated

###################################   Cluster API   #####################################
@api_view(['GET'])
def getAllCluster(request):
    try:
        res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',cookies=COOKIES,headers={}, verify=False)
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def GetClusterByName(requrest,cluster_id):
    try:
        res = requests.get(f"https://edgesphere.szsciit.com/v1/management.cattle.io.clusters/{cluster_id}",cookies=COOKIES,headers={}, verify=False)
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

###################################   VM API    #####################################
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
            verify=False
        )
        
        if res.headers.get('content-type') == 'application/json':
            return JsonResponse(res.json())
        
        return HttpResponse(res.content, status=res.status_code)
    
    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)


@api_view(['POST'])
def VMCreate(request,cluster_id):
    #First check if user is anthenticated
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
    # create the serializer
    serializer = VMCreateSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=400)
    #extract necessory data from request
    metadata = serializer.validated_data['metadata']
    spec = serializer.validated_data['spec']
    status_info = serializer.validated_data['status']
    json = {'metadata':metadata,'spec':spec,'status':status_info}

    try:
        #send the requests to the cloud
        res = requests.post(f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine",
                            cookies=COOKIES,
                            json = json, 
                            verify=False)
        # Try to create the instance
        record = start_instance(request.user, spec, cluster_id)
        if record:
            return Response(res.content, status=res.status_code)
        else:
            return JsonResponse({"error": "Can not create the instance"}, status=400)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)
    

@api_view(['POST'])
def VMUpdate(request, cluster_id, vm_name, vm_namespace):
    #First check if user is anthenticated
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
            verify=False
        )

        if res.status_code == 200:  # Assuming 200 is the success status code
            # Retrieve the corresponding instance
            instance = Instance.objects.get(user_id=request.user, vm_name=vm_name)
            
            # Update the instance using the provided function
            update_instance(instance, action)

        return Response(res.json(), status=res.status_code)
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

        # If instance exists, send the request to terminate the VM in the cloud
        json = {'clusterid': cluster_id, 'vmName': vm_name, 'namespace': vm_namespace}
        res = requests.post(
            f"wss://edgesphere.szsciit.com/wsproxy/k8s/clusters/{cluster_id}/apis/subresources.kubevirt.io/v1/namespaces/{vm_namespace}/virtualmachineinstances/{vm_name}/vnc",
            cookies=COOKIES,
            json=json,
            verify=False
        )
        
        # Check the response status. If the request was successful, update the instance.
        if res.status_code == 200:  # Assuming a 200 status code indicates success
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
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginAPI(APIView):
    def post(self, request):
        email = request.data.get('email')  # Change from username to email
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()  # Change from username to email

        if user and user.check_password(password):
            login(request, user)
            return Response({'message': 'User logged in successfully'})
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class UserLogoutAPI(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        logout(request)
        return Response({'message': 'User logged out successfully'})
    
###################################   INVENTORY API    #####################################
@api_view(['GET'])
def GetSshKey(request, clusterid):
    if not request.user.is_authenticated:
        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        # Making a GET request to the provided URL
        res = requests.get(f"https://edgesphere.szsciit.com/k8s/clusters/{clusterid}/v1/cnos.io.sshpublic", cookies=COOKIES, verify=False)
        
        # Return the content and status code
        return HttpResponse(res.content, status=res.status_code)
    except requests.RequestException as e:  # Catching specific requests exceptions
        return Response({"error": str(e)}, status=500)