'''
IMPORTANT:

This is the hard-coded version for internal tests only. Please delete the return statements and 
use the commented out code for the future use.

The COOKIES IS FOR TEST JUST ONLY

'''
COOKIES = {'R_SESS':'token-test01:62fwdpv2npks9vb4qbcjstzkrl98m6zc68tqrdmdkrdr4hjmtf98fz'}# DELETE THIS IN PRODUCTION USE

import requests
from django.http import JsonResponse, HttpResponse
from rest_framework import generics
from rest_framework.response import Response
from .models import *
from .serializers import *
from rest_framework.views import APIView
from rest_framework import status

from django.contrib.auth import login, logout
from rest_framework.permissions import IsAuthenticated

from django.http import FileResponse
from django.shortcuts import get_object_or_404

###################################   Cluster API   #####################################
def getAllCluster(request):
    try:
        res = requests.get('https://edgesphere.szsciit.com/v1/management.cattle.io.clusters',cookies=COOKIES,headers={}, verify=False)
        if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)


def GetClusterByName(requrest,cluster_id):
    try:
        res = requests.get(f"https://edgesphere.szsciit.com/v1/management.cattle.io.clusters/{cluster_id}",cookies=COOKIES,headers={}, verify=False)
        if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

###################################   VM API    #####################################
def VMGet(request,cluster_id, vm_name, vm_namespace):
    json = {'clusterid':cluster_id,'vmName':vm_name,'namespace':vm_namespace}
    try:
        res = requests.post(f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine/{vm_namespace}/{vm_name}",cookies=COOKIES,json = json, verify=False)
        if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)



def VMCreate(request,cluster_id):
    metadata = request.POST['metadata']
    spec = request.POST['spec']
    status = request.POST['status']
    json = {'metadata':metadata,'spec':spec,'status':status}
    try:
        res = requests.post(f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine",cookies=COOKIES,json = json, verify=False)
        if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)


def VMUpdate(request, cluster_id):
    cluster_id = request.POST['cluster_id']
    action = request.POST['action']
    json = {'cluster_id':cluster_id, 'action':action}
    try:
        res = requests.post(f"https://edgesphere.szsciit.com/k8s/clusters/{cluster_id}/v1/kubevirt.io.virtualmachine/default/vmName?action={action}",cookies=COOKIES,json = json, verify=False)
        if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

    
def VMTerminate(request,cluster_id,vm_name,vm_namespace):
    json = {'clusterid':cluster_id,'vmName':vm_name,'namespace':vm_namespace}
    try:
        res = requests.post(f"wss://edgesphere.szsciit.com/wsproxy/k8s/clusters/{cluster_id} /apis/subresources.kubevirt.io/v1/namespaces/{vm_namespace}/virtualmachineinstances/{vm_name}/vnc",cookies=COOKIES,json = json, verify=False)
        if res.headers.get('content-type') == 'application/json':
                return JsonResponse(res.json())
        return HttpResponse(res.content, status=res.status_code)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

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
class InventoryAPI(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        inventories = Inventory.objects.filter(user=user)
        serializer = InventorySerializer(inventories, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = InventorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DownloadSSHCertView(APIView):
    def get(self, request, inventory_id):
        inventory = get_object_or_404(Inventory, pk=inventory_id)
        ssh_cert = inventory.ssh_cert
        if ssh_cert:
            response = FileResponse(ssh_cert, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{inventory.inventory_name}.cert"'
            return response
        else:
            return Response({'message': 'SSH certificate not found'}, status=status.HTTP_404_NOT_FOUND)