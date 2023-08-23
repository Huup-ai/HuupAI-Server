'''
IMPORTANT:

This is the hard-coded version for internal tests only. Please delete the return statements and 
use the commented out code for the future use.

'''
from rest_framework import generics
from rest_framework.response import Response
from .models import *
from .serializers import *
from rest_framework.views import APIView
from rest_framework import status

from django.contrib.auth import login, logout
from rest_framework.permissions import IsAuthenticated

###################################   Cluster API   #####################################
class GetAllCluster(generics.ListAPIView):
    def list(self, request, *args, **kwargs):
        queryset = Cluster.objects.all()
        serializer = ClusterSerializer(queryset, many=True)
        # return Response(serializer.data)
        return Response({'Clusters':['us-ca-t4-c1','us-ca-t3-c2','us-wa-t4-c2']})

class GetClusterByName(generics.RetrieveAPIView):
    def get(self, requrest, *args,**kwargs):
    #     queryset = Cluster.objects.get(name = name_arg)
    #     serializer = ClusterSerializer(queryset)
    #     return Response(serializer.data)
        return Response({'name':kwargs['name'],'hour_rate':0.01,'gpu':'1','configuration':'xxx','region':'us-east-2','privacy':'xxx'})

class GetClusterStat(APIView):
    def get(self, request, name):
        # try:
        #     cluster = Cluster.objects.get(name=name)
        #     serializer = ClusterSerializer(cluster)
        #     return Response(serializer.data)
        return Response({'name':f'{name}','status':'running'})
        # except Cluster.DoesNotExist:
        #     return Response(status=status.HTTP_404_NOT_FOUND)

###################################   VM API    #####################################

class VMAPI(APIView):
    def get(self, request):
        # vms = VirtualMachine.objects.all()
        # serializer = VirtualMachineSerializer(vms, many=True)
        return Response({'VM_list':['vm1','vm2','vm2333']})
        #return Response(serializer.data)

    def post(self, request):
        serializer = VirtualMachineSerializer(data=request.data)
        if serializer.is_valid():
        #     serializer.save()
            return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VMControlAPI(APIView):
    def put(self, request, cluster_name, vm_name):
        # try:
        #     vm = VirtualMachine.objects.get(cluster__name=cluster_name, name=vm_name)
        #     serializer = VirtualMachineSerializer(vm, data=request.data)
        #     if serializer.is_valid():
        #         serializer.save()
        #         return Response(serializer.data)
        #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # except VirtualMachine.DoesNotExist:
        #     return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(f'{vm_name} has been successfully updated')

    def delete(self, request, cluster_name, vm_name):
        # try:
        #     vm = VirtualMachine.objects.get(cluster__name=cluster_name, name=vm_name)
        #     vm.delete()
        #     return Response(status=status.HTTP_204_NO_CONTENT)
        # except VirtualMachine.DoesNotExist:
        #     return Response(status=status.HTTP_404_NOT_FOUND)
        return Response('f{vm_name} has been successfully deleted')
    
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
        username = request.data.get('username')
        password = request.data.get('password')
        user = User.objects.filter(username=username).first()

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

