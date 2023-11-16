from ..models import *
from ..serializers import *
from datetime import timedelta
from django.utils import timezone
import requests
from django.core.exceptions import ObjectDoesNotExist

import requests
import json
from django.http import JsonResponse, HttpResponse

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.cvm.v20170312 import cvm_client, models

def get_external_api_token(user):
    try:
        url = "https://edgesphereszsciit.com/v3-public/localProviders/local?action=login"
        payload = {
            "username": user.email, # Assuming username is the email of the user
            "password": user.password, # You should store passwords securely (hashed) and not in plain text
        }
        # send the POST request
        response = requests.post(url, json=payload)

        if response.status_code == 200:
            # extract the token
            cookies = response.headers.get('Set-Cookie')
            if cookies:
                token = cookies.split(';')[0].split('=')[1]
                return token
        else:
            raise Exception
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def start_instance(user, spec, cluster_id):
    unique_data = {
        'user_id': user,
        'vm_name': spec.get("name"),
        'vm_namespace': spec.get("namespace"),
        'payment_method':spec.get("payment_method")
    }
    try:
        # Find the price from the Pricing table using the cluster_id
        pricing_obj = Pricing.objects.get(cluster_id=cluster_id)
        price = pricing_obj.price
    except ObjectDoesNotExist:
        price=1.0
        print(f"No pricing information found for cluster_id: {cluster_id}, using defualt value 1")
        # return False

    # Default values for creation
    defaults = {
        'status': "started",
        'start_time': timezone.now(),
        'cluster': cluster_id,
        'usage': 0.0,
        'price': price,
        }
    # Merging two dictionaries
    data = {**unique_data, **defaults}

    # Creating an instance with the merged data
    instance = Instance.objects.create(**data)

    return instance


def update_instance(instance, action):
    if instance.status!='terminated':
        instance.status = action
        stop_time = timezone.now()
        instance.usage += (stop_time - instance.start_time).total_seconds() / 3600 # Convert seconds to mins
        if action == 'terminated':
            instance.stop_time = stop_time
        else:
            instance.start_time = timezone.now()
        instance.save()



#创建实例

def create_and_start_cvm(key_pair_name):
    cred = credential.Credential("IKIDnY7XlkW3PYUEk260g7JH2lOo24taAXfZ", "jGdmhNuPkqiLwKUP5XmocCXdZIn6CJGy")
    try:
    # 配置腾讯云认证信息
    # 实例化一个http选项，可选的，没有特殊需求可以跳过
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.na-ashburn.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cvm_client.CvmClient(cred, "na-ashburn", clientProfile)
        #这里的"na-ashburn"是 弗吉尼亚 （美东server）

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.RunInstancesRequest()
        params = {
            "InstanceChargeType": "POSTPAID_BY_HOUR",
            "DisableApiTermination": False,
            "Placement": {
                "Zone": "na-ashburn-1",
                "ProjectId": 0
            },#这里的"na-ashburn"是 弗吉尼亚 （美东server）
            "VirtualPrivateCloud": {
                "AsVpcGateway": False,
                "VpcId": "DEFAULT",
                "SubnetId": "DEFAULT"
            },
            "InstanceType": "S2.MEDIUM2",
            "ImageId": "img-eb30mz89",
            "SystemDisk": {
                "DiskSize": 50,
                "DiskType": "CLOUD_BSSD"
            },
            "InternetAccessible": {
                "InternetMaxBandwidthOut": 5,
                "PublicIpAssigned": True,
                "InternetChargeType": "TRAFFIC_POSTPAID_BY_HOUR"
            },
            "LoginSettings": {
                "KeyIds": [ key_pair_name ]
            },
            "InstanceCount": 1,
            "EnhancedService": {
                "SecurityService": {
                    "Enabled": True
                },
                "MonitorService": {
                    "Enabled": True
                },
                "AutomationService": {
                    "Enabled": False
                }
            }
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个RunInstancesResponse的实例，与请求对象对应
        resp = client.RunInstances(req)
        # 输出json格式的字符串回包
        return JsonResponse({'status': 'success','message':resp.to_json_string()}, status=200)
    except TencentCloudSDKException as err:
        return JsonResponse({"error": str(err)})

#查看实例列表

def get_cvm(InstanceID = None,InstanceName = None): 
    try:
        # 实例化一个认证对象，入参需要传入腾讯云账户 SecretId 和 SecretKey，此处还需注意密钥对的保密
        # 代码泄露可能会导致 SecretId 和 SecretKey 泄露，并威胁账号下所有资源的安全性。密钥可前往官网控制台 https://console.tencentcloud.com/capi 进行获取
        cred = credential.Credential("IKIDnY7XlkW3PYUEk260g7JH2lOo24taAXfZ", "jGdmhNuPkqiLwKUP5XmocCXdZIn6CJGy")
        # 实例化一个http选项，可选的，没有特殊需求可以跳过
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cvm_client.CvmClient(cred, "na-ashburn", clientProfile)

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.DescribeInstancesRequest()
        if InstanceID:
            params = {
                "InstanceIds": [
                    InstanceID
                ]
        }
        elif InstanceName:
            params = {
                "InstanceName": InstanceName
        }
        else:
            params = {}
        
        """
            "InstanceIds": [
                
            ],
            "Filters": [
                {
                    "Name": None,
                    "Values": [
                        None
                    ]   
                }
            ],
            "Offset": None,
            "Limit": None
        """
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个DescribeInstancesResponse的实例，与请求对象对应
        resp = client.DescribeInstances(req)
        # 输出json格式的字符串回包
        return JsonResponse({'status': 'success','message':resp.to_json_string()}, status=200)
    except TencentCloudSDKException as err:
        return JsonResponse({"error": str(err)})

#更新实例
#可能目前用不太到
def update_cvm(InstanceID = None, InstanceName = None):
    try:
        # 实例化一个认证对象，入参需要传入腾讯云账户 SecretId 和 SecretKey，此处还需注意密钥对的保密
        # 代码泄露可能会导致 SecretId 和 SecretKey 泄露，并威胁账号下所有资源的安全性。密钥可前往官网控制台 https://console.tencentcloud.com/capi 进行获取
        cred = credential.Credential("SecretId", "SecretKey")
        # 实例化一个http选项，可选的，没有特殊需求可以跳过
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cvm_client.CvmClient(cred, "na-ashburn", clientProfile)

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.ModifyInstancesAttributeRequest()
        params = {
            "InstanceIds": [
                None
            ],
            "InstanceName": None,
            "SecurityGroups": [
                None
            ],
            "CamRoleName": None,
            "HostName": None,
            "DisableApiTermination": None,
            "CamRoleType": None
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个ModifyInstancesAttributeResponse的实例，与请求对象对应
        resp = client.ModifyInstancesAttribute(req)
        # 输出json格式的字符串回包
        return JsonResponse({'status': 'success','message':resp.to_json_string()}, status=200)

    except TencentCloudSDKException as err:
        return JsonResponse({"error": str(err)})

#关闭实例
def stop_cvm(InstanceID):
    # 配置腾讯云认证信息
    try:
        # 实例化一个认证对象，入参需要传入腾讯云账户 SecretId 和 SecretKey，此处还需注意密钥对的保密
        # 代码泄露可能会导致 SecretId 和 SecretKey 泄露，并威胁账号下所有资源的安全性。密钥可前往官网控制台 https://console.tencentcloud.com/capi 进行获取
        cred = credential.Credential("IKIDnY7XlkW3PYUEk260g7JH2lOo24taAXfZ", "jGdmhNuPkqiLwKUP5XmocCXdZIn6CJGy")
        # 实例化一个http选项，可选的，没有特殊需求可以跳过
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cvm_client.CvmClient(cred, "na-ashburn", clientProfile)

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.StopInstancesRequest()
        params = {
            "InstanceIds": [
                InstanceID
            ],
            "ForceStop": True,
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个StopInstancesResponse的实例，与请求对象对应
        resp = client.StopInstances(req)
        # 输出json格式的字符串回包
        return JsonResponse({'status': 'success','message':resp.to_json_string()}, status=200)

    except TencentCloudSDKException as err:
        return JsonResponse({"error": str(err)})
    

#启动实例
def start_cvm(InstanceID):
    try:
        # 实例化一个认证对象，入参需要传入腾讯云账户 SecretId 和 SecretKey，此处还需注意密钥对的保密
        # 代码泄露可能会导致 SecretId 和 SecretKey 泄露，并威胁账号下所有资源的安全性。密钥可前往官网控制台 https://console.tencentcloud.com/capi 进行获取
        cred = credential.Credential("IKIDnY7XlkW3PYUEk260g7JH2lOo24taAXfZ", "jGdmhNuPkqiLwKUP5XmocCXdZIn6CJGy")
        # 实例化一个http选项，可选的，没有特殊需求可以跳过
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cvm_client.CvmClient(cred, "na-ashburn", clientProfile)

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.StartInstancesRequest()
        params = {
            "InstanceIds": [
                InstanceID
            ]
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个StartInstancesResponse的实例，与请求对象对应
        resp = client.StartInstances(req)
        # 输出json格式的字符串回包
        return JsonResponse({'status': 'success','message':resp.to_json_string()}, status=200)

    except TencentCloudSDKException as err:
        return JsonResponse({"error": str(err)})

#删除、退还实例
def delete_cvm(InstanceID):
    try:
        # 实例化一个认证对象，入参需要传入腾讯云账户 SecretId 和 SecretKey，此处还需注意密钥对的保密
        # 代码泄露可能会导致 SecretId 和 SecretKey 泄露，并威胁账号下所有资源的安全性。密钥可前往官网控制台 https://console.tencentcloud.com/capi 进行获取
        cred = credential.Credential("IKIDnY7XlkW3PYUEk260g7JH2lOo24taAXfZ", "jGdmhNuPkqiLwKUP5XmocCXdZIn6CJGy")
        # 实例化一个http选项，可选的，没有特殊需求可以跳过
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cvm.tencentcloudapi.com"

        # 实例化一个client选项，可选的，没有特殊需求可以跳过
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        # 实例化要请求产品的client对象,clientProfile是可选的
        client = cvm_client.CvmClient(cred, "na-ashburn", clientProfile)

        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.TerminateInstancesRequest()
        params = {
            "InstanceIds": [
                InstanceID
            ],
            #"ReleasePrepaidDataDisks": null
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个TerminateInstancesResponse的实例，与请求对象对应
        resp = client.TerminateInstances(req)
        # 输出json格式的字符串回包
        return JsonResponse({'status': 'success','message':resp.to_json_string()}, status=200)
    except TencentCloudSDKException as err:
        return JsonResponse({"error": str(err)})