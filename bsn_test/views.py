from django.shortcuts import render
import requests
import json
from common import myecdsa256
from django.contrib import messages
from common.loggers import logger


def save(request):
	return render(request, "save.html")
	
def get(request):
	return render(request, "get.html")

def update(request):
	return render(request, "update.html")

def delete(request):
	return render(request, "delete.html")

def history(request):
	return render(request, "history.html")

def get_history(request):
	logger.info('\n -----------------进入get_history方法----------------->')

	if request.method == 'POST':
		# 用户唯一标识
		userCode = "reddate"
		# 应用唯一标识
		appCode = "CL1851016378620191011150518"
		# 链码Code
		chainCode = "cc_base"
		# 方法名称
		funcName = "getHistory"

		baseKey = request.POST.get('baseKey')
		if len(baseKey.strip()) == 0:
			return render(request, 'delete.html', {'hint': '唯一标识不能为空！'})
		
		logger.info('输入的baseKey：%s', baseKey)
		
		str = userCode + appCode + chainCode + funcName + baseKey
		logger.info('拼接待签名的字符串：%s', str)
		
		# 对字符串 A使用户证书的私钥进行 使用户证书的私钥进行 使用户证书的私钥进行 SHA256WITHECDSA签名
		mac = myecdsa256.ecdsa_sign(str, './certificate/private_key.pem').decode()
		logger.info('base64格式mac值：%s', mac)
		
		url = 'https://quanzhounode.bsngate.com:17602/api/node/reqChainCode'
		headers = {'content-type': 'application/json'}
		
		datas = {"header": {"userCode": userCode, "appCode": appCode, "tId": "dc1d6010b7ff421dae0146f193dded09"},
				 "body": {"chainCode": chainCode, "funcName": funcName, "args": [baseKey]},
				 "mac": mac}
		
		logger.info("delete_data传参：%s", datas)
		
		try:
			r = requests.post(url, headers=headers, json=datas, verify='./certificate/bsn_https.pem')
			
			if r.status_code == 200:
				result = r.json()
				logger.info("get_history返回报文：%s", result)
				
				# 对返回报文中的mac值，使用网关的公钥证书进行验签，待签名的字符串与传参时待签名字符串一致
				result_mac = result['mac']
				logger.info("返回报文的result_mac：%s", result_mac)
				# 调用ecdsa_verify方法，进行验签
				verify_results = myecdsa256.ecdsa_verify(str, result_mac, './certificate/gateway_public_cert.pem')
				logger.info("验签结果：%s", verify_results)
				
				# 判断验签结果是否为True
				if verify_results is True:
					if result['header']['code'] == 0:
						txId = result['body']['blockInfo']['txId']
						logger.info('链上返回的txId为：%s', txId)
						messages.success(request, result['header']['msg'])
						return render(request, 'delete.html', {'baseKey': baseKey, 'txId': txId})
					else:
						messages.success(request, result['header']['msg'])
						return render(request, 'delete.html', {'baseKey': baseKey})
				else:
					logger.error("验证返回报文签名失败，verify_results：%s", verify_results)
					messages.error(request, '验证返回报文签名失败')
					return render(request, 'delete.html', {'baseKey': baseKey})
				
			else:
				logger.error("请求响应码,status_code：%s", r.status_code)
				messages.error(request, '请求响应码不正确')
				return render(request, 'delete.html', {'baseKey': baseKey})
		
		except Exception as e:
			logger.error('请求异常：%s', e)
			messages.error(request, '请求异常')
			return render(request, 'delete.html', {'baseKey': baseKey})
	else:
		return render(request, 'delete.html')

def save_data(request):
	
	logger.info('\n -----------------进入save_data方法----------------->')
	
	if request.method == 'POST':
		# 用户唯一标识
		userCode = "reddate"
		# 应用唯一标识
		appCode = "CL1851016378620191011150518"
		# 链码Code
		chainCode = "cc_base"
		# 方法名称
		funcName = "set"
		
		# 获取用户输入的baseKey（唯一标识）和baseInfo（保存内容）
		baseKey = request.POST.get('baseKey')
		baseInfo = request.POST.get('baseInfo')
		
		# 判断baseKey（唯一标识）和baseInfo（保存内容）不可为空
		if len(baseKey.strip()) == 0:
			return render(request, 'save.html', {'hint': '唯一标识不能为空！'})
		elif len(baseInfo.strip()) == 0:
			return render(request, 'save.html', {'hint1': '保存内容不能为空！'})
		
		logger.info('用户输入baseKey：%s', baseKey)
		logger.info('用户输入baseInfo：%s', baseInfo)
		
		# 拼接用户输入的baseKey（唯一标识）和baseInfo（保存内容）
		list = {"baseKey": baseKey, "baseValue": baseInfo}
		list = json.dumps(list)
		
		# 请求url与headers
		url = 'https://quanzhounode.bsngate.com:17602/api/node/reqChainCode'
		headers = {'content-type': 'application/json'}
		
		# 拼接待签名的字符串
		str = userCode + appCode + chainCode + funcName + list
		logger.info('拼接待签名的字符串：%s', str)
		
		# 对字符串 使用用户私钥证书进行 SHA256WITHECDSA 签名，调用ecdsa_sign方法生成base64格式mac值
		mac = myecdsa256.ecdsa_sign(str, './certificate/private_key.pem').decode()
		logger.info('base64格式mac值：%s', mac)
		
		# 请求传参
		datas = {"header": {"userCode": userCode, "appCode": appCode, "tId": "dc1d6010b7ff421dae0146f193dded09"},
				 "body": {"chainCode": chainCode, "funcName": funcName, "args": [list]},
				 "mac": mac}
		logger.info('save_data请求传参：%s', datas)
		
		try:
			# 发起请求,附加HTTPS证书
			r = requests.post(url, headers=headers, json=datas, verify='./certificate/bsn_https.pem')
			
			# 判断请求响应码是否正确
			if r.status_code == 200:
				result = r.json()
				logger.info("save_data返回报文：%s", result)
				
				# 对返回报文中的mac值，使用网关的公钥证书进行验签，待签名的字符串与传参时待签名字符串一致
				result_mac = result['mac']
				logger.info("返回报文的result_mac：%s", result_mac)
				# 调用ecdsa_verify方法，进行验签
				verify_results = myecdsa256.ecdsa_verify(str, result_mac, './certificate/gateway_public_cert.pem')
				logger.info("验签结果：%s", verify_results)
				
				# 判断验签结果是否为True
				if verify_results is True:
					if result['header']['code'] == 0:
						messages.success(request, result['header']['msg'])
						txId = result['body']['blockInfo']['txId']
						logger.info('链上返回的txId为：%s', txId)
						return render(request, 'save.html', {'baseKey': baseKey, 'baseInfo': baseInfo, 'txId': txId})
					else:
						messages.success(request, result['header']['msg'])
						return render(request, 'save.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
				else:
					logger.error("验证返回报文签名失败，verify_results：%s", verify_results)
					messages.success(request, '验证返回报文签名失败')
					return render(request, 'save.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
			else:
				logger.error("请求响应码,status_code：%s", r.status_code)
				messages.success(request, '请求响应码不正确')
				return render(request, 'save.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
			
		except Exception as e:
			logger.error('请求异常：%s', e)
			messages.error(request, '请求异常')
			return render(request, 'save.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
		
	else:
		return render(request, 'save.html')


def get_data(request):
	
	logger.info('\n ####################进入get_data方法####################')
	
	if request.method == 'POST':
		userCode = "reddate"
		appCode = "CL1851016378620191011150518"
		chainCode = "cc_base"
		funcName = "get"
		
		baseKey = request.POST.get('baseKey')
		if len(baseKey.strip()) == 0:
			return render(request, 'get.html', {'hint': '唯一标识不能为空！'})
		
		logger.info('输入的baseKey：%s', baseKey)
		
		str = userCode + appCode + chainCode + funcName + baseKey
		logger.info('拼接待签名的字符串：%s', str)
		
		# 对字符串 A使用户证书的私钥进行 使用户证书的私钥进行 使用户证书的私钥进行 SHA256WITHECDSA签名
		mac = myecdsa256.ecdsa_sign(str, './certificate/private_key.pem').decode()
		logger.info('base64格式mac值：%s', mac)

		url = 'https://quanzhounode.bsngate.com:17602/api/node/reqChainCode'
		headers = {'content-type': 'application/json'}
		
		datas = {"header": {"userCode": userCode, "appCode": appCode, "tId": "dc1d6010b7ff421dae0146f193dded09"},
				 "body": {"chainCode": chainCode, "funcName": funcName, "args": [baseKey]},
				 "mac": mac}
		
		logger.info('get_data请求传参：%s', datas)
		
		try:
			r = requests.post(url, headers=headers, json=datas, verify='./certificate/bsn_https.pem')

			if r.status_code == 200:
				result = r.json()
				logger.info('get_data返回报文：%s', result)
				
				# 对返回报文中的mac值，使用网关的公钥证书进行验签，待签名的字符串与传参时待签名字符串一致
				result_mac = result['mac']
				logger.info("返回报文的result_mac：%s", result_mac)
				# 调用ecdsa_verify方法，进行验签
				verify_results = myecdsa256.ecdsa_verify(str, result_mac, './certificate/gateway_public_cert.pem')
				logger.info("验签结果：%s", verify_results)
				
				# 判断验签结果是否为True
				if verify_results is True:
					if result['header']['code'] == 0:
						baseInfo = result['body']['ccRes']['ccData']
						txId = result['body']['blockInfo']['txId']
						logger.info('baseKey: %s 查询结果为:%s', baseKey, baseInfo)
						logger.info('链上返回的txId为：%s', txId)
						messages.success(request, result['header']['msg'])
						return render(request, 'get.html', {'baseKey': baseKey, 'baseInfo': baseInfo, 'txId': txId})
					else:
						logger.error('查询结果code不为0：' + result['header']['msg'])
						messages.error(request, result['header']['msg'])
						return render(request, 'get.html', {'baseKey': baseKey})
					
				else:
					logger.error("验证返回报文签名失败，verify_results：%s", verify_results)
					messages.success(request, '验证返回报文签名失败')
					return render(request, 'get.html', {'baseKey': baseKey})
				
			else:
				logger.error("请求响应码,status_code：%s", r.status_code)
				messages.success(request, '请求响应码不正确')
				return render(request, 'get.html', {'baseKey': baseKey})
			
		except Exception as e:
			logger.error('请求异常：%s', e)
			messages.error(request, '请求异常')
			return render(request, 'get.html', {'baseKey': baseKey})
		
	else:
		return render(request, 'get.html')
		
		
def update_data(request):
	
	logger.info('\n >>>>>>>>>>>>>>>>>>>>>进入update_data方法>>>>>>>>>>>>>>>>>>>>>')
	
	if request.method == 'POST':
		userCode = "reddate"
		appCode = "CL1851016378620191011150518"
		chainCode = "cc_base"
		funcName = "update"
		
		baseKey = request.POST.get('baseKey')
		baseInfo = request.POST.get('baseInfo')
		
		if len(baseKey.strip()) == 0:
			return render(request, 'update.html', {'hint': '唯一标识不能为空！'})
		elif len(baseInfo.strip()) == 0:
			return render(request, 'update.html', {'hint1': '修改内容不能为空！'})
		
		logger.info('用户输入baseKey：%s', baseKey)
		logger.info('用户输入baseInfo：%s', baseInfo)
		
		list = {"baseKey": baseKey, "baseValue": baseInfo}
		list = json.dumps(list)
		
		str = userCode + appCode + chainCode + funcName + list
		logger.info('拼接待签名的字符串：%s', str)
		
		# 对字符串 A使用户证书的私钥进行 使用户证书的私钥进行 使用户证书的私钥进行 SHA256WITHECDSA签名
		mac = myecdsa256.ecdsa_sign(str, './certificate/private_key.pem').decode()
		logger.info('base64格式mac值：%s', mac)
		
		url = 'https://quanzhounode.bsngate.com:17602/api/node/reqChainCode'
		headers = {'content-type': 'application/json'}
		
		datas = {"header": {"userCode": userCode, "appCode": appCode, "tId": "dc1d6010b7ff421dae0146f193dded09"},
				 "body": {"chainCode": chainCode, "funcName": funcName, "args": [list]},
				 "mac": mac}
		
		logger.info('update_data请求传参：%s', datas)
		
		try:
			r = requests.post(url, headers=headers, json=datas, verify='./certificate/bsn_https.pem')
			
			if r.status_code == 200:
				result = r.json()
				logger.info('update_data返回报文：%s', result)
				
				# 对返回报文中的mac值，使用网关的公钥证书进行验签，待签名的字符串与传参时待签名字符串一致
				result_mac = result['mac']
				logger.info("返回报文的result_mac：%s", result_mac)
				# 调用ecdsa_verify方法，进行验签
				verify_results = myecdsa256.ecdsa_verify(str, result_mac, './certificate/gateway_public_cert.pem')
				logger.info("验签结果：%s", verify_results)
				
				# 判断验签结果是否为True
				if verify_results is True:
					if result['header']['code'] == 0:
						txId = result['body']['blockInfo']['txId']
						logger.info('链上返回的txId为：%s', txId)
						messages.success(request, result['header']['msg'])
						return render(request, 'update.html', {'baseKey': baseKey, 'baseInfo': baseInfo, 'txId': txId})
					else:
						messages.success(request, result['header']['msg'])
						return render(request, 'update.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
				else:
					logger.error("验证返回报文签名失败，verify_results：%s", verify_results)
					messages.error(request, '验签失败')
					return render(request, 'update.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
			else:
				logger.error("请求响应码,status_code：%s", r.status_code)
				messages.error(request, '请求响应码不正确')
				return render(request, 'update.html', {'baseKey': baseKey})
		
		except Exception as e:
			logger.error('请求异常：%s', e)
			messages.error(request, '请求异常')
			return render(request, 'update.html', {'baseKey': baseKey, 'baseInfo': baseInfo})
	else:
		return render(request, 'update.html')
	

def delete_data(request):
	
	logger.info('\n *******************进入delete_data方法*******************')
	
	if request.method == 'POST':
		userCode = "reddate"
		appCode = "CL1851016378620191011150518"
		chainCode = "cc_base"
		funcName = "delete"
		
		baseKey = request.POST.get('baseKey')
		if len(baseKey.strip()) == 0:
			return render(request, 'delete.html', {'hint': '唯一标识不能为空！'})
		
		logger.info('输入的baseKey：%s', baseKey)
		
		str = userCode + appCode + chainCode + funcName + baseKey
		logger.info('拼接待签名的字符串：%s', str)
		
		# 对字符串 A使用户证书的私钥进行 使用户证书的私钥进行 使用户证书的私钥进行 SHA256WITHECDSA签名
		mac = myecdsa256.ecdsa_sign(str, './certificate/private_key.pem').decode()
		logger.info('base64格式mac值：%s', mac)
		
		url = 'https://quanzhounode.bsngate.com:17602/api/node/reqChainCode'
		headers = {'content-type': 'application/json'}
		
		datas = {"header": {"userCode": userCode, "appCode": appCode, "tId": "dc1d6010b7ff421dae0146f193dded09"},
				 "body": {"chainCode": chainCode, "funcName": funcName, "args": [baseKey]},
				 "mac": mac}
		
		logger.info("delete_data传参：%s", datas)
		
		try:
			r = requests.post(url, headers=headers, json=datas, verify='./certificate/bsn_https.pem')
			
			if r.status_code == 200:
				result = r.json()
				logger.info("delete_data返回报文：%s", result)
				
				# 对返回报文中的mac值，使用网关的公钥证书进行验签，待签名的字符串与传参时待签名字符串一致
				result_mac = result['mac']
				logger.info("返回报文的result_mac：%s", result_mac)
				# 调用ecdsa_verify方法，进行验签
				verify_results = myecdsa256.ecdsa_verify(str, result_mac, './certificate/gateway_public_cert.pem')
				logger.info("验签结果：%s", verify_results)
				
				# 判断验签结果是否为True
				if verify_results is True:
					if result['header']['code'] == 0:
						txId = result['body']['blockInfo']['txId']
						logger.info('链上返回的txId为：%s', txId)
						messages.success(request, result['header']['msg'])
						return render(request, 'delete.html', {'baseKey': baseKey, 'txId': txId})
					else:
						messages.success(request, result['header']['msg'])
						return render(request, 'delete.html', {'baseKey': baseKey})
				else:
					logger.error("验证返回报文签名失败，verify_results：%s", verify_results)
					messages.error(request, '验证返回报文签名失败')
					return render(request, 'delete.html', {'baseKey': baseKey})
				
			else:
				logger.error("请求响应码,status_code：%s", r.status_code)
				messages.error(request, '请求响应码不正确')
				return render(request, 'delete.html', {'baseKey': baseKey})
		
		except Exception as e:
			logger.error('请求异常：%s', e)
			messages.error(request, '请求异常')
			return render(request, 'delete.html', {'baseKey': baseKey})
	else:
		return render(request, 'delete.html')