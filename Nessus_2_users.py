#encoding:utf-8

__author__  = 'Cichar'
__git__     = ''
__version__ = '0.1'

import requests
import json
import requests.packages
import time
from collections import OrderedDict
import csv
import logging
requests.packages.urllib3.disable_warnings()


def retry(func):
	'''装饰器
    如果捕获异常则重试，最多4次'''
	RETRIES = 0
	count = {"num": RETRIES}
	def wrapped(*args, **kwargs):
		try:
			return func(*args, **kwargs)
		except Exception as err:
			if count['num'] < 4:
				count['num'] += 1
				return wrapped(*args, **kwargs)
			else:
				raise Exception(err)
	return wrapped

class Nessus_api:
	def __init__(self, url, username, password):
		self.url = 'https://'+ url + ':8834'
		self.username = username
		self.password = password
		self.verify = False
		self.token = ''
		self.scanDictScan2uuid = ''
		self.scanDictId2Scan = OrderedDict([('1','Advanced Scan'),
		                                   ('2','Malware Scan'),
		                                   ('3','Audit Cloud Infrastructure'),
		                                   ('4','DROWN Detection'),
		                                    ('5','Web Application Tests'),
		                                   ('6','Offline Config Audit'),
		                                    ('7','Host Discovery'),
		                                    ('8','SCAP and OVAL Auditing'),
		                                    ('9','Credentialed Patch Audit'),
		                                    ('10','Mobile Device Scan'),
		                                    ('11','Internal PCI Network Scan'),
		                                    ('12','Bash Shellshock Detection'),
		                                    ('13','GHOST (glibc) Detection'),
		                                    ('14','Policy Compliance Auditing'),
		                                    ('15','Basic Network Scan'),
		                                    ('16','PCI Quarterly External Scan'),
		                                    ('17','MDM Config Audit'),
		                                    ('18','Badlock Detection')])

	def _build_url(self, path_url):
		'''构建要访问的url'''
		return '%s%s' % (self.url, path_url)

	def _connect(self, method, path_url, data = None):
		'''接收post,get等方法'''
		try:
			header = {'X-Cookie':'token=%s' % self.token,
				'Connection':'keep-alive',
				'Content-Type':'application/json'}
			if method == 'POST':
				r = requests.post(self._build_url(path_url), data=data, headers=header, verify=self.verify,timeout = 5)
			elif method == 'GET':
				r = requests.get(self._build_url(path_url), data=data, headers=header, verify=self.verify,timeout = 5)
			elif method == 'PUT':
				r = requests.put(self._build_url(path_url), data=data, headers=header, verify=self.verify,timeout = 5)
			elif method == 'DELETE':
				r = requests.delete(self._build_url(path_url), data=data, headers=header, verify=self.verify,timeout = 5)
			if 'download' in path_url:
				return r.content
			try:
				return r.json()
			except ValueError:
				return r.content
		except Exception as e:
			pass

	@retry
	def login(self):
		'''登录nessus，输入用户名和密码'''
		login_data = {"username": self.username, "password": self.password}
		login_data = json.dumps(login_data) #dumps将python对象转换成json字符串
		try:
			#连接nessus服务器，获取token
			data = self._connect('POST', '/session', login_data)
			self.token = data['token']
			self._get_scans()
			#print(self.username + ' 登录成功..')
		except Exception as e:
			logging.error(e)

	#Request URL:https://ip:8834/editor/scan/templates
	def _get_scans(self):
		'''获取任务扫描方法(归纳为字典，title:uuid)'''
		data = self._connect('GET', '/editor/scan/templates')
		self.scanDictScan2uuid = dict((p['title'],p['uuid']) for p in data['templates'])

	def printscans(self):
		'''打印任务扫描方法'''
		for id in self.scanDictId2Scan:
			logging.info(id + ':' + self.scanDictId2Scan[id])

	#Request URL:https://ip:8834/scans
	@retry
	def add_scan(self, name = None, desc = None, target = None, scannum = None):
		'''添加扫描任务'''
		try:
			scan = {'settings':{'name': name,               #这里是名字
			                    'description': desc,        #这里是描述
			                    'text_targets': target,      #这里是目标
			                    'folder_id': '3',
			                    'scanner_id': '1',}}

			uuid = self.scanDictScan2uuid[self.scanDictId2Scan[str(scannum)]]
			scan['uuid'] = uuid
			add_scan_data = json.dumps(scan)
			data = self._connect('POST','/scans', data = add_scan_data)
			if data:
				logging.info(':任务创建成功，ID：'+str(data['scan']['id']))
			#return data
			scanId = str(data['scan']['id'])
			return scanId
		except Exception as e:
			logging.info('任务创建失败..')
			raise Exception(e)

	#Request URL:https://ip:8834/scans?folder_id=3
	@retry
	def getStatusAndId(self):
		'''获取id与status列表'''
		data = self._connect('GET', '/scans')
		#print(data)
		if data['scans'] != None:
			status_dict = dict((p['name'],p['status']) for p in data['scans'])
			id_dict = dict((p['name'],p['id']) for p in data['scans'])
			status_id_dict = {}
			for name in id_dict:
				status_id_dict[id_dict[name]] = status_dict[name]
			#logging.info(status_id_dict)
			return status_id_dict

	@retry
	def getRunscannum(self):
		'''获取正在运行的任务数量'''
		data = self._connect('GET', '/scans')
		#print(data)
		if data['scans'] != None:
			status_dict = list(p['status'] for p in data['scans'])
			#print(status_dict.count('running'))
			runscannum = status_dict.count('running')
			return runscannum
		else:
			#print('0')
			return 0


	def getscanstatus(self, scanId):
		'''获取单任务状态'''
		try:
			data = self._connect('GET', '/scans/%s' % scanId)
			status = data['history'][0]['status']
			return status
		except Exception as e:
			pass

	#Request URL:https://ip:8834/scans/scanId/launch
	@retry
	def launch(self,scanId):
		'''启动扫描任务
		通过getStatusAndId获取id与status'''
		data = self._connect('POST','/scans/%s/launch' % scanId)
		print('任务ID：%s 启动成功' % scanId)
		return data['scan_uuid']

	# Request URL:https://localhost:8834/scans/scanId/pause
	def pausescan(self, scanId):
		'''暂停扫描任务'''
		self._connect('POST', '/scans/%s/pause' % scanId)
		return

	#Ruqeust URL:https://ip:8834/scans/scanId/folder
	@retry
	def delscan(self, scanId):
		'''删除扫描任务'''
		data = self._connect('DELETE','/scans/%s' % scanId)
		if data == b'':
			logging.info('任务ID:%s 删除成功' % scanId)

	#Request URL :https://ip:8834/scans/scanId/export
	def _getResult(self, scanId, file_class):
		'''获取结果文件,并打印fileId'''
		if file_class == 'csv':
			data = {'format':file_class,
			        'chapters': "vuln_hosts_summary"}
		elif file_class == 'html':
			data = {'format': file_class,
			        'chapters': "vuln_by_host"}
		data = json.dumps(data)
		data = self._connect('POST', '/scans/%s/export' % scanId, data = data)
		fileId = data['file']
		status = self._getResultStatus(scanId, fileId)
		while status != 'ready':
			time.sleep(4)
		return status, fileId

	#Request URL :https://ip:8834/scans/scanId/export/fileId/status
	def _getResultStatus(self, scanId, fileId):
		'''获取结果文件状态'''
		data = self._connect('GET', '/scans/%s/export/%s/status' % (scanId, fileId))
		return data['status']

	#Request URL:https://ip:8834/scans/scanId/export/fileId/download
	def _downloadfile(self, scanId, fileId, file_class):
		'''下载任务文件'''
		data = (self._connect('GET', '/scans/%s/export/%s/download' % (scanId, fileId)))
		filename = 'Nessus_%s_%s.%s' % (scanId, fileId, file_class)
		with open('F:/pycharmProjects/PythonJob/Nessus/log/nessus/%s' % filename, 'wb') as f:
			f.write(data)
		return filename

	def download(self, scanId, file_class):
		'''根据输入的任务ID以及期望文件类型，下载目标文件'''
		result = self._getResult(scanId, file_class)
		fileId = result[1]
		self._downloadfile(scanId, fileId, file_class)
		logging.info('文件下载完成')

	def downloadAndClear2csv(self, scanId):
		'''清理文件，只留下漏洞名，漏洞描述，漏洞编号，漏洞细节，漏洞地址'''
		result = self._getResult(scanId, 'csv')
		fileId = result[1]
		oldfilename = self._downloadfile(scanId, fileId, 'csv')
		newfilename = 'cleared_'+oldfilename
		cols = [1, 2, 3, 5, 10, 11] #不需要的列数
		with open(oldfilename) as oldfile, open(newfilename, 'w') as newfile:
			reader = csv.reader(oldfile)
			writer = csv.writer(newfile)
			# for row in reader:
				# a = list(item for col, item in enumerate(row) if col not in cols)
				# writer.writerow(a)
			rows = (list(item for col, item in enumerate(row) if col not in cols) for row in reader)
			writer.writerows(rows)
		logging.info('文件写入完成')

	@retry
	def getclearResult(self, scanId):
		'''下载文件打印并返回清洗过的结果，只留下漏洞名、漏洞描述、漏洞编号、
			漏洞细节、漏洞地址、host、Plugin Output'''
		result = self._getResult(scanId, 'csv')
		fileId = result[1]
		filename = self._downloadfile(scanId, fileId, 'csv')
		list = []
		try:
			with open(filename, 'r') as f:
				fcsv = csv.DictReader(f)
				for dict in fcsv:
					newdict = {}
					for i in ['Plugin ID', 'Host', 'Port', 'Name', 'Synaoaoopsis', 'Description', 'Plugin Output']:
						newdict[i] = dict[i].replace('\n', '.')
					list.append(newdict)
				#print(list)
				return list
		except Exception as e:
			pass


class control:
	def __init__(self, userfilepath):
		self.userfilepath = userfilepath
		self.allconnect = {}
		self.allresult = []
		self.allstatus = {}
		self.scanlist = []

	def showscanmethod(self):
		scanmethod = OrderedDict([('1', 'Advanced Scan'),
		             ('2', 'Malware Scan'),
		             ('3', 'Audit Cloud Infrastructure'),
		             ('4', 'DROWN Detection'),
		             ('5', 'Web Application Tests'),
		             ('6', 'Offline Config Audit'),
		             ('7', 'Host Discovery'),
		             ('8', 'SCAP and OVAL Auditing'),
		             ('9', 'Credentialed Patch Audit'),
		             ('10', 'Mobile Device Scan'),
		             ('11', 'Internal PCI Network Scan'),
		             ('12', 'Bash Shellshock Detection'),
		             ('13', 'GHOST (glibc) Detection'),
		             ('14', 'Policy Compliance Auditing'),
		             ('15', 'Basic Network Scan'),
		             ('16', 'PCI Quarterly External Scan'),
		             ('17', 'MDM Config Audit'),
		             ('18', 'Badlock Detection')])
		for i in scanmethod:
			print(i + ':' + scanmethod[i])

	def login(self):
		'''批量连接nessus服务器'''
		# with open(self.userfilepath, 'r') as f:
		# 	for line in f.readlines():
		for i in self.userfilepath:
			# line: ip，username, password
			# user = list(line.strip().replace(' ', '').split(','))
			# ip, username, password = user[0], user[1], user[2]
			ip, username, password = i.get('services'), i.get('username'), i.get('password')
			p = Nessus_api(ip, username, password)
			#p.login()
			self.allconnect[username] = p
			#print(self.allconnect[ip].getRunscannum())

	def getmintaskIp(self):
		'''获取当前执行任务数最少的机器'''
		tasknum = 666
		mintaskIp = None
		for i in self.allconnect:
			taskconn = self.allconnect[i]
			taskconn.login()
			#print(taskconn.token)
			nowRunTaskNum = taskconn.getRunscannum()
			print(i + ' 目前的任务数量：' + str(nowRunTaskNum))
			if nowRunTaskNum < tasknum:
				tasknum = nowRunTaskNum
				mintaskIp = self.allconnect[i]
		return mintaskIp

	def addtask(self, scanfilepath = None):
		'''对当前执行任务数最少的机器发布任务'''
		# 将要增加的任务信息导入
		# scanlist = [[name1, desc1, target1, scannum1],[name2, desc2, target2, scannum2]....]
		if scanfilepath != None:
			try:
				with open(scanfilepath, 'r') as f:
					for line in f.readlines():
						tuple = list(line.strip().replace(' ', '').split(','))
						self.scanlist.append(tuple)
				for i in self.scanlist:
					logging.info(i)
					mintaskIp = self.getmintaskIp()
					scanId = mintaskIp.add_scan(i[0], i[1], i[2], i[3])
					mintaskIp.launch(scanId)
				logging.info('所有任务添加完毕..')
				return
			except AttributeError:
				print('各机任务已达上限...')
		else:
			while True:
				name = input('请输入任务名称：')
				desc = input('请输入任务描述：')
				target = input('请输入任务IP目标：')
				scannum = input('请输入方法编号：')
				scan = [name, desc ,target, scannum]
				self.scanlist.append(scan)
				if input('是否继续添加任务：(Y/N)') == 'Y':
					self.addtask()
				else:
					for i in self.scanlist:
						logging.info(i)
						#print(i)
						mintaskIp = self.getmintaskIp()
						scanId = mintaskIp.add_scan(i[0], i[1], i[2], i[3])
						mintaskIp.launch(scanId)
					exit()

	def getalldata(self):
		'''获取已经完成的任务的任务结果'''
		for i in self.allconnect:
			taskconn = self.allconnect[i]
			taskconn.login()
			scanStatusDict = taskconn.getStatusAndId()
			for scanId in scanStatusDict:
				if scanStatusDict[scanId] == 'completed':
					self.allresult.append(self.allconnect[i].getclearResult(scanId))
		print(self.allresult)
		return self.allresult

	def getallstatus(self):
		'''获取所有机器的任务情况'''
		for i in self.allconnect:
			taskconn = self.allconnect[i]
			taskconn.login()
			scanStatusDict = taskconn.getStatusAndId()
			self.allstatus[i] = scanStatusDict
		print(self.allstatus)

	def delallscan(self):
		'''删除所有机器上的任务'''
		for i in self.allconnect:
			taskconn = self.allconnect[i]
			taskconn.login()
			scanStatusDict = taskconn.getStatusAndId()
			print(scanStatusDict)
			if scanStatusDict != None:
				for scanId in scanStatusDict:
					taskconn.delscan(scanId)
		logging.info('删除完毕')

if __name__ == '__main__':
	nessconfig = [{'services':'127.0.0.1','username':'Cichar','password':''},
	              {'services':'127.0.0.1','username':'','password':''},
	              {'services': '127.0.0.1', 'username': '', 'password': ''}]
	p = control(nessconfig)
	p.login()
	#p.showscanmethod()
	#p.addtask('scanfile.txt')
	#p.addtask()
	p.delallscan()
	#p.getallstatus()
	#p.getalldata()
