#！encoding:utf-8
import json
import time
import os
import sys

from random import randint
_ATTACK_INFO = [
		"GET_Illegal_Args",
		"Illegal_File_Content_Upload",
		"Steal_resource",
		"unusual_HTTP_request",
		"CC_Attack",
		"Directory_Traversal_Attack",
		"File_Contains_Attack",
		"xss Injection",
		"System_command_Injection",
		"SQL_Injection",
		"Deny_of_struts2_EXP",
		"Use_Hack_Tools",
		"Deny_URL",
		"Vulnerability_Of_Struts2",
		"Deny_Cookie",
		"BlackList_IP",
		"White_IP"

	]
def get_current_time():
	return time.strftime('%Y-%m-%d',time.localtime(time.time()))

ANALYSER_LOG_PATH = "../lib/static/temp" 


class CountingAttackIP(object):
	"""docstring for AttackIP"""
	ATTACK_IPs = {}
	def __init__(self, arg):
		pass

	@classmethod
	def get_results(cls, log):
		client_ip = log['client_ip']
		if client_ip not in cls.ATTACK_IPs:
			cls.ATTACK_IPs[client_ip] = 1
		else:
			cls.ATTACK_IPs[client_ip] += 1

	@classmethod
	def save(cls):
		data = {"data":[]}
		for key in cls.ATTACK_IPs:
			data["data"].append([randint(5,30), cls.ATTACK_IPs[key], key])
		with open(ANALYSER_LOG_PATH + '/counting_ip', 'w') as fp:
			json.dump(data, fp)

class CountingAttackInfo(object):
	ATTACK_INFOs = {}
	def __init__(self, arg):
		pass
	@classmethod
	def get_results(cls, log):
		attack_info = log['attack_info']
		if attack_info in cls.ATTACK_INFOs:
			cls.ATTACK_INFOs[attack_info] += 1
		else:
			cls.ATTACK_INFOs[attack_info] = 1
	@classmethod
	def save(cls):
		data = []
		for key in cls.ATTACK_INFOs:
			data.append(cls.ATTACK_INFOs[key])
		with open(ANALYSER_LOG_PATH + '/counting_attack_type', 'w') as fp:
			json.dump(data, fp)

class AttackMethod(object):
	ATTACK_TYPE_COLLECTIONs = {}
	def __init__(self, args):
		try:
			self.attack_type = args["attack_info"]
			self.client_ip = args["client_ip"]
			self.rule = args['filter_rule']
			self.local_time = args["local_time"]
			self.server_name = args["server_name"]
			self.req = args["req_url"]
		except Exception as err:
			self.req = "NOT FOUND"
			# print(self.req)
			print(err)
	
	def fix_final_list(self):
		index = _ATTACK_INFO.index(self.attack_type)
		try:
			check_dict = {
				 0: 	"发现主机" + self.client_ip + "发起的GET请求中存在危险参数，请求数据为：" + self.req + " ，已被WAF拦截。",
				 1: 	"发现主机" + self.client_ip + "上传的文件中有危险内容，请求路径为：" + self.req + ",已被WAF阻止。",
				 2: 	"发现主机" + self.client_ip + "正在请求本站资源，由于设置防盗链已被拦截，请求URI为" + self.req,
				 3: 	"发现主机" + self.client_ip + "发起不常见HTTP请求，请求方法为" + self.rule + "已被WAF阻止。",
				 4: 	"发现主机" + self.client_ip + "频繁对 "+ self.req + "发起连接，疑似CC攻击，已被拦截",
				 5: 	"发现主机" + self.client_ip + "正在执行目录遍历攻击，已被拦截，请求URI为" + self.req,
				 6:		"发现主机" + self.client_ip + "正在进行文件包含攻击，已被拦截，请求URI为" + self.req,
				 7: 	"发现主机" + self.client_ip + "正在尝试XSS注入攻击，请求URL为" + self.req + ", 已被拦截。",
				 8: 	"发现主机" + self.client_ip + "正在尝试命令注入攻击，请求URL为" + self.req + ", 已被拦截。",
				 9: 	"发现主机" + self.client_ip + "正在尝试SQL注入攻击，请求URL为" + self.req + ", 已被拦截。",
				 10: 	"发现主机" + self.client_ip + "疑似利用WEB容器漏洞发起攻击，请求URL为" + self.req + ", 已被拦截。",
				 11:	"发现主机" + self.client_ip + "正在使用黑客扫描工具扫描本服务器，已被拦截。",
				 12:	"发现主机" + self.client_ip + "访问限制URL：" + self.req ,
				 13:	"发现主机" + self.client_ip + "利用st2漏洞进行攻击，已拦截。",	 
				 14:	"发现主机" + self.client_ip + "请求的Cookies中含有非法字符，已拦截。 ",
				 15:	"发现主机" + self.client_ip + "发起请求，但本IP已在黑名单中，故拦截。",
				 16:	"Nothing"
			}
			self.req = check_dict[index]
		except Exception as err:
			pass
			print(index)
			print(err)


	def get_one_final_list(self):
		data_list = []
		try:
			self.fix_final_list()
			data_list.append(self.attack_type)
			data_list.append(self.local_time)
			data_list.append(self.server_name)
			data_list.append(self.client_ip)
			data_list.append(u"中危")
			data_list.append(self.req)
			
		except Exception as err:
			print("找不到对应类型：" + str(err))
			pass
		return data_list

	@classmethod
	def save(cls):
		for list in cls.ATTACK_TYPE_COLLECTIONs:
			with open(ANALYSER_LOG_PATH + '/' + list, 'w') as fp:
				data = {"data":cls.ATTACK_TYPE_COLLECTIONs[list]}
				json.dump(data, fp)	
	
	@classmethod
	def get_results(cls, args):
		AttackObject = AttackMethod(args)
		final_list = AttackObject.get_one_final_list()
		if final_list[0] in cls.ATTACK_TYPE_COLLECTIONs:
			cls.ATTACK_TYPE_COLLECTIONs[final_list[0]].append(final_list)
		else:
			cls.ATTACK_TYPE_COLLECTIONs[final_list[0]] = [final_list, ]

def save_result():
	CountingAttackIP.save()
	CountingAttackInfo.save()
	AttackMethod.save()

def analyser():
	time = get_current_time()
	log_file_path = time + '_waf.log'
	# log_file_path = '2017-09-01_waf.log'
	log_file_path = '/usr/local/openresty/nginx/logs/' + log_file_path
	with open(log_file_path, 'r') as fp:
		records = fp.readlines()
		print(len(records))
		for record in records:
			# record = record.decode('gb2312')
			print(record)
			if record == '\n' or record == '' or len(record) <= 20:
				continue
			record.replace('\n', '')
			record.replace('0xdf', '')
			log = (json.loads(record))
			CountingAttackIP.get_results(log)
			CountingAttackInfo.get_results(log)
			AttackMethod.get_results(log)
			save_result()

if __name__ == '__main__':
	if not os.path.exists(ANALYSER_LOG_PATH):
		os.makedirs(ANALYSER_LOG_PATH)
	analyser()




	

