#!/usr/bin/env python
#coding=utf8

import glob, os, time, sys, threading, commands
from optparse import OptionParser
from filterShell import *
from getFileTime import *
from scanShell import *
from createHtml import createHtml
from directory.codition_code import *
from get_ip import *
import json, socket, fcntl, struct  


n_objs = [] #线程文件名列表  
c_objs = [] #线程内容列表
lc_objs = [] #线程大内容列表
lock = threading.Lock()
#黑名单列表
blackList = []
#名字字典
fileList = {}
#结果列表
resList =  []


class find_name:
	def __init__(self):
		self.res = []
		self.con = {}
	def run(self, ext, name):
		if ext == "php":
			if name in php_webshell:
				self.res.append(name)
		elif ext == "asp":
			if name in asp_webshell:
				self.res.append(name)
		elif ext == "apsx":
			if name in aspx_webshell:
				self.res.append(name)
		elif ext == "jsp":
			if name in jsp_webshell:
				self.res.append(name)
		elif ext == "all":
			if name in (php_webshell + asp_webshell + aspx_webshell + jsp_webshell):
				self.res.append(name)
		else:
			print "args error!"
			exit(0)
	def strt(self, ext, ctent, path):
		if ext == "php":
			for word in php_sensitive_words.keys():
				if word in ctent:
					self.con[php_sensitive_words.get(word)] = path
					break
		elif ext == "asp":
			for word in asp_sensitive_words.keys():
				if word in ctent:
					self.con[asp_sensitive_words.get(word)] = path
					break
		elif ext == "aspx":
			for word in aspx_sensitive_words.keys():
				if word in ctent:
					self.con[aspx_sensitive_words.get(word)] = path
					break
		elif ext == "jsp":
			for word in jsp_sensitive_words.keys():
				if word in ctent:
					self.con[jsp_sensitive_words.get(word)] = path
					break
		elif ext == "all":
			all_sensitive_words.update(php_sensitive_words)
			all_sensitive_words.update(asp_sensitive_words)
			all_sensitive_words.update(jsp_sensitive_words)
			all_sensitive_words.update(aspx_sensitive_words)
			for word in all_sensitive_words.keys():
				if word in ctent:
					self.con[all_sensitive_words.get(word)] = path
					break
		else:
			print "args error!"
			exit(0)
	def get_res(self):
		return self.res
		
	def get_con(self):
		return self.con


		
class find_codition_code:
	def __init__(self):
		self.con = {}
	def find_c(self, filepath):
		status, output = commands.getstatusoutput('md5sum ' + filepath)
		if status == 0 and os.path.getsize(filepath) >= 1:
			for line in codition_code.keys():
				if line in output:
					self.con[codition_code.get(line)] = filepath	
	def get_con(self):
		return self.con		

		

def deal_res():
	#处理后门列表
	l = len(resList)
	for i in xrange(l):
		resList[i][5] = os.path.abspath(resList[i][5])
		
	#生成报告
	fp = open('out.json', 'w')
	#html = createHtml(resList)
	
	fp.write('{\n')
	fp.write('\t"data": [\n')
	ll = len(resList)
	ss = 0
	for line in resList:
		leng = len(line)
		num = 0
		fp.write('\t\t[\n')
		for l in line:
			num += 1
			if num == leng:
				fp.write('\t\t"' + l + '"\n')
			else:
				fp.write('\t\t"' + l + '",\n')
		ss += 1
		if ss == ll:
			fp.write('\t\t]\n')
		else:
			fp.write('\t\t],\n')
	fp.write('\t]\n')
	fp.write('}\n')
	fp.close()

def scan_php_webshell(path = '/www/html/'):
	options = ['php', path]
	start = time.clock()
	

	#获取文件绝对路径
	for root, dirs, files in os.walk(options[1]):
		for filename in files:
			fullpath = os.path.join(root, filename)
			fileList[filename] = fullpath
      
	print "已查询到%s目录下所有文件" %options[1]
	
	temp_codition = {}
	
	
	#过滤类
	
	fn = find_name()
	#文件名过滤
	for filename in fileList.keys():
		t = threading.Thread(target=fn.run, args=(options[0], filename, ))
		t.start()
		#res = FilterShell.filename(options.ext, filename)
		n_objs.append(t)
	
	for t in n_objs:
		t.join()
	
	webshell_name = fn.get_res()
	
	for i in webshell_name:
		#获取后门类型，文件修改时间，文件路径
		fullpath = fileList.get(i)
		mtime = getFileTime(fullpath)
		filemode = "一般类型"
		resList.append([filemode, mtime, get_ip('eth0'), ' ', '高危', fullpath])
		blackList.append(fullpath)
		
	
	print "已完成%s目录下所有文件可疑文件名的扫描" %options[1]

#根据后门特征码检测
	
	fc = find_codition_code()
	try:
		for key in fileList:
			if fileList[key] not in blackList:
				t = threading.Thread(target=fc.find_c, args=(fileList[key],))
				t.start()
				lc_objs.append(t)
	except BaseException, SyntaxError:
		pass
	
	for t in lc_objs:
		t.join()
	temp_codition = fc.get_con()
	

	for i in temp_codition:
		mtime = getFileTime(temp_codition[i])
		resList.append([i, mtime, get_ip('eth0'), ' ', '高危', temp_codition[i]])
		blackList.append(temp_codition[i])


	print "已完成%s目录下所有文件hash值的匹配" %options[1]
	
	

	
	#根据webshell敏感字符过滤
	
	try:
		for filename in fileList.keys():
			fullpath = fileList.get(filename)
			if fullpath not in blackList and os.path.isfile(fullpath):
				with open(fullpath, "rb") as fp:
					if os.path.getsize(fullpath) < 500000:
						ctent = fp.read()
						filemode = FilterShell.content(options[0], ctent)
						#获取后门类型，文件修改时间，文件路径
						if filemode:
							mtime = getFileTime(fullpath)
							resList.append([filemode, mtime, get_ip('eth0'), ' ', '高危', fullpath])
							blackList.append(fullpath)
						else:
							pass
					else:
						for line in fp:
							filemode = FilterShell.content(options[0], line)
							if filemode:
								mtime = getFileTime(fullpath)
								resList.append([filemode, mtime, get_ip('eth0'), ' ', '高危', fullpath])
								blackList.append(fullpath)
								break
							else:
								pass
			else:
				pass
	except BaseException:
		pass
	
	
	
	print "已完成%s目录下所有文件敏感字符的查询" %options[1]
	
	
	#正则匹配后门语法
	scan(options[1], options[0], blackList, resList)
	
	print "已完成%s目录下加载插件的扫描" %options[1]
	
	end = time.clock()
	print "在%s目录下扫描完成共%fs" %(options[1], end-start)
	
	if resList:
		deal_res()
		print "已生成webshell扫描文件报告"
	else:
		print "未扫描出结果"
		
	

	
	
	
	
if __name__=='__main__':
	FilterShell = FilterShell()
	scan_php_webshell('/var')
