from codition_code import *
import os, commands

fileList = {}

if __name__=='__main__':
    for root, dirs, files in os.walk('/etc'):
		for filename in files:
			fullpath = os.path.join(root, filename)
			fileList[filename] = fullpath


    for key in fileList:
		status, output = commands.getstatusoutput('md5sum ' + fileList[key])
		if status == 0:
			#print output
                        out1 = output[:output.find(' ')]
                        out2 = output[output.find(fileList[key]):]
                        #print out1
                        #print out2
                        print out1 + '1'
                        break
