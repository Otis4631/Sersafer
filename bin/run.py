import os
import time
from multiprocessing import Pool
def analyser():
	i = 0
	while True:
		i += 1
		CMD = []
		CMD.append("python3 log_analyser.py")
		CMD.append("python3 ssh_analyser.py")
		CMD.append("python ../webshell/main.py")
		CMD.append("mv out.json ../lib/static/temp")
		for cmd in CMD:
			os.system(cmd)
		if os.path.exists("out"):
			cmd = " python3 visualizer.py  out"
			os.system(cmd)
			os.system("rm out")
			
		else:
			os.system(" python3 analyzer.py -x out.xml out ")
			cmd = " python3 visualizer.py  out"
		os.system(cmd)
		break
		#time.sleep(3 * 60 * 60)

def flask_server():
	print("Initializing Data...")
	os.system("python3 Nmap2CVE-Search.py out.xml")
	print("subprocess done!")
	#time.sleep(3 * 60 * 60)


if __name__ == '__main__':
	p = Pool()
	p.apply_async(analyser,)
	print("main" + str(os.getpid()))
	p.close()
	p.join()
