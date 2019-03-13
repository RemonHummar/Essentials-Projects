import os
import subprocess as sp
from datetime import datetime
import os
import concurrent.futures
import requests
import re

if os.name=='nt':
	try:
		from colorama import init,AnsiToWin32
		init()
	except ImportError:
		print "[!] os anda adalah windows\n[!] kamu harus menginstall colorama"
		rr = raw_input("mau menginstall colorama [y/n]  ")
		if rr=='y' or rr=='Y':
			sp.call('pip install colorama',shell=True)
		else:
			quit()
else:
	pass
from time import sleep as t
def logo():
	m = "\033[1;31m"
	p = "\033[1;37m"
	b = "\033[1;34m"
	h = "\033[1;32m"
	k = "\033[1;33m"
	print """
                      {0} __________________
                      {1}|                  |
                      {2}|                  |             {9}Essentials Project v.{10}1.{11}0
                      {3}|                  |             {12}Author    : {13}Muhammad Quwais Safutra
                  {4}----------------------------         {14}Languages : {15}3+
                      {5}##                ##             {16}Youtube   : {17}QsonXLawyer
                     {6} ##                ##             {18}WhatsApp  : {19}+{20}6289662275646
                      {7} ##              ##               {21}System {22}Server {23}Secur{24}ity
                   {8}===========================

	""".format(m,p,p,p,m,k,k,k,h,b,m,h,p,m,p,m,p,m,h,k,p,m,b,m,h)

thread_count = 4

print "\n"*300
logo()
m = "\033[1;31m"
p = "\033[1;37m"
b = "\033[1;34m"
h = "\033[1;32m"
k = "\033[1;33m"
kk = "{0}[{1}?{2}] {3}p{4}ass{5}wor{6}d {7}:{8}    ".format(k,h,b,p,m,k,b,p,m)
d = datetime.now().strftime("%H:%M")
info = "\033[1;33m[\033[1;32m{}\033[1;33m][\033[1;31mINFO\033[1;33m] \033[1;37m".format(d)

print """
     {0}Languages
     {1}[1]  {2}Indonesia
     {3}[2]  {4}English

""".format(p,h,m,h,b)

def alpha(hashvalue, hashtype):
    return False

def beta(hashvalue, hashtype):
    response = requests.get('http://hashtoolkit.com/reverse-hash/?hash=', hashvalue).text
    match = re.search(r'/generate-hash/?text=.*?"', response)
    if match:
        return match.group(1)
    else:
        return False

def gamma(hashvalue, hashtype):
    response = requests.get('http://www.nitrxgen.net/md5db/' + hashvalue).text
    if response:
        return response
    else:
        return False

def delta(hashvalue, hashtype):
    return False

def theta(hashvalue, hashtype):
    response = requests.get('http://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=deanna_abshire@proxymail.eu&code=1152464b80a61728' % (hashvalue, hashtype)).text
    if len(response) != 0:
        return response
    else:
        return False

md5 = [gamma, alpha, beta, theta, delta]
sha1 = [alpha, beta, theta, delta]
sha256 = [alpha, beta, theta]
sha384 = [alpha, beta, theta]
sha512 = [alpha, beta, theta]

def crack_indo(hashvalue):
	d = datetime.now().strftime("%H:%M")
	info = "\033[1;33m[\033[1;32m{}\033[1;33m][\033[1;31mINFO\033[1;33m] \033[1;37m".format(d)
	result = False
	if len(hashvalue)==32:
		if not file:
			print "{} tipe hash di temukan \033[1;32mMD5".format(info)
		for api in md5:
			r = api(hashvalue,'md5')
			if r: return r 
	elif len(hashvalue)==40:
		if not file:
			print "{} tipe hash di temukan \033[1;32mSHA1".format(info)
		for api in sha1:
			r = api(hashvalue,'sha1')
			if r: return r
	elif len(hashvalue)==64:
		if not file:
			print "{} tipe hash di temukan \033[1;32mSHA-256".format(info)
		for api in sha1:
			r = api(hashvalue,'sha256')
			if r: return r
	elif len(hashvalue)==96:
		if not file:
			print "{} tipe hash di temukan \033[1;32mSHA-384".format(info)
		for api in sha1:
			r = api(hashvalue,'sha384')
			if r: return r
	elif len(hashvalue)==128:
		if not file:
			print "{} tipe hash di temukan \033[1;32mSHA-512".format(info)
		for api in sha1:
			r = api(hashvalue,'sha-512')
			if r: return r
	else:
		if not file:
			print "{} tipe hash sepertinya tidak terdeteksi :( maaf".format(info)
		else: return False

def crack_english(hashvalue):
	d = datetime.now().strftime("%H:%M")
	info = "\033[1;33m[\033[1;32m{}\033[1;33m][\033[1;31mINFO\033[1;33m] \033[1;37m".format(d)
	result = False
	if len(hashvalue)==32:
		if not file:
			print "{} hash type is \033[1;32mMD5".format(info)
		for api in md5:
			r = api(hashvalue,'md5')
			if r: return r 
	elif len(hashvalue)==40:
		if not file:
			print "{} hash type is \033[1;32mSHA1".format(info)
		for api in sha1:
			r = api(hashvalue,'sha1')
			if r: return r
	elif len(hashvalue)==64:
		if not file:
			print "{} hash type is \033[1;32mSHA-256".format(info)
		for api in sha1:
			r = api(hashvalue,'sha256')
			if r: return r
	elif len(hashvalue)==96:
		if not file:
			print "{} hash type is \033[1;32mSHA-384".format(info)
		for api in sha1:
			r = api(hashvalue,'sha384')
			if r: return r
	elif len(hashvalue)==128:
		if not file:
			print "{} hash type is \033[1;32mSHA-512".format(info)
		for api in sha1:
			r = api(hashvalue,'sha-512')
			if r: return r
	else:
		if not file:
			print "{} i cannot found the hash type. i'm sorry :(".format(info)
		else: return False

def single_indo(password):
	result = crack_indo(password)
	if result:
		print info+"password di pecahkan : \033[1;33m"+result+"\033[1;37m"
	else:
		print "{} tipe hash sepertinya tidak terdeteksi :( maaf".format(info)

def single_english(password):
	result = crack_indo(password)
	if result:
		print info+"password cracked : \033[1;33m"+result+"\033[1;37m"
	else:
		print "{} i cannot foun the hash type. i'm sorry :(".format(info)


def miner_indo(file):
	lines = []
	found = set()
	with open(file,'r') as f:
		for line in f:
			lines.append(line.strip('\n'))
	for line in lines:
		matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
		if matches:
			for match in matches:
				found.add(match)
	print ('%s Hashes ditemukan: %i' % (info, len(found)))
	print info+"hash di temukan: %i"%len(found)
	threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
	futures = (threadpool.submit(threaded, hashvalue) for hashvalue in found)
	for i, _ in enumerate(concurrent.futures.as_completed(futures)):
		if i + 1 == len(found) or (i + 1) % thread_count == 0:
			print info+"prosessing %i/%i"%(info,i+1,len(found))

def miner_english(file):
	lines = []
	found = set()
	with open(file,'r') as f:
		for line in f:
			lines.append(line.strip('\n'))
	for line in lines:
		matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
		if matches:
			for match in matches:
				found.add(match)
	print ('%s Hashes found: %i' % (info, len(found)))
	print info+"hash found: %i"%len(found)
	threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=thread_count)
	futures = (threadpool.submit(threaded, hashvalue) for hashvalue in found)
	for i, _ in enumerate(concurrent.futures.as_completed(futures)):
		if i + 1 == len(found) or (i + 1) % thread_count == 0:
			print info+"progress %i/%i"%(info,i+1,len(found))


def indonesia():
	m = "\033[1;31m"
	p = "\033[1;37m"
	b = "\033[1;34m"
	h = "\033[1;32m"
	k = "\033[1;33m"
	print "\n"*300
	logo()
	kk = "{0}[{1}?{2}] {3}p{4}ass{5}wor{6}d {7}:{8}    ".format(k,h,b,p,m,k,b,p,m)
	kkd = "{0}[{1}?{2}] {3}p{4}ass{5}wor{6}d {9}file {7}:{8}     ".format(k,h,b,p,m,k,b,p,m,b)
	d = datetime.now().strftime("%H:%M")
	info = "\033[1;33m[\033[1;32m{}\033[1;33m][\033[1;31mINFO\033[1;33m] \033[1;37m".format(d)
	print """
{0}[!]{1} pilih opsi yang kamu mau
{2}1. {3}satu password saja
{4}2. {5}crack satu file

	""".format(m,k,h,p,h,p)
	while True:
		opsi = raw_input("opsi >  ")
		if opsi=='1':
			password = raw_input(kk)
			print "\n{0} starting Essentials Project 1.0".format(info)
			t(3)
			print "{} mencari liblary request(s)".format(info)
			try:
				import requests
			except ImportError:
				print "[!] requests tidak di temukan!. silahkan install terlebih dahulu :("
				quit()
			cwd = os.getcwd()
			single_indo(password)
		elif opsi=='2':
			files = raw_input(kkd)
			miner_indo(files)
			with open('cracked-%s'%files.split('/')[-1],'w+') as f:
				print info+"file disimpan pada cracked-%s"%files.split('/')[-1]


def english():
	m = "\033[1;31m"
	p = "\033[1;37m"
	b = "\033[1;34m"
	h = "\033[1;32m"
	k = "\033[1;33m"
	print "\n"*300
	logo()
	kk = "{0}[{1}?{2}] {3}p{4}ass{5}wor{6}d {7}:{8}    ".format(k,h,b,p,m,k,b,p,m)
	kkd = "{0}[{1}?{2}] {3}p{4}ass{5}wor{6}d {9}file {7}:{8}     ".format(k,h,b,p,m,k,b,p,m,b)
	d = datetime.now().strftime("%H:%M")
	info = "\033[1;33m[\033[1;32m{}\033[1;33m][\033[1;31mINFO\033[1;33m] \033[1;37m".format(d)
	print """
{0}[!]{1} select the options you want
{2}1. {3}just one password to crack
{4}2. {5}crack 1 files with password

	""".format(m,k,h,p,h,p)
	while True:
		opsi = raw_input("options >  ")
		if opsi=='1':
			password = raw_input(kk)
			print "\n{0} starting Essentials Project 1.0".format(info)
			t(3)
			print "{} searching for liblary request(s)".format(info)
			try:
				import requests
			except ImportError:
				print "[!] requests not found !. please install requests first :("
				quit()
			cwd = os.getcwd()
			single_english(password)
		elif opsi=='2':
			files = raw_input(kkd)
			miner_indo(files)
			with open('cracked-%s'%files.split('/')[-1],'w+') as f:
				print info+"file saved in cracked-%s"%files.split('/')[-1]

l=raw_input("select number  :   ")
if l=='1':
	indonesia()
elif l=='2':
	english()
else:
	print "[!] invalid syntax"