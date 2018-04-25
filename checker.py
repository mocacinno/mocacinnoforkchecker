import sys
import argparse
import requests
import base58
import time
import urllib3
import json

def main():
	available_forks = {
		"B2X": get_b2x, 				#Bitcoin Segwit2X			#working
		"BCA": get_bca, 				#Bitcoin Atom				#manual	
		"BCD": get_bcd, 				#Bitcoin Diamond			#manual	
		"BCH": get_bch, 				#Bitcoin Cash				#working
		"BCHC": get_bchc, 				#Bitcoin Clashic			#working
		"BCI": get_bci, 				#Bitcoin Intrest			#working
		"BCK": get_bck, 				#Bitcoin King				#no explorer
		"BCW": get_bcw, 				#Bitcoin Wonder				#no explorer
		"BCX" : get_bcx, 				#BitcoinX					#working
		"BICC" : get_bicc,				#BitClassic					#working
		"BITCOINMINOR" : get_bitcoinminor,	#Bitcoin Minor			#no explorer
		"BNR" : get_bnr,				#Bitcoin Neuro				#no explorer
		"BPA" : get_bpa, 				#Bitcoin Pizza				#working
		"BTA" : get_bta,				#Bitcoin All				#no explorer
		"BTC" : get_btc,				#Bitcoin					#working
		"BTCP" : get_btcp,				#Bitcoin platinum			#no explorer
		"BTCS" : get_btcs,				#Bitcoin Stake				#no explorer
		"BTF": get_btf, 				#Bitcoin Faith				#no explorer
		"BTG": get_btg, 				#Bitcoin Gold				#working
		"BTH": get_bth,					#Bitcoin Hot				#no explorer
		"BTP": get_btp,					#Bitcoin Pay				#no explorer
		"BTSQ": get_btsq,				#Bitcoin Community			#no explorer
		"BTW": get_btw, 				#Bitcoin World				#no explorer
		"BTX": get_btx, 				#Bitcore					#working
		"CDY": get_cdy, 				#Bitcoin Candy (for of BCH)	#working
		"LBTC": get_lbtc,				#Lightning Bitcoin			#manual
		"OBTC": get_obtc,				#Oil Bitcoin				#no explorer
		"SUPERBTC": get_superbtc, 		#Super Bitcoin				#working
	}
	parser = argparse.ArgumentParser()
	parser.add_argument("--address", help="query a single address")
	parser.add_argument("--addressfile", help="query all addresses in this file")
	parser.add_argument("--fork", help="query a single fork")
	parser.add_argument("--showforks", help="show all forks" , action='store_true')
	parser.add_argument("--outfile", help="output to this file instead of stdout (screen)")
	parser.add_argument("--timeout", help="number of seconds to wait between 2 requests", nargs='?', const=2, type=int)
	args = parser.parse_args()
	if args.outfile:
		sys.stdout = open(args.outfile, 'w')

	if args.showforks:
		print "available forks:"
		print "****************"
		for printfork in available_forks:
			print printfork
		sys.exit("")

	addresslist = []
	forklist = []
	successes = []
	if args.address:
		addresslist.append(args.address)
	if args.addressfile:
		with open(args.addressfile) as file:
			for address in file:
				addresslist.append(address.rstrip())
	if len(addresslist) == 0:
		sys.exit("no addresses available")
		
	if args.fork:
		for forkname, forkfunction in available_forks.iteritems(): 
			if forkname == args.fork:
				forklist = {forkname:forkfunction}
	else:
		forklist = available_forks
		
	if len(forklist) == 0:
		sys.exit("no forks to check")
	if args.timeout:
		timeout = args.timeout
	else:
		timeout = 2
		
	for testaddress in addresslist:
		for testfork in forklist:
			print "testing " + testaddress + " on " + testfork
			func = forklist.get(testfork, lambda: "Wrong fork")
			balance = func(testaddress)
			if balance > 0:
				successes.append(testaddress + " has a balance of " + str(balance) + " on " + testfork)
			time.sleep(timeout)
	if len(successes) > 0:
		print
		print "**************************************************"
		print "* found unspent outputs on one or more chains!!! *"
		print "* claim at your own risk!                        *"
		print "**************************************************"
		print
		print "successlist"
		print "***********"
		for success in successes:
			print success
		print
		print "-------------------------------------------------------------------------------------------"
		print "| once again, if you import your private key into ANY unknown/untrusted wallet,           |"
		print "| you risk losing your unspent outputs on all other chains!!!                             |"
		print "| proceed with caution                                                                    |"
		print "|*****************************************************************************************|"
		print "| at least make sure your wallets on the most important chains are empty before importing |"
		print "| their private keys into unknown wallets!!!                                              |"
		print "-------------------------------------------------------------------------------------------"
		print
		print "if you like this project, consider some of the \"free\" coins you got from these forks to me ;)"
		print "BTC/BCH/BTX/B2X/...: 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa"
		print "BTG: GeeXaL3TKCjtdFS78oCrPsFBkEFt9fxuZF"

###############################################################################################	

def veranderprefix(address, prefix):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = prefix
		newaddress = base58.b58encode_check(bytes(decoded))
		return newaddress
	except:
		print "could not convert address " + address + " using prefix " + prefix 

def frominsightapi(address, baseurl, chain):
	stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
	try:
		r = requests.get(baseurl + 'addr/%s/?noTxList=1' % address)
		if r.text != 'Invalid address: Address has mismatched network type.. Code:1':
			balance = r.json()['balance']
			try:
			   val = float(balance)
			   return val
			except ValueError:
			   print stderror
			   return 0
		else :
			print stderror
			return 0
	except:
		print stderror
		return 0
		
def frominsightapi_urllib3(address, baseurl, chain):
	#only use this one if incorrect depreciation warnings are shown when using the fromsightapi function
	urllib3.disable_warnings()
	stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
	try:
		http = urllib3.PoolManager()
		r = http.request('get', baseurl + 'addr/%s/?noTxList=1' % address)
		balance = json.loads(r.data)['balance']
		try:
		   val = float(balance)
		   return val
		except ValueError:
		   print stderror
		   return 0
	except:
		print stderror
		return 0

def fromchainz(address, baseurl, chain):
	try:
		r = requests.get(baseurl + 'api.dws?q=getbalance&a=%s' % address)
		stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
		try:
			val = float(r.text)
			return val
		except ValueError:
			print stderror
			return 0
	except:
		print stderror
		return 0
		
def fromiquidus(address, baseurl, chain):
	try:
		r = requests.get(baseurl + 'getbalance/%s' % address)
		stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
		try:
			val = float(r.text)
			return val
		except ValueError:
			if json.loads(r.text)['error'] == "address not found.":
				return 0
			print stderror + " 1"
			return 0
	except:
		print stderror + " 2"
		return 0
		
###############################################################################################

def get_bchc(address):
	chain = "BCHC"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi_urllib3(address, 'https://truevisionofsatoshi.com/api/', chain)	
	
def get_btc(address):	
	chain = "BTC"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return fromchainz(address, 'https://chainz.cryptoid.info/btc/', chain)		
		
def get_bci(address):
	chain = "BCI"
	address = veranderprefix(address, 102)
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://explorer.bitcoininterest.io/api/', chain)	
	
def get_btx(address):	
	chain = "BCX"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return fromchainz(address, 'https://chainz.cryptoid.info/btx/', chain)	
			
def get_bca(address):
	print "\tno explorer with an api found, check manually on https://bitcoinatom.net/ (prefix 23)"
		
def get_btsq(address):
	print "\tdidn't find a single explorer for bitcoin community (btsq) (prefix 63)"
	
def get_obtc(address):
	print "\tdidn't find a single explorer for oil bitcoin (obtc)"
	
def get_cdy(address):
	chain = "CDY"
	address = veranderprefix(address, 0x1c)
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'http://block.cdy.one/insight-api/', chain)	
		
def get_bth(address):
	print "\tdidn't find a single explorer for bitcoin hot (bth) (prefix 40)"
	
def get_bitcoinminor(address):
	print "\tdidn't find a single explorer for bitcoin minor (bitcoinminor)"

def get_btp(address):
	print "\tdidn't find a single explorer for bitcoin pay (btp) (prefix 0x38)"
	
def get_bta(address):
	print "\tdidn't find a single explorer for bitcoin all (bta)"
	
def get_bnr(address):
	print "\tdidn't find a single explorer for bitcoin neuro (bnr)"

def get_bpa(address):
	chain = "BPA"
	address = veranderprefix(address, 55)
	print "\t checking address " + address + " on the " + chain + " chain"	
	return fromiquidus(address, 'http://47.100.55.227/ext/', chain)

def get_bicc(address):
	chain = "BICC"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return fromiquidus(address, 'http://18.216.251.169/ext/', chain)

def get_btw(address):
	print "\tdidn't find a single explorer for bitcoin world (btw) (prefix 73)"
	
def get_btf(address):
	print "\tdidn't find a single explorer for bitcoin faith (btf) (prefix 36)"

def get_btcp(address):
	print "\tdidn't find a single explorer for bitcoin platinum (btcp)"

def get_btcs(address):
	print "\tdidn't find a single explorer for bitcoin stake (btcs)"

def get_bck(address):
	print "\tdidn't find a single explorer for bitcoin king (bck)"

def get_bcw(address):
	print "\tdidn't find a single explorer for bitcoin wonder (bcw)"
	
def get_bcx(address):
	chain = "BCX"
	address = veranderprefix(address, 75)
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://bcx.info/insight-api/', chain)	
	
def get_bch(address):
	chain = "BCH"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://bitcoincash.blockexplorer.com/api/', chain)	
				
def get_superbtc(address):
	chain = "SUPERBTC"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'http://block.superbtc.org/insight-api/', chain)	
	print "\tSUPERBTC api down, check manually at block.superbtc.org"
	
def get_b2x(address):
	chain = "B2X"
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://explorer.b2x-segwit.io/b2x-insight-api/', chain)	
	
def get_lbtc(address):
	print "\tLBTC api down, check manually at explorer.lbtc.io"

def get_bcd(address):
	print "\tLBTC api down, check manually at explorer.btcd.io"
	
def get_btg(address):
	chain = "BTG"
	address = veranderprefix(address, 38)
	print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://btgexplorer.com/api/', chain)	

###############################################################################################	

if __name__ == '__main__':
	main()