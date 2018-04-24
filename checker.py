import sys
import argparse
import requests
import base58
import time

def main():
	available_forks = {
		"B2X": get_b2x, 			#Bitcoin Segwit2X			#working
		"BCA": get_bca, 			#Bitcoin Atom				#manual	
		"BCH": get_bch, 			#Bitcoin Cash				#working
		"BCI": get_bci, 			#Bitcoin Intrest			#working
		"BCX" : get_bcx, 			#BitcoinX					#working
		"BPA" : get_bpa, 			#Bitcoin Pizza				#working
		"BTC" : get_btc,			#Bitcoin					#working
		"BTF": get_btf, 			#Bitcoin Faith				#no explorer
		"BTG": get_btg, 			#Bitcoin Gold				#working
		"BTH": get_bth,				#Bitcoin Hot				#no explorer
		"BTP": get_btp,				#Bitcoin Pay				#no explorer
		"BTSQ": get_btsq,			#Bitcoin Community			#no explorer
		"BTW": get_btw, 			#Bitcoin World				#no explorer
		"BTX": get_btx, 			#Bitcore					#working
		"CDY": get_cdy, 			#Bitcoin Candy (for of BCH)	#working
		"LBTC": get_lbtc,			#Lightning Bitcoin			#manual
		"SUPERBTC": get_superbtc, 	#Super Bitcoin				#manual
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

		
###############################################################################################		
		
def get_btc(address):
	try:
		r = requests.get('https://chainz.cryptoid.info/btx/api.dws?q=getbalance&a=%s' % address)
		return r.text
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BTC chain"
		return 0	
		
def get_bci(address):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = 102
		address_bci = base58.b58encode_check(bytes(decoded))
		print "\t address " + address + " was converted to BCI address " + address_bci	
		r = requests.get('https://explorer.bitcoininterest.io/api/addr/%s/?noTxList=1' % address_bci)
		if r.text != 'Invalid address: Address has mismatched network type.. Code:1':
			balance = r.json()['balance']
			return balance
		else :
			print "\tsomething went wrong while checking " + str(address) + " on the BCI chain"
			return 0
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BCI chain"
		return 0		
		
		
def get_bca(address):
	#BCA 23
	print "\tno explorer with an api found, check manually on https://bitcoinatom.net/"
		
def get_btsq(address):
	#BTW 63
	print "\tdidn't find a single explorer for bitcoin community (btsq)"
		
def get_cdy(address):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = 0x1c
		address_cdy = base58.b58encode_check(bytes(decoded))
		print "\t address " + address + " was converted to CDY address " + address_cdy	
		r = requests.get('http://block.cdy.one/insight-api/addr/%s/?noTxList=1' % address_cdy)
		if r.text != 'Invalid address: Address has mismatched network type.. Code:1':
			balance = r.json()['balance']
			return balance
		else :
			print "\tsomething went wrong while checking " + str(address) + " on the CDY chain"
			return 0
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the CDY chain"
		return 0
		
def get_bth(address):
	#BTW 40
	print "\tdidn't find a single explorer for bitcoin hot (bth)"

def get_btp(address):
	#BTW 0x38
	print "\tdidn't find a single explorer for bitcoin pay (btp)"

def get_bpa(address):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = 55
		address_bpa = base58.b58encode_check(bytes(decoded))
		print "\t address " + address + " was converted to BPA address " + address_bpa	
		r = requests.get('http://47.100.55.227/ext/getbalance/%s' % address_bpa)
		balance = r.text
		if balance.isnumeric():
			return balance
		else :
			print "\tsomething went wrong while checking " + str(address) + " on the BPA chain"
			return 0
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BPA chain"
		return 0

def get_btw(address):
	#BTW 73
	print "\tdidn't find a single explorer for bitcoin world (btw)"
	
def get_btf(address):
	#BTF 36
	print "\tdidn't find a single explorer for bitcoin faith (btf)"
		
def get_bcx(address):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = 75
		address_bcx = base58.b58encode_check(bytes(decoded))
		print "\t address " + address + " was converted to BCX address " + address_bcx	
		r = requests.get('https://bcx.info/insight-api/addr/%s/?noTxList=1' % address_bcx)
		if r.text != 'Invalid address: Address has mismatched network type.. Code:1':
			balance = r.json()['balance']
			return balance
		else :
			print "\tsomething went wrong while checking " + str(address) + " on the BCX chain"
			return 0
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BCX chain"
		return 0
			
def get_bch(address):
	try:
		r = requests.get('https://bitcoincash.blockexplorer.com/api/addr/%s/?noTxList=1' % address)
		balance = r.json()['balance']
		return balance
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BCH chain"
		return 0
			
def get_btx(address):
	try:
		r = requests.get('https://chainz.cryptoid.info/btx/api.dws?q=getbalance&a=%s' % address)
		return r.text
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BTX chain"
		return 0

def get_superbtc(address):
	#try:
	#	r = requests.get('http://block.superbtc.org/insight-api/addr/%s/?noTxList=1' % address)
	#	balance = r.json()['balance']
	#	if balance == 0:
	#		return 0
	#	return balance
	#except:
	#	print "something went wrong while checking " + str(address) + " on the SUPERBTC chain"
	#	return 0
	print "\tSUPERBTC api down, check manually at block.superbtc.org"
	
	
def get_b2x(address):
	try:
		r = requests.get('https://explorer.b2x-segwit.io/b2x-insight-api/addr/%s/?noTxList=1' % address)
		balance = r.json()['balance']
		return balance
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the B2X chain"
		return 0
	
def get_lbtc(address):
	print "\tLBTC api down, check manually at explorer.lbtc.io"

def get_btg(address):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = 38
		address_btg = base58.b58encode_check(bytes(decoded))
		print "\t address " + address + " was converted to BTG address " + address_btg
		r = requests.get('https://btgexplorer.com/api/addr/%s/?noTxList=1' % address_btg)
		balance = r.json()['balance']
		return balance
	except:
		print "\tsomething went wrong while checking " + str(address) + " on the BTG chain"
		return 0

if __name__ == '__main__':
	main()