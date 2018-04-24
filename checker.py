import sys
import argparse
import requests
import base58
import time

def main():
	available_forks = {
		"B2X": get_b2x, 	#Bitcoin Segwit2X
		"BCH": get_bch, 	#Bitcoin Cash
		"BCX" : get_bcx, 	#BitcoinX
		"BPA" : get_bpa, 	#Bitcoin Pizza
		"BTG": get_btf, 	#Bitcoin Faith
		"BTG": get_btg, 	#bitcoin gold
		"BTW": get_btw, 	#Bitcoin World
		"BTX": get_btx, 	#Bitcore
		"LBTC": get_lbtc,	#Lightning Bitcoin
		"SUPERBTC": get_superbtc, 
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
	#BTF 73
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