import sys
import argparse
import requests
import base58
import time

def main():
	available_forks = {"BCH": get_bch, "BTG": get_btg}
	parser = argparse.ArgumentParser()
	parser.add_argument("--address", help="query a single address")
	parser.add_argument("--addressfile", help="query all addresses in this file")
	parser.add_argument("--fork", help="query a single fork")
	parser.add_argument("--showforks", help="show all forks")
	parser.add_argument("--timout", help="number of seconds to wait between 2 requests", nargs='?', const=2, type=int)
	args = parser.parse_args()
	addresslist = []
	forklist = []
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
	
	if args.showforks:
		print available_forks
		sys.exit("")
	
	timeout = args.timeout
	for testaddress in addresslist:
		for testfork in forklist:
			func = forklist.get(testfork, lambda: "Wrong fork")
			balance = func(testaddress)
			if balance > 0:
				print testaddress + " has a balance of " + str(balance) + " on " + testfork
		time.sleep(timeout)	
	
def get_bch(address):
		try:
			r = requests.get('https://bitcoincash.blockexplorer.com/api/addr/%s/?noTxList=1' % address)
			balance = r.json()['balance']
			if balance == 0:
				return 0
			return balance
		except:
			print "something went wrong while checking " + str(address) + " on the BCH chain"
			return 0
			
def get_btg(address):
		try:
			decoded = base58.b58decode_check(address)
			decoded = bytearray(decoded)
			decoded[0] = 38
			address_btg = base58.b58encode_check(bytes(decoded))
			r = requests.get('https://btgexplorer.com/api/addr/%s/?noTxList=1' % address_btg)
			balance = r.json()['balance']
			if balance == 0:
				return 0
			return balance
		except:
			print "something went wrong while checking " + str(address) + " on the BTG chain"
			return 0

if __name__ == '__main__':
	main()