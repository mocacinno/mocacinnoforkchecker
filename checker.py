import sys
import argparse
import requests
import base58
import time
import urllib3
import json
from tqdm import *

def main():
	available_forks = {
		"ABTC": get_abtc, 				#A Bitcoin					#no explorer
		"B2X": get_b2x, 				#Bitcoin Segwit2X			#working
		"BBC": get_bbc, 				#Big Bitcoin				#no explorer
		"BCA": get_bca, 				#Bitcoin Atom				#manual	
		"BCB": get_bcb, 				#Bitcoin Boy				#no explorer
		"BCD": get_bcd, 				#Bitcoin Diamond			#manual	
		"BCH": get_bch, 				#Bitcoin Cash				#working
		"BCHC": get_bchc, 				#Bitcoin Clashic			#working
		"BCI": get_bci, 				#Bitcoin Intrest			#working
		"BCK": get_bck, 				#Bitcoin King				#no explorer
		"BCL": get_bcl, 				#Bitcoin Lunar				#no explorer
		"BCL2": get_bcl2, 				#Bitcoin Classic			#no explorer
		"BCM": get_bcm, 				#Bitcoin Master				#no explorer
		"BCO": get_bco, 				#Bitcoin Ore				#no explorer
		"BCP": get_bcp, 				#Bitcoin Cash Plus			#working
		"BCPC": get_bcpc, 				#Bitcoin Cash Plus			#no explorer
		"BCS": get_bcs, 				#Bitcoin Smart				#no explorer
		"BCS2": get_bcs2, 				#Bitcoin Sudu				#no explorer
		"BCW": get_bcw, 				#Bitcoin Wonder				#no explorer
		"BCX" : get_bcx, 				#BitcoinX					#working
		"BEC" : get_bec, 				#Bitcoin ECO				#no explorer
		"BICC" : get_bicc,				#BitClassic					#working
		"BIFI" : get_bifi,				#Bitcoin File				#no explorer
		"BITCOINMINOR" : get_bitcoinminor,	#Bitcoin Minor			#no explorer
		"BITE" : get_bite,				#BitEthereum				#no explorer
		"BNR" : get_bnr,				#Bitcoin Neuro				#no explorer
		"BPA" : get_bpa, 				#Bitcoin Pizza				#working
		"BTA" : get_bta,				#Bitcoin All				#no explorer
		"BTC" : get_btc,				#Bitcoin					#working
		"BTC2" : get_btc2,				#Bitcoin 2					#no explorer
		"BTCH" : get_btch,				#Bitcoin Hush				#should be fixable if src is released
		"BTCL" : get_btcl,				#Bitcoin Lite				#no explorer
		"BTCM" : get_btcm,				#Bitcoin Metal				#no explorer
		"BTCP" : get_btcp,				#Bitcoin platinum			#no explorer
		"BTCP2" : get_btcp2,			#Bitcoin Private			#no explorer
		"BTCS" : get_btcs,				#Bitcoin Stake				#no explorer
		"BTCTI" : get_btcti				#BitcoinTI  				#no explorer
		"BTCV" : get_btcv,				#Bitcoin Blvck				#no explorer
		"BTD" : get_btd,				#Bitcoin Dollar				#no explorer
		"BTF": get_btf, 				#Bitcoin Faith				#no explorer
		"BTG": get_btg, 				#Bitcoin Gold				#working
		"BTH": get_bth,					#Bitcoin Hot				#no explorer
		"BTN": get_btn,					#Bitcoin New				#no explorer
		"BTP": get_btp,					#Bitcoin Pay				#no explorer
		"BTP2": get_btp2,				#Bitcoin Pro				#manual
		"BTR": get_btr,					#Bitcoin Rhodium			#no explorer
		"BTSQ": get_btsq,				#Bitcoin Community			#no explorer
		"BTT": get_btt,					#Bitcoin Top				#no explorer
		"BTV": get_btv, 				#BitVote					#working
		"BTW": get_btw, 				#Bitcoin World				#no explorer
		"BTX": get_btx, 				#Bitcore					#working
		"BUM": get_bum, 				#Bitcoin Uranium			#no explorer
		"CDY": get_cdy, 				#Bitcoin Candy (for of BCH)	#working
		"FBTC": get_fbtc, 				#Bitcoin Fast				#no explorer
		"GOD": get_god, 				#Bitcoin God				#no explorer
		"LBTC": get_lbtc,				#Lightning Bitcoin			#manual
		"OBTC": get_obtc,				#Oil Bitcoin				#no explorer
		"NBTC": get_nbtc,				#New Bitcoin				#no explorer
		"QBTC": get_qbtc,				#Quantum Bitcoin			#no explorer
		"SUPERBTC": get_superbtc, 		#Super Bitcoin				#working
		"UBTC": get_ubtc, 				#United Bitcoin				#manual
		"WBTC": get_wbtc, 				#World Bitcoin				#working
	}
	parser = argparse.ArgumentParser()
	parser.add_argument("--address", help="query a single address")
	parser.add_argument("--addressfile", help="query all addresses in this file")
	parser.add_argument("--fork", help="query a single fork")
	parser.add_argument("--showforks", help="show all forks" , action='store_true')
	parser.add_argument("--verbose", help="show all tests while they are running" , action='store_true')
	parser.add_argument("--outfile", help="output to this file instead of stdout (screen)")
	parser.add_argument("--timeout", help="number of seconds to wait between 2 requests", nargs='?', const=2, type=int)
	args = parser.parse_args()
	global verbose
	if args.verbose:
		verbose = 1
	else:
		verbose = 0
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
	untested = []
	failed = []
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
	
	if not verbose:
		numberaddresses = len(addresslist)
		numberforks = len(forklist)
		product = numberaddresses * numberforks
		pbar = tqdm(total=product, unit='forks', ascii=True)
	for testaddress in addresslist:
		for testfork in forklist:
			if verbose:
				print "testing " + testaddress + " on " + testfork
			if not verbose:
				pbar.update(1)
			func = forklist.get(testfork, lambda: "Wrong fork")
			balance = func(testaddress)
			if balance == -1:
				untested.append("for some reason, address " + testaddress + " was not tested on " + testfork)
			if balance == -2:
				failed.append("for some reason, address " + testaddress + " failed to be tested on " + testfork)
			if balance > 0:
				successes.append(testaddress + " has a balance of " + str(balance) + " on " + testfork)
			time.sleep(timeout)
	if not verbose:
		pbar.close()
	if len(failed) > 0:
		print
		print "failed tests (usually because the api was down, or because the address wasnt found on the explorer)"
		print "************"
		for fail in failed:
			print fail
	if len(untested) > 0:
		print
		print "untested (usually because the coin was DOA, dead, dying or to new... Sometimes because the only block explorer didnt have an api)"
		print "************"
		for untest in untested:
			print untest
	if len(successes) > 0:
		print
		print
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
		print "[ERR] could not convert address " + address + " using prefix " + prefix
		return address

		
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
				if verbose:
					print stderror
				return -2
		else :
			if verbose:
				print stderror
			return -2
	except:
		if verbose:
			print stderror
		return -2
		
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
			if verbose:
				print stderror
			return -2
	except:
		if verbose:
			print stderror
		return -2

def fromchainz(address, baseurl, chain):
	try:
		r = requests.get(baseurl + 'api.dws?q=getbalance&a=%s' % address)
		stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
		try:
			val = float(r.text)
			return val
		except ValueError:
			if verbose:
				print stderror
			return -2
	except:
		if verbose:
			print stderror
		return -2
		
def fromiquidus(address, baseurl, chain):
	try:
		r = requests.get(baseurl + 'getbalance/%s' % address)
		stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
		try:
			val = float(r.text)
			return val
		except ValueError:
			if json.loads(r.text)['error'] == "address not found.":
				return -2
			if verbose:
				print stderror + " 1"
			return -2
	except:
		if verbose:
			print stderror + " 2"
		return -2
		
###############################################################################################
def get_btt(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin top (btt)"
	return -1
	
def get_btcl(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin lite (btcl)"
	return -1
	
def get_bttr(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin rhodium (btr)"
	return -1
	
def get_bite(address):
	if verbose:
		print "\tdidn't find a single explorer for bitethereum (bite)"
	return -1
	
def get_abtc(address):
	if verbose:
		print "\tdidn't find a single explorer for abitcoin (abtc)"
	return -1
	
def get_bcl2(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin classic (bcl)"
	return -1
	
def get_btcm(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin metal (btcm)"
	return -1
	
def get_bcl(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin lunar (bcl)"
	return -1
	
def get_bcm(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin master (bcm)"
	return -1
	
def get_btcti(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcointi (btcti)"
	return -1	
	
def get_bcs2(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin sudu (bcs)"
	return -1
	
def get_btd(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin dollar (btd)"
	return -1	
	
def get_btcp2(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin private (btcp)"
	return -1
	
def get_bbc(address):
	if verbose:
		print "\tdidn't find a single explorer for big bitcoin (bbc)"
	return -1

def get_btc2(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin 2 (btc2)"
	return -1	
	
def get_btcv(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin Blvck (btcv)"
	return -1
	
def get_bcpc(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin parallel (bcpc)"
	return -1
	
def get_bcs(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin smart (bcs)"
	return -1
	
def get_bcb(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin boy (bcb)"
	return -1

def get_bco(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin ore (bco)"
	return -1	
	
def get_bum(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin uranium (bum)"
	return -1
	
def get_nbtc(address):
	if verbose:
		print "\tdidn't find a single explorer for new bitcoin (nbtc)"
	return -1
	
def get_fbtc(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin fast (fbtc)"
	return -1

def get_god(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin god (god)"
	return -1

def get_bifi(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin file (bifi)"
	return -1

def get_bchc(address):
	chain = "BCHC"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi_urllib3(address, 'https://truevisionofsatoshi.com/api/', chain)	
	
def get_btc(address):	
	chain = "BTC"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return fromchainz(address, 'https://chainz.cryptoid.info/btc/', chain)		
		
def get_bci(address):
	chain = "BCI"
	address = veranderprefix(address, 102)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://explorer.bitcoininterest.io/api/', chain)	
	
def get_btch(address):
	chain = "BTCH"
	decoded = base58.b58decode_check(address)
	decoded = bytearray(decoded)
	decoded[0] = 127
	#sourcecode isn't available yet, but decoded[1] should be between 192 and 202
	decoded[1] = 192
	#decoded[1] = 202
	address = base58.b58encode_check(bytes(decoded))
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"
	return -1
	return frominsightapi(address, 'http://explorer.btchush.org/api/', chain)
	
def get_btv(address):
	chain = "BTV"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://block.bitvote.one/insight-api/', chain)
	
def get_btx(address):	
	chain = "BCX"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return fromchainz(address, 'https://chainz.cryptoid.info/btx/', chain)	
			
def get_bca(address):
	if verbose:
		print "\tno explorer with an api found, check manually on https://bitcoinatom.net/ (prefix 23)"
	return -1
	
def get_btp2(address):
	if verbose:
		print "\tno explorer with an api found, check manually on http://bitcoin-pool.de/explorer/BTP/ (prefix 23)"
	return -1
	
def get_ubtc(address):
	if verbose:
		print "\tno explorer with an api found, check manually on https://www.ub.com/explorer"
	return -1
		
def get_btsq(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin community (btsq) (prefix 63)"
	return -1

def get_obtc(address):
	if verbose:
		print "\tdidn't find a single explorer for oil bitcoin (obtc)"
	return -1
	
def get_qbtc(address):
	if verbose:
		print "\tdidn't find a single explorer for quantum bitcoin (qbtc)"	
	return -1

def get_btn(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin new (btn)"	
	return -1
	
def get_cdy(address):
	chain = "CDY"
	address = veranderprefix(address, 0x1c)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'http://block.cdy.one/insight-api/', chain)	
		
def get_bth(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin hot (bth) (prefix 40)"
	return -1
	
def get_bitcoinminor(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin minor (bitcoinminor)"
	return -1

def get_btp(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin pay (btp) (prefix 0x38)"
	return -1
	
def get_bta(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin all (bta)"
	return -1
	
def get_bnr(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin neuro (bnr)"
	return -1

def get_bpa(address):
	chain = "BPA"
	address = veranderprefix(address, 55)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return fromiquidus(address, 'http://47.100.55.227/ext/', chain)
	
def get_wbtc(address):
	chain = "WBTC"
	address = veranderprefix(address, 73)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"
	return fromiquidus(address, 'http://142.44.242.32:3001/ext/', chain)

def get_bicc(address):
	chain = "BICC"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return fromiquidus(address, 'http://18.216.251.169/ext/', chain)

def get_btw(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin world (btw) (prefix 73)"
	return -1
	
def get_btf(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin faith (btf) (prefix 36)"
	return -1

def get_btcp(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin platinum (btcp)"
	return -1

def get_btcs(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin stake (btcs)"
	return -1

def get_bck(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin king (bck)"
	return -1

def get_bcw(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin wonder (bcw)"
	return -1

def get_bec(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin eco (bec)"
	return -1
	
def get_bcx(address):
	chain = "BCX"
	address = veranderprefix(address, 75)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://bcx.info/insight-api/', chain)	
	
def get_bch(address):
	chain = "BCH"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://bitcoincash.blockexplorer.com/api/', chain)	
				
def get_superbtc(address):
	chain = "SUPERBTC"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'http://block.superbtc.org/insight-api/', chain)	

def get_bcp(address):
	chain = "BCP"
	address = veranderprefix(address, 28)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'http://www.bcpexp.org/api/', chain)	
	
def get_b2x(address):
	chain = "B2X"
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://explorer.b2x-segwit.io/b2x-insight-api/', chain)	
	
def get_lbtc(address):
	if verbose:
		print "\tLBTC api down, check manually at explorer.lbtc.io"
	return -1

def get_bcd(address):
	if verbose:
		print "\tLBTC api down, check manually at explorer.btcd.io"
	return -1
	
def get_btg(address):
	chain = "BTG"
	address = veranderprefix(address, 38)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://btgexplorer.com/api/', chain)	

###############################################################################################	

if __name__ == '__main__':
	main()