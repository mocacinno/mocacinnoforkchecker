import sys
import argparse
import requests
import base58
import time
import urllib3
import urllib
import json
from tqdm import *
import cfscrape
import signal

def main():
	global available_forks
	available_forks = [
	#0=working; 1=manual; 2=no explorer; 3= defenately dead
	{"ticker": "ABTC",	"function": get_abtc, 			"name": "A Bitcoin", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "B2X",	"function": get_b2x, 			"name": "Bitcoin Segwit2X", 			"status": 0, 	"CMC": "cmc:segwit2x", 			"explorer": "https://explorer.b2x-segwit.io" },
	{"ticker": "BBC",	"function": get_bbc, 			"name": "Big Bitcoin", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCA",	"function": get_bca, 			"name": "Bitcoin Atom", 				"status": 1, 	"CMC": "cmc:bitcoin-atom", 		"explorer": "https://bitcoinatom.net" },
	{"ticker": "BCH",	"function": get_bch, 			"name": "Bitcoin Cash", 				"status": 0, 	"CMC": "cmc:bitcoin-cash", 		"explorer": "https://bitcoincash.blockexplorer.com" },
	{"ticker": "BCB",	"function": get_bcb, 			"name": "Bitcoin Boy", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCD",	"function": get_bcd , 			"name": "Bitcoin Diamond", 				"status": 1, 	"CMC": "cmc:bitcoin-diamond",	"explorer": "http://explorer.btcd.io" },
	{"ticker": "BCHC",	"function": get_bchc, 			"name": "Bitcoin Clashic, also BCL",	"status": 0, 	"CMC": "bisq:bchc_btc", 		"explorer": "https://truevisionofsatoshi.com" },
	{"ticker": "BCI",	"function": get_bci, 			"name": "Bitcoin Intrest", 				"status": 0, 	"CMC": "tradesat:BCI_BTC",		"explorer": "https://explorer.bitcoininterest.io" },
	{"ticker": "BCK",	"function": get_bck, 			"name": "Bitcoin King", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCL",	"function": get_bcl, 			"name": "Bitcoin Lunar", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCM",	"function": get_bcm, 			"name": "Bitcoin Master", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCO",	"function": get_bco, 			"name": "Bitcoin Ore", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCP",	"function": get_bcp, 			"name": "Bitcoin Cash Plus", 			"status": 0, 	"CMC": "yobit:bcp_usd", 		"explorer": "http://www.bcpexp.org" },
	{"ticker": "BCPC",	"function": get_bcpc, 			"name": "Bitcoin Cash P", 				"status": 2,	"CMC": "", 						"explorer": "" },
	{"ticker": "BCS",	"function": get_bcs, 			"name": "Bitcoin Smart", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCS2",	"function": get_bcs2 , 			"name": "Bitcoin Sudu", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCW",	"function": get_bcw, 			"name": "Bitcoin Wonder", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BCX",	"function": get_bcx, 			"name": "BitcoinX", 					"status": 0, 	"CMC": "cmc:bitcoinx", 			"explorer": "https://bcx.info" },
	{"ticker": "BEC",	"function": get_bec, 			"name": "Bitcoin ECO", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BICC",	"function": get_bicc, 			"name": "BitClassic", 					"status": 0, 	"CMC": "topbtc:none", 			"explorer": "http://18.216.251.169" },
	{"ticker": "BIFI",	"function": get_bifi, 			"name": "Bitcoin File", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCMI",	"function": get_bitcoinminor, 	"name": "Bitcoin Minor", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BITE",	"function": get_bite, 			"name": "BitEthereum", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BNR",	"function": get_bnr, 			"name": "Bitcoin Neuro", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BPA",	"function": get_bpa, 			"name": "Bitcoin Pizza", 				"status": 0, 	"CMC": "hbtop:none", 			"explorer": "http://47.100.55.227" },
	{"ticker": "BTA",	"function": get_bta, 			"name": "Bitcoin All", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTC",	"function": get_btc, 			"name": "Bitcoin", 						"status": 0, 	"CMC": "cmc:bitcoin", 			"explorer": "http://www.blockchain.info" },
	{"ticker": "BTC2",	"function": get_btc2, 			"name": "Bitcoin 2", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCH",	"function": get_btch, 			"name": "Bitcoin Hush", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCL",	"function": get_btcl, 			"name": "Bitcoin Lite", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCM",	"function": get_btcm, 			"name": "Bitcoin Metal", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCP",	"function": get_btcp, 			"name": "Bitcoin platinum", 			"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCP2",	"function": get_btcp2, 			"name": "Bitcoin Private", 				"status": 2, 	"CMC": "cmc:bitcoin-private",	"explorer": "" },
	{"ticker": "BTCS",	"function": get_btcs, 			"name": "Bitcoin Stake", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCTI",	"function": get_btcti, 			"name": "BitcoinTI", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTCV",	"function": get_btcv, 			"name": "Bitcoin Blvck", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTD",	"function": get_btd, 			"name": "Bitcoin Dollar", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTF",	"function": get_btf, 			"name": "Bitcoin Faith", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTG",	"function": get_btg, 			"name": "Bitcoin Gold", 				"status": 0, 	"CMC": "cmc:bitcoin-gold", 		"explorer": "https://btgexplorer.com" },
	{"ticker": "BTH",	"function": get_bth, 			"name": "Bitcoin Hot", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTN",	"function": get_btn, 			"name": "Bitcoin New", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTP",	"function": get_btp, 			"name": "Bitcoin Pay", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTP2",	"function": get_btp2, 			"name": "Bitcoin Pro", 					"status": 1, 	"CMC": "", 						"explorer": "http://bitcoin-pool.de/explorer/BTP/" },
	{"ticker": "BTR",	"function": get_btr, 			"name": "Bitcoin Rhodium", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTSQ",	"function": get_btsq, 			"name": "Bitcoin Community", 			"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTT",	"function": get_btt,			"name": "Bitcoin Top", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTV",	"function": get_btv,			"name": "BitVote", 						"status": 0, 	"CMC": "yobit:btv_usd", 		"explorer": "https://block.bitvote.one" },
	{"ticker": "BTW",	"function": get_btw,			"name": "Bitcoin World", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "BTX",	"function": get_btx,			"name": "Bitcore", 						"status": 0, 	"CMC": "cmc:bitcore", 			"explorer": "https://chainz.cryptoid.info/btx/" },
	{"ticker": "BUM",	"function": get_bum,			"name": "Bitcoin Uranium", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "CDY",	"function": get_cdy,			"name": "Bitcoin Candy (fork of BCH)", 	"status": 0, 	"CMC": "coinex:CDYBCH",			"explorer": "http://block.cdy.one/" },
	{"ticker": "FBTC",	"function": get_fbtc,			"name": "Bitcoin Fast", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "GOD",	"function": get_god,			"name": "Bitcoin God", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "LBTC",	"function": get_lbtc,			"name": "Lightning Bitcoin", 			"status": 1, 	"CMC": "cmc:lightning-bitcoin", "explorer": "http://explorer.lbtc.io" },
	{"ticker": "OBTC",	"function": get_obtc,			"name": "Oil Bitcoin", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "NBTC",	"function": get_nbtc,			"name": "New Bitcoin", 					"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "QBTC",	"function": get_qbtc,			"name": "Quantum Bitcoin", 				"status": 2, 	"CMC": "", 						"explorer": "" },
	{"ticker": "SBTC",	"function": get_superbtc,		"name": "Super Bitcoin", 				"status": 0, 	"CMC": "cmc:super-bitcoin",		"explorer": "http://block.superbtc.org" },
	{"ticker": "UBTC",	"function": get_ubtc,			"name": "United Bitcoin	", 				"status": 1, 	"CMC": "", 						"explorer": "https://www.ub.com/explorer" },
	{"ticker": "WBTC",	"function": get_wbtc,			"name": "World Bitcoin", 				"status": 0, 	"CMC": "tradesat:WBTC_BTC",		"explorer": "http://142.44.242.32:3001" },
	]
	
	global coinmarketcapdb
	try:
		url = "https://api.coinmarketcap.com/v1/ticker/?limit=10000"
		response = urllib.urlopen(url)
		coinmarketcapdb = json.loads(response.read())
	except:
		print "problem loading the tickers from coinmarketcap"
	
	global yobitdb
	try:
		loadyobit()
	except:
		print "problem loading the tickers from yobit"
	
	global bisqdb
	try:
		url = "https://markets.bisq.network/api/ticker"
		response = urllib.urlopen(url)
		bisqdb = json.loads(response.read())
	except:
		print "problem loading the tickers from bisq"
	
	global tradesatoshidb
	try:
		url = "https://tradesatoshi.com/api/public/getmarketsummaries"
		response = urllib.urlopen(url)
		scraper = cfscrape.create_scraper()
		response = scraper.get(url).content
		tradesatoshidb = json.loads(response)
		tradesatoshidb = tradesatoshidb['result']
	except:
		print "problem loading the tickers from tradesatoshi"
		
	global coinexdb
	try:
		url = "https://api.coinex.com/v1/market/ticker/all"
		response = urllib.urlopen(url)
		coinexdb = json.loads(response.read())
		coinexdb = coinexdb['data']['ticker']
	except:
		print "problem loading the tickers from coinexdb"
		
	global grandtotal
	grandtotal = float(0)
	
	global bitcoinprice
	try:
		bitcoinprice = float(getbitcoinprice())
		print "current BTC price in USD according to coinmarketcap: $" + str(bitcoinprice)
	except:
		bitcoinprice = float(9000)
		print "i was unable to load the BTC price, so i took the estimation of the end of may 2018: $9000/BTC"
		
	global bitcoincashprice
	try:
		bitcoincashprice = float(getbitcoincashprice())
		print "current BCH price in USD according to coinmarketcap: $" + str(bitcoincashprice)
	except:
		bitcoincashprice = float(1000)
		print "i was unable to load the BCH price, so i took the estimation of the end of may 2018: $1000/BCH"
	
	parser = argparse.ArgumentParser()
	parser.add_argument("--address", help="query a single address")
	parser.add_argument("--addressfile", help="query all addresses in this file")
	parser.add_argument("--fork", help="query a single fork")
	parser.add_argument("--showforks", help="show all forks" , action='store_true')
	parser.add_argument("--verbose", help="show all tests while they are running" , action='store_true')
	parser.add_argument("--outfile", help="output to this file instead of stdout (screen)")
	parser.add_argument("--timeout", help="number of seconds to wait between 2 requests", nargs='?', const=2, type=int)
	parser.add_argument("--secperrequest", help="if a fork check doesn't return an answer for this many seconds, skip the fork", nargs='?', const=30, type=int)
	parser.add_argument("--maximumstatus", help="maximumstatus 1 = only check chains that can be checked automatically; maximumstatus 2 = also print chains that have to checked manually: minmimstatus 3 = also print out chains that cannot be checked because they are dead or the absense of an explorer", type=int)
	parser.add_argument("--skipbtc", help="don't check for unspent outputs on the BTC (original) chain", action='store_true')
	args = parser.parse_args()
	global verbose
	if args.verbose:
		verbose = 1
	else:
		verbose = 0
	if args.outfile:
		file = open(args.outfile, "w")
		file.write("if you like this project, consider some of the \"free\" coins you got from these forks to me ;)\nBTC/BCH/BTX/B2X/...: 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa\nBTG: GeeXaL3TKCjtdFS78oCrPsFBkEFt9fxuZF\n\n")
		file.close()

	if args.showforks:
		print "available forks:"
		print "****************"
		for printfork in available_forks:
			print printfork['ticker'] + "\tstatus: " + str(printfork['status'] + 1) + "\tfull name: " + str(printfork['name']) + "\t\texplorer: " + str(printfork['explorer'])
		sys.exit("")
	signal.signal(signal.SIGALRM, handler)
	addresslist = []
	forklist = {}
	successes = []
	untested = []
	failed = []
	if args.address:
		addresslist.append(args.address)
	if args.addressfile:
		with open(args.addressfile) as file:
			for address in file:
				firstletter = address[:1]
				secondletter = address[:2]
				if firstletter == "1" or firstletter == "3" or firstletter == "b":
					addresslist.append(address.rstrip())
	if len(addresslist) == 0:
		sys.exit("no addresses available")
	else:
		print "testing " + str(len(addresslist)) + " addresses for unspent outputs"
	if args.maximumstatus:
		maximumstatus = args.maximumstatus
	else:
		maximumstatus = 4
	if args.secperrequest:
		secperrequest = args.secperrequest
	else:
		secperrequest = 30
	if args.fork:
		for currentfork in available_forks: 
			if currentfork['ticker'] == args.fork:
				if args.skipbtc and currentfork['ticker'] == "BTC":
					print "didnt add BTC to the list of forks to check, since it was disabled by parameter skipbtc"
				else:
					forklist = {currentfork['ticker']:currentfork['function']}
	else:
		for currentfork in available_forks: 
			if currentfork['status'] < maximumstatus:
				forklist.update({currentfork['ticker']:currentfork['function']})
		
	if len(forklist) == 0:
		sys.exit("no forks to check")
	else:
		print "testing " + str(len(forklist)) + " chains for unspent outputs"
	if args.timeout:
		timeout = args.timeout
	else:
		timeout = 3
	
	if not verbose:
		numberaddresses = len(addresslist)
		numberforks = len(forklist)
		product = numberaddresses * numberforks
		pbar = tqdm(total=product, unit='forks', ascii=True)
	for testaddress in addresslist:
		for testfork in forklist:
			signal.alarm(secperrequest)
			if verbose:
				print "testing " + testaddress + " on " + testfork
			if not verbose:
				pbar.update(1)
			try:
				func = forklist.get(testfork, lambda: "Wrong fork")
				balance = func(testaddress)
			except:
				print "[ERROR] while testing " + testaddress + " on " + testfork
				balance = -2
			if balance == -1:
				untested.append("for some reason, address " + testaddress + " was not tested on " + testfork)
			if balance == -2:
				failed.append("for some reason, address " + testaddress + " failed to be tested on " + testfork)
			if balance > 0:
				try:
					price = trypricefetch(testfork, balance)
				except:
					price = " something went wrong while fetching the FIAT price"
				successes.append(testaddress + " has a balance of " + str(balance) + " on " + testfork + " " + str(price))
				
				if args.outfile:
					file = open(args.outfile, "a")
					file.write("[SUCCESS] " + testaddress + " has a balance of " + str(balance) + " on " + testfork + " " + price + "\n")
					file.close()
			time.sleep(timeout)
			signal.alarm(0)
	if not verbose:
		pbar.close()
	if len(failed) > 0:
		print
		print "failed tests (usually because the api was down, or because the address wasnt found on the explorer)"
		print "************"
		for fail in failed:
			print fail
		if args.outfile:
			file = open(args.outfile, "a")
			file.write("\nfailed tests (usually because the api was down, or because the address wasnt found on the explorer)\n************\n")
			file.close()
			for fail in failed:
				file = open(args.outfile, "a")
				file.write(fail + "\n") 
				file.close()
	if len(untested) > 0:
		print
		print "untested (usually because the coin was DOA, dead, dying or to new... Sometimes because the only block explorer didnt have an api)"
		print "************"
		for untest in untested:
			print untest
		if args.outfile:
			file = open(args.outfile, "a")
			file.write("\nuntested (usually because the coin was DOA, dead, dying or to new... Sometimes because the only block explorer didnt have an api)\n************\n")
			file.close()
			for untest in untested:
				file = open(args.outfile, "a")
				file.write(untest + "\n") 
				file.close()
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
		if args.outfile:
			file = open(args.outfile, "a")
			file.write("\n\n\n**************************************************\n* found unspent outputs on one or more chains!!! *\n* claim at your own risk!                        *\n**************************************************\n\nsuccesslist\n***********\n")
			file.close()
			for success in successes:
				file = open(args.outfile, "a")
				file.write(success + "\n") 
				file.close()
			file = open(args.outfile, "a")
			file.write("\n\n-------------------------------------------------------------------------------------------\n| once again, if you import your private key into ANY unknown/untrusted wallet,           |\n| you risk losing your unspent outputs on all other chains!!!                             |\n| proceed with caution                                                                    |\n|*****************************************************************************************|\n| at least make sure your wallets on the most important chains are empty before importing |\n| their private keys into unknown wallets!!!                                              |\n-------------------------------------------------------------------------------------------\n\nif you like this project, consider some of the \"free\" coins you got from these forks to me ;)\nBTC/BCH/BTX/B2X/...: 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa\nBTG: GeeXaL3TKCjtdFS78oCrPsFBkEFt9fxuZF\n\n")
			file.close()
	
	print "if you would exchange all coins right now, you'd make a whopping $" + str(grandtotal) 
	if args.outfile:
		file = open(args.outfile, "a")
		file.write("if you would exchange all coins right now, you'd make a whopping $" + str(grandtotal) + "\n")
		file.close()
		
###############################################################################################	
def loadyobit():
	global yobitdb
	try:
		parameters = ""
		eerste = 0
		for currenttestfork in available_forks:
			cmc = currenttestfork['CMC']
			if len(cmc) > 2:
				split = cmc.split(":")
				cmc = split[1]
				type = split[0]
				if type == "yobit":
					if eerste == 0:
						eerste = 1
						parameters = cmc
					else:
						parameters = parameters + "-" + cmc
		url = "https://yobit.net/api/3/ticker/" + parameters
		scraper = cfscrape.create_scraper()
		response = scraper.get(url).content
		yobitdb = json.loads(response)
	except:
		print "yobit api could not be reached"

def getbitcoinprice():
	try:
		for coinmarketlisting in coinmarketcapdb:
				if coinmarketlisting['id'] == 'bitcoin':
					return coinmarketlisting['price_usd']
	except:
		print "bitcoinprice could not be fetched from coinmarketcap"
		
def getbitcoincashprice():
	try:
		for coinmarketlisting in coinmarketcapdb:
				if coinmarketlisting['id'] == 'bitcoin-cash':
					return coinmarketlisting['price_usd']
	except:
		print "bitcoin cash price could not be fetched from coinmarketcap"

def handler(signum, frame):
    print 'Signal handler called with signal', signum
	
def trypricefetch(testfork, balance):
	global grandtotal
	cmc = ""
	type = ""
	price = ". There is no linkt to coinmarketcap or any other exchange, so we can't find the price"
	for currenttestfork in available_forks:
		if currenttestfork['ticker'] == testfork and len(currenttestfork['CMC']) > 2:
			cmc = currenttestfork['CMC']
			split = cmc.split(":")
			cmc = split[1]
			type = split[0]
	if type == "cmc" :
		for coinmarketlisting in coinmarketcapdb:
			if cmc == coinmarketlisting['id']:
				prijspercoin = coinmarketlisting['price_usd']
				totaal = float(prijspercoin) * float(balance)
				grandtotal = grandtotal + totaal
				price = ". Coinmarketcap says this balance of " + str(balance) + str(testfork) + " is worth $" + str(prijspercoin) + " per coin. In your case this comes down to " + str(totaal) + "USD"
	if type == "yobit":
		for yobitlistingticker, yobitlistinginfo in yobitdb.items():
			if cmc == yobitlistingticker:
				prijspercoin = yobitlistinginfo['avg']
				totaal = float(prijspercoin) * float(balance)
				grandtotal = grandtotal + totaal
				price = ". Yobit says this balance of " + str(balance) + str(testfork) + " is worth $" + str(prijspercoin) + " per coin. In your case this comes down to " + str(totaal) + "USD"
	if type == "bisq":
		for bisqlistingticker, bisqlistinginfo in bisqdb.items():
			if cmc == bisqlistingticker:
				prijspercoin = bisqlistinginfo['last']
				totaal = float(prijspercoin) * float(balance)
				grandtotal = grandtotal + totaal
				price = ". Bisq says this balance of " + str(balance) + str(testfork) + " is worth $" + str(prijspercoin) + " per coin. In your case this comes down to " + str(totaal) + "USD"
	if type == "tradesat":
		for tradesatoshilisting in tradesatoshidb:
			if cmc == tradesatoshilisting['market']:
				btcprijspercoin = tradesatoshilisting['last']
				prijspercoin = float(btcprijspercoin) * bitcoinprice
				totaal = prijspercoin * float(balance)
				grandtotal = grandtotal + totaal
				price = ". Tradesatoshi says this balance of " + str(balance) + str(testfork) + " is worth $" + str(prijspercoin) + " per coin. In your case this comes down to " + str(totaal) + "USD"
	if type == "coinex":
		for coinexticker, coinexlisting in coinexdb.items():
			if cmc == coinexticker:
				bchprijspercoin = coinexlisting['last']
				prijspercoin = float(bchprijspercoin) * bitcoincashprice
				totaal = prijspercoin * float(balance)
				grandtotal = grandtotal + totaal
				price = ". coinex says this balance of " + str(balance) + str(testfork) + " is worth $" + str(prijspercoin) + " per coin. In your case this comes down to " + str(totaal) + "USD"
	return price

def veranderprefix(address, prefix):
	try:
		decoded = base58.b58decode_check(address)
		decoded = bytearray(decoded)
		decoded[0] = prefix
		newaddress = base58.b58encode_check(bytes(decoded))
		return newaddress
	except:
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
	stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
	try:
		r = requests.get(baseurl + 'api.dws?q=getbalance&a=%s' % address)
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
	stderror = "\t something went wrong while querying the api for address " + address + " on the " + chain + " chain, using the insight api on " + baseurl
	try:
		r = requests.get(baseurl + 'getbalance/%s' % address)
		
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
	
def get_btr(address):
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
	
def get_btch(address):
	if verbose:
		print "\tdidn't find a single explorer for bitcoin hush (btch)"
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
	return frominsightapi(address, 'https://insight.bitpay.com/api/', chain)		
		
def get_bci(address):
	chain = "BCI"
	address = veranderprefix(address, 102)
	if verbose:
		print "\t checking address " + address + " on the " + chain + " chain"	
	return frominsightapi(address, 'https://explorer.bitcoininterest.io/api/', chain)	
	
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
