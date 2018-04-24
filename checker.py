import sys
import argparse
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--address", help="query a single address")
	parser.add_argument("--addressfile", help="query all addresses in this file")
	parser.add_argument("--fork", help="query a single fork")
	parser.add_argument("--showforks", help="show all forks")
	args = parser.parse_args()
	addresslist = []
	forklist = []
	if args.address:
		addresslist.append(args.address)
	if args.addressfile:
		with open(args.addressfile) as file:
			for address in file:
				addresslist.append(address)
	if len(addresslist) == 0:
		sys.exit("no addresses available")
	

if __name__ == '__main__':
	main()