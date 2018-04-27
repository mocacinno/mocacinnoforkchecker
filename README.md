**Introduction**  
I was searching for a tool to check my unspent outputs on all different altcoins that recently forked  from bitcoin at a certain heigh, and whose unspent outputs could be spent by using my private keys... I found several tools, like [https://github.com/foozzi/bitcoin-fork-checker](https://github.com/foozzi/bitcoin-fork-checker), but i found them either lacking basic functionality, unmaintained or lacking a lot of the current forks. This is why i decided to write my own script.  
  
**Prereqs**  
If you want to run the script, i recommend:  
  
 - Linux
 - python 2.7
 - pip
 - pip modules sys, argparse, requests, base58, time, urllib, urllib3, json, tqdm, signal and cfscrape
 - git
  
**How to install the script**  
  
 - git clone https://github.com/mocacinno/mocacinnoforkchecker
 - cd mocacinnoforkchecker
 - pip install argparse requests base58 urllib urllib3 json tqdm cfscrape
 - python checker.py --help
  
**How to run the binary on linux**  
  
 - visit the releases-page: https://github.com/mocacinno/mocacinnoforkchecker/releases
 - download the latest release AND detached signature file
 - check the signature
 - tar -xvf filename.tar.gz
 - ./checker --help
  
**Parameters**  
  
| parameter | mandatory?  | explanation |  
| ---- | ---- | ---- |  
| address | yes* | check one single address |  
| addressfile | yes* | check all addresses in this ascii file |  
| fork | no | only check this fork |  
| help | no | prints help about the parameters and exits |  
| maximumstatus | no | only check forks with a status <= this parameter |  
| outfile | no | print the output to this outfile |  
| secperrequest | no | number of seconds to wait for a reply from the fork's block explorer. This number must be bigger than the (optional) timeout |  
| showforks | no | show a list of supported forks and exit |  
| skipbtc | no | do not check for unspent outputs on the original bitcoin chain |  
| timeout | no | set the sleep() time to x seconds (default:3) |  
| verbose | no | write all output to stdout, disables the progress bar |  
  
\* either the address OR the addressfile parameter have to be used... This is the only mandatory parameter. If you use BOTH the address AND the addressfile, a union will be executed, duplicate lines will be checked twice  
   
 **examples**  
  
> python checker.py --address 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa  
  
check for unspent outputs on ALL supported chains, also print out which explorers need to be queried manually, and which coins don't have an explorer (but might still be worth something)  
>python checker.py --addressfile myaddresses.txt --timeout 6 --maximumstatus 1 --outfile log.log  
  
check all addresses found in the newline seperated ascii file myaddresses.txt (you can add comments by starting a line with #). The timeout between 2 queries needs to be 6 seconds, and only forks that can be checked 100% automatically need to be queried. The output needs to be written to the file log.log  
  
**Adding your own fork to the script**  
If you have your own fork, you can quickly fork this script, add your own parameters to it, then generate a pull request... Or you can take the lazy approach and create a ticket containing the following information:  
  
 1. The name of your coin
 2. The ticker symbol
 3. Where i can find the sourcecode
 4. Where i can find a block explorer that has a public api
 5. Where i can find an exchange that is listing your coin and has a public api
 6. Your project's homepage
  
In order to add your coin to the script yourself, just add 1 line to the available_forks-dictionary, and add a function at the bottom of the script (you can copy an existing function and adapt it to your situation). Basically, adding a coin is adding 4 or 5 lines to the script (pretty easy huh ;) )  
  
**warnings!**  
*Some of these coins don't have replay protection, some of these coins might only distribute binary wallets (or have open source wallets that weren't toroughly vetted by a competent community member). The first case can result in transactions being replaying on unintended chains, the second case can result in backdoors or bugs exposing your private keys to either the makers of the coin, or hackers exploiting the wallets... Always empty out your bitcoin wallet before attempting to import the private keys into wallets belonging to forked chains... Also try to claim the forks in order of importance (the most expensive forks first, the least expensive forks last)*  
  
**tipjar(s)**  
Since you can now claim a lot of coins on a lot of forks, you're in the ability to send me a tip (if you'd like)

| coin | address |  
| --- | --- |  
| BTC | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BTC (segwit) | 3NMoA9R6dNDxV3dmnRRFqC44cW1PaDg5hs |  
| BCH | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BPA | PVPnKB7MPGcnXcoaYvsGdzsZSodvJaXbzT |  
| WBTC | WjUe38UYAWxZFRK8zUs1NFmimtGu5GjTFi |  
| BTV | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BCI | iQH8bH7tkkPxxzMeheXFRtfY2WkFfigvu8 |  
| SBTC | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BICC | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BTX | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| B2X | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BCHC | 1MocACiWLM8bYn8pCrYjy6uHq4U3CkxLaa |  
| BCX | XY9r1M57astJtHbK3KXeLWKJ2tnnVUrZ2V |  
| BTG | GeeXaL3TKCjtdFS78oCrPsFBkEFt9fxuZF |  
| BCP | CdGVjF4aDQ78Sv3EtbsfYcXKTBgT5zQEX4 |  
| CDY | CdGVjF4aDQ78Sv3EtbsfYcXKTBgT5zQEX4 |  

