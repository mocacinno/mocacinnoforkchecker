# mocacinnoforkchecker  
i got the idear from foozzi/bitcoin-fork-checker and also used part of his functions  
  
reqs: python 2.7 with modules sys, argparse, requests, time and base58  
  
usage  
python checker.py --address THEADDRESSYOUWANTTOTEST --addressfile FILEWITHNEWLINESEPERATOR --fork ONLYTESTTHISFORK --showforks --timeout secs  
address : 1 address you want to test  
addresfile : a file with multiple addresses you want to test  
fork : only test this fork  
showforks: show a list of available forks and exit  
timeout: timeout between 2 requests... In order not to overload the used api's  
  
You need to test at least 1 address, so either address or addressfile is obligatory. If both address and addressfile are used, a union is taken and all addresses are tested. Duplicate addresses are NOT removed!!!  
The fork parameter is mandatory... If it is not used, ALL available forks are tested  
The showforks parameter is mandatory, don't use it if you want to execute a real test  
The timeout parameter is mandatory and defaults to 2 seconds  

  
  
  
  
  
sources:  
https://github.com/mocacinno/bitcoin_fork_claimer/ => extra forks  
https://github.com/foozzi/bitcoin-fork-checker => basic idear  
https://bitcointalk.org/index.php?topic=2749969.0 => extra forks  
  
version 0.1:  
Initial working beta
