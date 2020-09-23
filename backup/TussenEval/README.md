# MobileIP
Implementation of annotated RFC 5944 in the Click Modular Router environment.

## How to run our code
The assignment included a Virtual Machine on which we can test our code.
To run our code you need to do the following:
  1. In the folder "click/elements/local" you need to paste the mobileip folder from our repository
  (or an alias to this folder)
  2. In the folder click/scripts/ you need to replace the provided library folder with the library folder from our repository

Navigate to the click/scripts folder and execute the following commands:
  1. sudo ./setup.sh (only for the initial setup)
  2. cd ../; make elemlist; make -j2; cd scripts/; sudo ./start_click.sh

##  Implemented
* Tunneling of packets
* MobileIP registration request and replies 
* ICMP Agent Advertisement and Agent Solicitation
* Mobile Node can detect what network he is on (rudimentary)
