# Project
Implementation of annotated RFC 5944 in the Click Modular Router environment.
For more information you can look in the resources folder which contains summaries for all the necessary RFC's.
The src/library folder contains all the Click scripts.

# MobileIP
![mobileip](https://photos1.blogger.com/blogger/5119/2878/1600/MobileIP-e.gif)


## How to run our code
The assignment includes a Virtual Machine on which we can test our code.
To run our code you need to do the following:
  1. In the folder "click/elements/local" you need to paste the mobileip folder from our repository
  (or an alias to this folder)
  2. In the folder click/scripts/ you need to replace the provided library folder with the library folder from our repository

Navigate to the click/scripts folder and execute the following commands:
  1. sudo ./setup.sh (only for the initial setup)
  2. cd ../; make elemlist; make -j2; cd scripts/; sudo ./start_click.sh

The start_click script contains the following commands:
	../userlevel/click glue.click -p 10000 & 	# Run the glue that connects the elements
	../userlevel/click mn.click -p 10001 &		# Run the MN 
	../userlevel/click ha.click -p 10002 &		# Run the HA
	../userlevel/click fa.click -p 10003 &		# Run the FA
	../userlevel/click cn.click -p 10004		# Run the CN (Corresponding node)


##  Interaction with the reference implementation 
It is possible to combine our elements (HA,FA or MN) with those of the reference implementation.
This combination allows us to test our timing and error handling. 
For more information look at the misc/VM_Howto.pdf file

## The available handlers 
For more information on these handlers please read the misc/VM_howto.pdf file.
These handlers are mentioned below for easy copy-pasting purposes.

### Mobile node (MN)
#### General
	write mobile_node/mobile_node.force_lifetime true
	write mobile_node/mobile_node.force_lifetime false

#### AgentSolicitationSender
	write mobile_node/AgentSolicitationSender@17.code [Integer]
	write mobile_node/AgentSolicitationSender@17.interval [Integer]
	write mobile_node/AgentSolicitationSender@17.invalid_checksum true
	write mobile_node/AgentSolicitationSender@17.invalid_checksum false
	write mobile_node/AgentSolicitationSender@17.length [Integer]
	write mobile_node/AgentSolicitationSender@17.sending true
	write mobile_node/AgentSolicitationSender@17.sending false

### Home agent (HA)
#### Advertisements 
	write home_agent/adv.code [Integer]
	write home_agent/adv.invalid_checksum true
	write home_agent/adv.invalid_checksum false
	write home_agent/adv.sending true
	write home_agent/adv.sending false

#### Mobility
	write home_agent/mobility.invalid_checksum true
	write home_agent/mobility.invalid_checksum false
	write home_agent/mobility.id true
	write home_agent/mobility.id false
	write home_agent/mobility.node true
	write home_agent/mobility.node false
	write home_agent/mobility.port true
	write home_agent/mobility.port false
	write home_agent/mobility.sending true
	write home_agent/mobility.sending false
	write home_agent/mobility.zero_checksum true
	write home_agent/mobility.zero_checksum false

### Foreign agent (FA)
#### Advertisements 
	write foreign_agent/adv.code [Integer]
	write foreign_agent/adv.invalid_checksum true
	write foreign_agent/adv.invalid_checksum false
	write foreign_agent/adv.sending true
	write foreign_agent/adv.sending false

#### Visitors
	write foreign_agent/visitors.invalid_checksum true
	write foreign_agent/visitors.invalid_checksum false
	write foreign_agent/visitors.id true
	write foreign_agent/visitors.id false
	write foreign_agent/visitors.port true
	write foreign_agent/visitors.port false
	write foreign_agent/visitors.sending true
	write foreign_agent/visitors.sending false
	write foreign_agent/visitors.zero_checksum true
	write foreign_agent/visitors.zero_checksum false






