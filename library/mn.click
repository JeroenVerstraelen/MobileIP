// Mobile Node
// The input/output configuration is as follows:
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

// Input:
//	[0]: packets received from the network
//
// Output:
//	[0]: packets sent to the network
//	[1]: packets destined for the host itself


elementclass MobileNode {
	$address, $gateway, $home_agent |

	// Generates ICMP solicitation messages and send them on the local network
	solicitationGenerator :: Solicitor(SRC $address);
	solicitationGenerator -> EtherEncap(0x0800, SRC $address, DST ff:ff:ff:ff:ff:ff) -> output;

	// Generates registration requests and send them 
	// TODO maybe also handle incoming replies here OR provide a new global element that coordinates the MN?
	requestGenerator :: RequestGenerator(SRC $address, HA $home_agent);
 	requestGenerator -> EtherEncap(0x0800, SRC $address, DST $gateway) -> [0]output; //TODO verify ethernet DST

	// Shared IP input path
	ip :: Strip(14)
		-> CheckIPHeader
		-> rt :: LinearIPLookup(
			$address:ip/32 0,
			$address:ipnet 1,
			0.0.0.0/0 $gateway 1)
		-> [1]output;

	rt[1]	-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1]	-> ICMPError($address, parameterproblem)
		-> output;

	ttl[1]	-> ICMPError($address, timeexceeded)
		-> output;

	frag[1]	-> ICMPError($address, unreachable, needfrag)
		-> output;

	// incoming packets
	input	-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;

	in_cl[2]
		-> ip;
}
