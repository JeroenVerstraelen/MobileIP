#ifndef CLICK_ROUTINGELEMENT_HH
#define CLICK_ROUTINGELEMENT_HH
#include <click/element.hh>

// Local imports
#include "Advertiser.hh"
#include "structs/MobilityBinding.hh"
#include "structs/ICMPSolicitation.hh"


CLICK_DECLS
/*
 *	Click element that will:
 *	- function like a routing element for the agent
 *	- handle incoming messages like the ICMP solicitations message
 *	- handle the registration request message at the agent side
 *	- generate specific replies depending the current situation
 *	Input 0 ==> directed messages to the agent itself
 * 	Input 1 ==> messages from the CN
 * 	Output 0 ==> packets to private network
 *	Output 1 ==> packets to the public network
 * 	Output 2 ==> packets to the agent itself
 *  Output 3 ==> reply to public network without setting UDP checksum
 *	Output 4 ==> reply to private network without setting UDP checksum
*/
class RoutingElement : public Element {
	public:
		RoutingElement();
		~RoutingElement();

		const char *class_name() const	{ return "RoutingElement"; }
		const char *port_count() const	{ return "2/5"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		void push(int, Packet* p);

	private:
		// Public IPAddress of the agent
		IPAddress _agentAddressPublic;

		// Private IPAddress of the agent
		IPAddress _agentAddressPrivate;

		// Keep track of MN which are not home
		Vector<MobilityBinding> _mobilityBindings;

		// Reference to the advertiser element
		Advertiser* _advertiser;

		// Respond to an ICMP solicition message
		void _solicitationResponse(Packet* p);

		// Respond to a Mobile IP registration request. 
		void _registrationRequestResponse(Packet* p);

		// Respond to a Mobile IP registration reply.
		void _registrationReplyResponse(Packet* p);

		// Encapsulate the incoming IP packet in an outer IP header according RFC2003
		void _encapIPinIP(Packet* p, IPAddress coa);

		//  Generate a reply based on a specific request
		Packet* _generateReply(IPAddress, IPAddress, IPAddress, uint32_t, uint16_t, uint16_t, uint16_t);

		// Find the care of address for the mobile node which is away
		// This information is stored in the mobilitybindings attribute
		IPAddress _findCareOfAddress(IPAddress mobileNode);

		// Create, update or delete MobilityBinding for the MN request
		// Return the IPAddress to which the reply must be sent
		IPAddress _updateMobilityBindings(MobilityBinding data);
};

CLICK_ENDDECLS
#endif
