#ifndef CLICK_ROUTINGELEMENT_HH
#define CLICK_ROUTINGELEMENT_HH
#include <click/element.hh>
#include <click/timer.hh>

// Local imports
#include "Advertiser.hh"
#include "structs/MobilityBinding.hh"
#include "structs/ICMPSolicitation.hh"
#include "structs/RegistrationRequest.hh"

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
*/
class RoutingElement : public Element {
	public:
		RoutingElement();
		~RoutingElement();

		const char *class_name() const	{ return "RoutingElement"; }
		const char *port_count() const	{ return "2/3"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		int initialize(ErrorHandler *);
		void run_timer(Timer* t);
		void push(int, Packet* p);

	private:
		// Timer which keeps the mobility bindings up to date
		Timer _mobilityTimer;

		// Public IPAddress of the agent
		IPAddress _agentAddressPublic;

		// Private IPAddress of the agent
		IPAddress _agentAddressPrivate;

		// Keep track of MN which are not home
		Vector<MobilityBinding> _mobilityBindings;

		// TODO Keep track of visitors on the current network (FA side)
		// Replace bool by something usefull
		Vector<bool> _visitors;

		// Reference to the advertiser element
		Advertiser* _advertiser;

		// Respond to an ICMP solicition message
		void _solicitationResponse(Packet* p);

		// Respond to a Mobile IP registration request.
		void _registrationRequestResponse(Packet* p);

		// Relay the Mobile IP registration reply to the MN.
		void _registrationReplyRelay(Packet* p);

		// Encapsulate the incoming IP packet in an outer IP header according RFC2003
		void _encapIPinIP(Packet* p, IPAddress coa);

		//  Generate a reply based on a specific request
		Packet* _generateReply(IPAddress, uint16_t, uint16_t, RegistrationRequest*, bool);

		// Find the care of address for the mobile node which is away
		// This information is stored in the mobilitybindings attribute
		IPAddress _findCareOfAddress(IPAddress mobileNode);

		// Create, update or delete MobilityBinding for the MN request
		// Bool indicates if it was a valid request
		// Return the IPAddress to which the reply must be sent
		IPAddress _updateMobilityBindings(MobilityBinding, bool);

		// Decreases all the lifetime field in the mobility bindings vector
		void _decreaseLifetimeMobilityBindings();

		// Check request and return various codes for the reply
		// Code 0 indicates that request was valid
		// For other codes we refer to RFC5944
		// The boolean parameter indicates if this agent is working like a HA or FA
		uint8_t _checkRequest(RegistrationRequest*, bool);

};

CLICK_ENDDECLS
#endif
