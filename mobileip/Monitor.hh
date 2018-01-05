#ifndef CLICK_MONITOR_HH
#define CLICK_MONITOR_HH
#include <click/element.hh>

// Local imports
#include "RequestGenerator.hh"
#include "Solicitor.hh"
#include "structs/ICMPRouterEntry.hh"
#include <map>

CLICK_DECLS

/*
 *	Click element that will monitor for the mobile node
 *	It will receive incoming ICMP advertisement and handle them
 *	It will receive registration replies and if necessary send a new registration through the RequestGenerator class
*/
class Monitor : public Element {
	public:
		Monitor();
		~Monitor();

		const char *class_name() const	{ return "Monitor"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
    	void push(int, Packet* p);

		// Method to return if the MN is at home or not
		bool isHome(){ return _atHome; }

	private:
		// Keep track of the sequence numbers of the advertisements
		uint16_t _currentSequenceNumber;

		// The IP address of the MN
		IPAddress _ipAddress;

		// The IP address of the home agent, discovered using ICMP
		//IPAddress _homeAgent = NULL;

		// The request generator of the MN
		RequestGenerator* _reqGenerator;

		// The solicitation generator of the MN
		Solicitor* _solicitor;

		// Boolean value which keeps track if MN is at home
		bool _atHome;

		void _handleAdvertisement(Packet* p);
		void _handleRegistrationReply(Packet* p);
		bool _updateSequenceNumber(unsigned int);
};

CLICK_ENDDECLS
#endif
