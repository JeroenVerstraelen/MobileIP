#ifndef CLICK_ETHERCHECK_HH
#define CLICK_ETHERCHECK_HH
#include <click/element.hh>
#include <click/timer.hh>

// Local imports
#include "utils/HelperFunctions.hh"

CLICK_DECLS

/*
 *	Click element that keep track of the ethernet address of the incoming advertisements
 *  Input 1 is just the normal flow of the messages through the MN
 *	Output 0 is for all none ping related messages
 *	Output 1 is used for ICMP ping replies
*/
class EtherCheck : public Element {
	public:
		EtherCheck();
		~EtherCheck();

		const char *class_name() const	{ return "EtherCheck"; }
		const char *port_count() const	{ return "1/2"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		void push(int, Packet* p);

	private:
		uint8_t etherDest[6];

};

CLICK_ENDDECLS
#endif
