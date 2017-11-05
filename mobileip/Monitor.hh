#ifndef CLICK_MONITOR_HH
#define CLICK_MONITOR_HH
#include <click/element.hh>
CLICK_DECLS

/*
 *	Click element that will monitor for the mobile node
 *  It will receive incoming ICMP advertisement and handle them
 *  It will receive registration replies and if necessary send a new registration through the RequestGenerator class
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

	private:
		// temporary
    uint temp;
};

CLICK_ENDDECLS
#endif
