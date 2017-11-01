#ifndef CLICK_ADVERTISER_HH
#define CLICK_ADVERTISER_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS

/*
 *	Click element that will handle and send advertisements
*/
class Advertiser : public Element {
	public:
		Advertiser();
		~Advertiser();

		const char *class_name() const	{ return "Advertiser"; }
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void run_timer(Timer* t);

	private:
		// Private methods
		void _generateAdvertisement();

		// Private attributes
		IPAddress _routerAddressPrivate; // The private router address
		IPAddress _routerAddressPublic;
		unsigned int _advertisementCounter;
		Timer _advertisementTimer;

};

CLICK_ENDDECLS
#endif
