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
		int initialize(ErrorHandler *);
		void run_timer(Timer* t);

		// This method is called by the RoutingElement when the agent received a solicitation
		void respondToSolicitation();

	private:
		// Private methods
		void _generateAdvertisement();

		// Private attributes
		IPAddress _routerAddressPrivate; // The private router address
		IPAddress _routerAddressPublic;
		uint16_t _advertisementCounter;
		Timer _advertisementTimer;

};

CLICK_ENDDECLS
#endif
