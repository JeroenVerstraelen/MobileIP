#ifndef CLICK_SOLICITOR_HH
#define CLICK_SOLICITOR_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS

/*
 * Click element that generates solicitation messages at the mobile node.
*/
class Solicitor : public Element {
	public:
		Solicitor();
		~Solicitor();

		const char *class_name() const	{ return "Solicitor"; }
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void _generateSolicitation();
		void run_timer(Timer* t);

	private:
		// The source address
		IPAddress _srcAddress;
		Timer _solicitationTimer;
};

CLICK_ENDDECLS
#endif
