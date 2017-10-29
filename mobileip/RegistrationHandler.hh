#ifndef CLICK_REGISTRATIONHANDLER_HH
#define CLICK_REGISTRATIONHANDLER_HH
#include <click/element.hh>
CLICK_DECLS

/*
 *	Click element that will handle registration requests at the agent side
 *	It will generate specific replies depending the current situation
*/
class RegistrationHandler : public Element {
	public:
		RegistrationHandler();
		~RegistrationHandler();

		const char *class_name() const	{ return "RegistrationHandler"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

	private:
		// Identification of packet
		atomic_uint32_t _id;
};

CLICK_ENDDECLS
#endif
