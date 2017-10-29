#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "RegistrationHandler.hh"

CLICK_DECLS
RegistrationHandler::RegistrationHandler(){}

RegistrationHandler::~ RegistrationHandler(){}

int RegistrationHandler::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0){
			return -1;
	}
	return 0;
}
CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationHandler)
