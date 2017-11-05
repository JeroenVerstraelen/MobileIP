#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "Monitor.hh"
#include "structs/RegistrationReply.hh"
#include "structs/ICMPAdvertisement.hh"

CLICK_DECLS
Monitor::Monitor(){}

Monitor::~ Monitor(){}

int Monitor::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0){
			return -1;
	}
	return 0;
}

void Monitor::push(int, Packet* p){
  click_chatter("Received a packet at the Mobile Node");
  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
