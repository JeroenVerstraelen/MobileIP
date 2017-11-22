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
#include "structs/MobilityAgentAdvertisementExtension.hh"

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
	const click_ip* iph = p->ip_header();
	IPAddress destIP = iph->ip_dst;
	// handle advertisements
	if (destIP == IPAddress("255.255.255.255")){
		p->pull(sizeof(click_ip));
	  click_chatter("Received a packet at the Mobile Node with dest 255.255.255.255, length %d", p->length());
		ICMPAdvertisement* advertisement = (ICMPAdvertisement *) p->data();
		MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension *) (p->data() + sizeof(ICMPAdvertisement));
		if (advertisement->type == 9){
			// TODO handle advertisement here
			_possibleAgents.push_back(IPAddress(advertisement->routerAddress));
		}
		click_chatter("done");
	} if (destIP == _ipAddress.in_addr() and iph->ip_p == 17){
		// TODO handle incoming reply here
	}
  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
