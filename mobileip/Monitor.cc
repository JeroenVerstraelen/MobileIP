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
#include "utils/Configurables.hh"

CLICK_DECLS
Monitor::Monitor(){}

Monitor::~ Monitor(){}

int Monitor::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_ipAddress, "REQUESTGENERATOR", cpkM, (RequestGenerator*) cpElement, &_reqGenerator, cpEnd) < 0){
			return -1;
	}
	this->_homeNetwork = _ipAddress.unparse().substring(0, 9);
	return 0;
}

void Monitor::push(int, Packet* p){
	const click_ip* iph = p->ip_header();
	IPAddress destIP = iph->ip_dst;
	// handle advertisements
	if (destIP == broadCast){
		IPAddress srcIP = iph->ip_src;
		click_chatter("%s = ip src address of incoming advertisement", srcIP.unparse().c_str());
		//click_chatter("%s test ", srcIP.unparse().substring(0,9).c_str());
		p->pull(sizeof(click_ip));
	  click_chatter("Received a packet at the Mobile Node with dest 255.255.255.255, length %d", p->length());
		ICMPAdvertisement* advertisement = (ICMPAdvertisement *) p->data();
		MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension *) (p->data() + sizeof(ICMPAdvertisement));
		if (advertisement->type == 9){
			// TODO handle advertisement here
			_possibleAgents.push_back(IPAddress(advertisement->routerAddress));
		}
		// TODO provide better pattern matching (string comparison untill the third .)
		if (!srcIP.unparse().starts_with(_homeNetwork)){
			// If the advertisement is not from the home agent
			click_chatter("Not at home");
			// click_chatter("router address coa %s", IPAddress(advertisement->routerAddress).unparse().c_str());
			_reqGenerator->generateRequest(srcIP, IPAddress(advertisement->routerAddress));

		}
	} if (destIP == _ipAddress.in_addr() and iph->ip_p == 17){
		// TODO handle incoming reply here
		click_chatter("Incoming reply at the MN side");
	}
  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
