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
#include "utils/HelperFunctions.hh"

CLICK_DECLS
Monitor::Monitor() : _atHome(true){}

Monitor::~ Monitor(){}

int Monitor::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_ipAddress, "REQUESTGENERATOR", cpkM, (RequestGenerator*) cpElement, &_reqGenerator, cpEnd) < 0){
			return -1;
	}
	this->_homeNetwork = _ipAddress.unparse().substring(0, 9); // TODO delete this
	return 0;
}

void Monitor::push(int, Packet* p){
	// click_chatter("[Monitor::push]");
	const click_ip* iph = p->ip_header();
	IPAddress destIP = iph->ip_dst;
	IPAddress s = iph->ip_src;
	// click_chatter("[Monitor] Source = %s", s.unparse().c_str());
	// handle ICMP advertisements
	if (destIP == broadCast) {
	  click_chatter("[Monitor] Received a packet at the Mobile Node with dest 255.255.255.255, length %d", p->length());
		IPAddress srcIP = iph->ip_src;
		click_chatter("[Monitor] %s = ip src address of incoming ICMP advertisement", srcIP.unparse().c_str());
		p->pull(sizeof(click_ip));
		ICMPAdvertisement* advertisement = (ICMPAdvertisement *) p->data();
		MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension *) (p->data() + sizeof(ICMPAdvertisement));
		if (advertisement->type == 9){
			// TODO handle advertisement here
			// TODO dont push the same agent twice in the vector
			_possibleAgents.push_back(IPAddress(advertisement->routerAddress));
		}
		if (!sameNetwork(srcIP, _ipAddress)) {
			// If the advertisement is not from the home agent
			click_chatter("[Monitor] Mobile node is NOT AT HOME");
			// click_chatter("router address coa %s", IPAddress(advertisement->routerAddress).unparse().c_str());
			_reqGenerator->generateRequest(srcIP, IPAddress(advertisement->routerAddress));
			_atHome = false;
			p->kill();
			return;
		}
		if (!_atHome & sameNetwork(srcIP, _ipAddress)){
			click_chatter("[Monitor] Mobile node is BACK AT HOME");
			_atHome = true;
			// If the advertisement is from the home agent
			click_chatter("TEST router address coa %s", IPAddress(advertisement->routerAddress).unparse().c_str());
			_reqGenerator->generateRequest(srcIP, IPAddress(advertisement->routerAddress));
		}
	}
	// click_chatter("[Monitor] IPH->IP_P:  %d", iph->ip_p);
	// click_chatter("[Monitor] CHECK: %d", destIP == _ipAddress.in_addr());
	if (destIP == _ipAddress.in_addr() and iph->ip_p == 17){
		// TODO handle incoming reply here, update registration request
		click_chatter("[Monitor] Received MobileIP Reply at the Mobile Node");

		// Registration was accepted
		// Registration was denied by FA
		// Registration was denied by HA

	}
  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
