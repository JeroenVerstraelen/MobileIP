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

void Monitor::run_timer(Timer* t){
	/* TODO
	for (availableAgents) {
		if (&agent.timer == t) 
	}
	*/
}

void Monitor::push(int, Packet* p){
	LOG("[Monitor::push]");
	const click_ip* iph = p->ip_header();
	IPAddress destIP = iph->ip_dst;
	IPAddress s = iph->ip_src;
	LOG("[Monitor] Source = %s", s.unparse().c_str());
	// ICMP advertisements
	if (destIP == broadCast) {
	  	LOG("[Monitor] Received a packet at the Mobile Node with dest 255.255.255.255, length %d", p->length());
		IPAddress srcIP = iph->ip_src;
		LOG("[Monitor] %s = ip src address of incoming ICMP advertisement", srcIP.unparse().c_str());
		p->pull(sizeof(click_ip));
		ICMPAdvertisement* advertisement = (ICMPAdvertisement *) p->data();
		// TODO handle extension
		MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension *) (p->data() + sizeof(ICMPAdvertisement));
		if (advertisement->type == 9){
 			const click_icmp *icmph = p->icmp_header();
 			unsigned icmp_len = p->length() - p->transport_header_offset();
			unsigned csum = click_in_cksum((unsigned char *)icmph, icmp_len) & 0xFFFF;
			uint8_t numAddrs = advertisement->numAddrs;
			uint8_t addrEntrySize = advertisement->addrEntrySize;
			if (csum != 0) {
				LOG("[Monitor] Advertisement message is sent with an invalid checksum");
			}
			else if (advertisement->code != 0) {
				LOG("[Monitor] Advertisement message is sent with code %d "
				"but it should be 0", advertisement->code);
			}
			else if (numAddrs < 1) {
				LOG("[Monitor] Advertisement message is sent with numAddrs = %d "
				"but it should be greater than or equal to 1", numAddrs);
			}
			else if (addrEntrySize < 2) {
				LOG("[Monitor] Advertisement message is sent with addrEntrySize = %d "
				"but it should be greater than or equal to 2", addrEntrySize);
			}
			else if (icmp_len < 8 + (numAddrs * addrEntrySize * 4)) {
				LOG("[Monitor] Advertisement message is sent with ICMP length = %d "
				"but it should be greater or equal to %d", 
				icmp_len,
				8 + (numAddrs * addrEntrySize * 4));
			}
			else if (!sameNetwork(srcIP, IPAddress(advertisement->routerAddress))) {
				LOG("[Monitor] Advertisement has no router address that matches "
				"the host's subnet.");
			}
			else if (advertisement->type == 9) {
				// TODO dont push the same agent twice in the vector
				ICMPRouterEntry entry = ICMPRouterEntry();
				entry.routerAddress = advertisement->routerAddress;
				entry.preferenceLevel = advertisement->preferenceLevel;
				entry.timer.initialize(this);
				entry.timer.schedule_after_sec(advertisement->lifetime);
				_availableRouters.push_back(entry);
				LOG("[Monitor] Received a valid advertisement message");
			}
			// Silently discard
			p->kill();
		}
		if (!sameNetwork(srcIP, _ipAddress)) {
			// If the advertisement is not from the home agent
			LOG("[Monitor] Mobile node is NOT AT HOME");
			LOG("router address coa %s", IPAddress(advertisement->routerAddress).unparse().c_str());
			_reqGenerator->generateRequest(srcIP, IPAddress(advertisement->routerAddress), requestLifetime);
			_atHome = false;
			p->kill();
			return;
		}
		if (!_atHome & sameNetwork(srcIP, _ipAddress)) {
			// If the advertisement is from the home agent
			LOG("[Monitor] Mobile node is BACK AT HOME");
			_atHome = true;
			// Send request with lifetime 0
			_reqGenerator->generateRequest(srcIP, IPAddress(advertisement->routerAddress), 0);
		}
	}
	LOG("[Monitor] IPH->IP_P:  %d", iph->ip_p);
	LOG("[Monitor] CHECK: %d", destIP == _ipAddress.in_addr());

	// MobileIP reply
	if (destIP == _ipAddress.in_addr() and iph->ip_p == 17){
		// No need for the ip and udp header here
		p->pull(sizeof(click_ip));
		p->pull(sizeof(click_udp));
		LOG("[Monitor] Received MobileIP Reply at the Mobile Node");
		RegistrationReply* reply = (RegistrationReply*) p->data();
		if (ntohs(reply->lifetime) == 0){
			// Reply with lifetime 0 => stop the requests
			_reqGenerator->stopRequests();
		}

		// TODO further implement the following scenario's
		// Registration was accepted (basic version is done)
		// Registration was denied by FA
		// Registration was denied by HA
	}
  output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
