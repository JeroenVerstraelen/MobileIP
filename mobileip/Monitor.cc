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
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_ipAddress,
	"REQUESTGENERATOR", cpkM, (RequestGenerator*) cpElement, &_reqGenerator,
	"SOLICITATIONGENERATOR", cpkM, (Solicitor*) cpElement, &_solicitor,
	cpEnd) < 0){
			return -1;
	}
	return 0;
}

void Monitor::run_timer(Timer* t){
	std::map<Timer*, ICMPRouterEntry>::iterator it;
	it = _availableRouters.find(t);
  	if (it != _availableRouters.end()) {
		// Discard entry
		_availableRouters.erase(t);
		delete t;
		// Move detection
		_solicitor->generateSolicitation();
	}
}

void Monitor::push(int, Packet* p){
	// LOG("[Monitor::push]");
	const click_ip* iph = p->ip_header();
	IPAddress srcIP = iph->ip_src;
	IPAddress destIP = iph->ip_dst;
	// LOG("[Monitor] Source = %s", srcIP.unparse().c_str());
	// ICMP advertisements
	if (destIP == broadCast) {
	  	LOG("[Monitor] Received a packet at the Mobile Node with dest 255.255.255.255, length %d", p->length());
		LOG("[Monitor] %s = ip src address of incoming ICMP advertisement", srcIP.unparse().c_str());
		p->pull(sizeof(click_ip));
		ICMPAdvertisement* advertisement = (ICMPAdvertisement *) p->data();
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
				LOGERROR("[Monitor] Advertisement message is sent with code %d "
				"but it should be 0", advertisement->code);
			}
			else if (numAddrs < 1) {
				LOGERROR("[Monitor] Advertisement message is sent with numAddrs = %d "
				"but it should be greater than or equal to 1", numAddrs);
			}
			else if (addrEntrySize < 2) {
				LOGERROR("[Monitor] Advertisement message is sent with addrEntrySize = %d "
				"but it should be greater than or equal to 2", addrEntrySize);
			}
			else if (icmp_len < (unsigned) 8 + (numAddrs * addrEntrySize * 4)) {
				LOGERROR("[Monitor] Advertisement message is sent with ICMP length = %d "
				"but it should be greater or equal to %d",
				icmp_len,
				8 + (numAddrs * addrEntrySize * 4));
			}
			else if (advertisement->type == 9) {
				/*
				if (_homeAgent == NULL)
					_homeAgent = IPAddress(advertisement->routerAddress);
				*/
				std::map<Timer*, ICMPRouterEntry>::iterator it =_availableRouters.begin();
				bool found = false;
				for (;it != _availableRouters.end(); ++it) {
					if (it->second.routerAddress == advertisement->routerAddress) {
						found = true;
						// Update preferenceLevel
						it->second.preferenceLevel = advertisement->preferenceLevel;
						// Reset the timer to new value
						it->first->schedule_after_sec(advertisement->lifetime);
					}
				}
				if (!found) {
					ICMPRouterEntry entry = ICMPRouterEntry();
					entry.routerAddress = advertisement->routerAddress;
					entry.preferenceLevel = advertisement->preferenceLevel;
					Timer* timer = new Timer();
					timer->initialize(this);
					timer->schedule_after_sec(advertisement->lifetime);
					_availableRouters.insert( std::pair<Timer*, ICMPRouterEntry>(timer, entry) );
				}
				LOG("[Monitor] Received a valid advertisement message");
				// TODO handle extension
				MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension *) (p->data() + sizeof(ICMPAdvertisement));
				//if (srcIP != _homeAgent) {
				if (!sameNetwork(srcIP, _ipAddress)) {
					// If the advertisement is not from the home agent
					LOG("[Monitor] Mobile node is NOT AT HOME");
					LOG("router address coa %s", IPAddress(extension->careOfAddress).unparse().c_str());
					if (extension->R == 1) {
						_reqGenerator->generateRequest(srcIP, IPAddress(extension->careOfAddress), requestLifetime);
					}
					_atHome = false;
					return;
				}
				//if (!_atHome & srcIP == _homeAgent) {
				if (!_atHome & sameNetwork(srcIP, _ipAddress)) {
					// If the advertisement is from the home agent
					LOG("[Monitor] Mobile node is BACK AT HOME");
					_atHome = true;
					// Send request with lifetime 0
					_reqGenerator->generateRequest(srcIP, IPAddress(advertisement->routerAddress), 0);
				}
			}
		}
		// Discard
		p->kill();
		return;
	}
	// LOG("[Monitor] IPH->IP_P:  %d", iph->ip_p);
	// LOG("[Monitor] CHECK: %d", destIP == _ipAddress.in_addr());

	// Incoming IP packet with UDP payload
	if (destIP == _ipAddress.in_addr() and iph->ip_p == 17){
		const click_ip* ipHeader = p->ip_header();
		RegistrationReply* reply = (RegistrationReply*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
		if (reply->type == 3){
			LOG("[Monitor] Received MobileIP Reply at the Mobile Node");
			if (reply->code == 0 || reply->code == 1){ // Registration was accepted
				if (ntohs(reply->lifetime) == 0){
					// Reply with lifetime 0 => stop the requests
					// TODO further administration work with valid reply
					_reqGenerator->stopRequests();
				}
			} else if (reply->code == 64){
				LOGERROR("[Monitor] The registration was denied by FA (reason unspecified)");
			} else if (reply->code == 69){
				LOGERROR("[Monitor] The registration was denied by FA (requested lifetime is too long (<=%d seconds))", ntohs(reply->lifetime));
				_reqGenerator->generateRequest(IPAddress(ipHeader->ip_src), IPAddress(), ntohs(reply->lifetime));
			} else if (reply->code == 70){
				LOGERROR("[Monitor] The registration was denied by FA (poorly formed request)");
			} else if (reply->code == 71){
				LOGERROR("[Monitor] The registration was denied by FA (poorly formed reply)");
			} else if (reply->code == 72){
				LOGERROR("[Monitor] The registration was denied by FA (encapsulation is unavailable)");
			} else if (reply->code == 128){
				LOGERROR("[Monitor] The registration was denied by HA (reason unspecified)");
			} else if (reply->code == 134){
				LOGERROR("[Monitor] The registration was denied by HA (poorly formed request)");
			} else if (reply->code == 136){
				LOGERROR("[Monitor] The registration was denied by HA (reason unspecified)");
			}
			// TODO handling of error codes
			// Registration was denied by FA
			// Registration was denied by HA
		}
	}
  	output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
