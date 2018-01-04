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
Monitor::Monitor() :  _currentSequenceNumber(0), _atHome(true){}

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

void Monitor::push(int, Packet* p){
	const click_ip* iph = p->ip_header();
	IPAddress destIP = iph->ip_dst;

	// ICMP agent advertisement
	if (destIP == broadCast) {
		_handleAdvertisement(p);
		return;
	}

	// Incoming IP packet with UDP payload
	// MobileIP Registration reply
	if (destIP == _ipAddress.in_addr() and iph->ip_p == 17) {
		_handleRegistrationReply(p);
	}

  	output(0).push(p);
}

void Monitor::_handleAdvertisement(Packet* p) {
	const click_ip* iph = p->ip_header();
	IPAddress srcIP = iph->ip_src;
	IPAddress destIP = iph->ip_dst;
	LOG("[Monitor] Received an advertisement, length %d, ip src = %s", p->length(), srcIP.unparse().c_str());
	p->pull(sizeof(click_ip));
	ICMPAdvertisement* advertisement = (ICMPAdvertisement *) p->data();
	if (advertisement->type == 9) {
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
		else {
			LOG("[Monitor] Received a valid advertisement message");
			// TODO handle extension
			MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension *) (p->data() + sizeof(ICMPAdvertisement));
			bool registerAgain = _updateSequenceNumber(ntohs(extension->sequenceNumber));
			if (registerAgain) _reqGenerator->generateRequest(srcIP, IPAddress(extension->careOfAddress), requestLifetime);
			if (!sameNetwork(srcIP, _ipAddress)) {
				// If the advertisement is not from the home agent
				LOG("[Monitor] Mobile node is NOT AT HOME");
				// TODO toch niet op elke advertisement van de FA een nieuwe registration sturen ofwel?
				if (extension->R == 1 && !_reqGenerator->hasActiveRegistration(IPAddress(extension->careOfAddress))) {
					_reqGenerator->generateRequest(srcIP, IPAddress(extension->careOfAddress), requestLifetime);
				}
				_atHome = false;
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
	}
	// Discard
	p->kill();
}

void Monitor::_handleRegistrationReply(Packet* p) {
	const click_ip* ipHeader = p->ip_header();
	click_udp *udpHeader = (click_udp *) (p->data() + sizeof(click_ip));
	RegistrationReply* reply = (RegistrationReply*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
	if (reply->type != 3)
		return;
	LOG("[Monitor] Received MobileIP Reply at the Mobile Node");
	if (ntohs(udpHeader->uh_dport) != portUDP){
		LOGERROR("[Monitor] Received registration reply packet on UDP port %d, but expected port %d", ntohs(udpHeader->uh_dport), portUDP);
		return;
	}
	if (reply->code == 0 || reply->code == 1){ // Registration was accepted
		if (ntohs(reply->lifetime) == 0){
			// Reply with lifetime 0 => stop the requests
			_reqGenerator->stopRequests();
		} else {
			// If the reply was valid and lifetime is not 0
			// Update the responding registration in RequestGenerator in order to resend
			// a registration request when its lifetime is almost expired at the home agent
			_reqGenerator->updateRegistration(reply->identification, ntohs(reply->lifetime));
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
}


/*
 * Update the sequence number and if necessary resend a registration request
 * (if the FA has rebooted (sequenceNumber between 0 and 256))
 * Returns true if the MN SHOULD register again
 */
bool Monitor::_updateSequenceNumber(unsigned int seqNumber){
	if (seqNumber < _currentSequenceNumber && !_atHome){
		// seqNumber is an unsigned int and thus implicit >= 0
		if (seqNumber <= 255 && !_atHome){
				// FA has rebooted and MN should register again
				return true;
		}
	}
	_currentSequenceNumber = seqNumber;
	if (_atHome) _currentSequenceNumber = 0;
	return false;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Monitor)
