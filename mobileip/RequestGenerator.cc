#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>
#include <limits.h>
#include <time.h>

// Local imports
#include "RequestGenerator.hh"
#include "structs/RegistrationRequest.hh"
#include "utils/Configurables.hh"
#include "utils/HelperFunctions.hh"

CLICK_DECLS
RequestGenerator::RequestGenerator():_timer(this){}

RequestGenerator::~ RequestGenerator(){}

int RequestGenerator::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_srcAddress,\
			"HA", cpkM, cpIPAddress, &_homeAgent, cpEnd) < 0){
			return -1;
	}
	_timer.initialize(this);
	return 0;
}

void RequestGenerator::run_timer(Timer* t){
	// Update the remainingLifetime fields in the pendingRegistrationsData vector
	// click_chatter("[RequestGenerator] Timer is triggered");
	if (t == &_timer){
		_decreaseRemainingLifetime();
		_timer.reschedule_after_sec(1);
	}
}

void RequestGenerator::stopRequests(){
	_timer.clear();
	_pendingRegistrationsData.clear();
}

// If reply has reached MN, update its registration lifetime according to page49 in RFC 5944
void RequestGenerator::updateRegistration(uint64_t identification, uint16_t newLifetime){
	for (Vector<RegistrationData>::iterator it=_pendingRegistrationsData.begin(); it != _pendingRegistrationsData.end(); it++){
		if (it->identification == identification) { // TODO check if this way is correct
			LOG("Updating the pending registration for %d", identification);
			uint16_t difference = it->originalLifetime - newLifetime;
			it->remainingLifetime = it->remainingLifetime - difference;
		}
	}
}

bool RequestGenerator::hasActiveRegistration(IPAddress coa){
	LOG("[RequestGenerator] hasActiveRegistration");
	for (Vector<RegistrationData>::iterator it=_pendingRegistrationsData.begin(); it != _pendingRegistrationsData.end(); it++){
		if (IPAddress(it->careOfAddress) == coa){
			LOG("[RequestGenerator] Already an active registration for this coa");
			return true;
		}
	}
	return false;
}

void RequestGenerator::generateRequest(IPAddress agentAddress, IPAddress coa, uint16_t lifetime){
	click_chatter("[RequestGenerator] Sending MobileIP request message");
	int tailroom = 0;
	int headroom = sizeof(click_ether) + 4;
	int packetsize = sizeof(click_ip) + sizeof(click_udp) + sizeof(RegistrationRequest);
	WritablePacket* packet = Packet::make(headroom, 0, packetsize, tailroom);
	memset(packet->data(), 0, packet->length());

	// IP header
	click_ip *iph = (click_ip *) packet->data();
	iph->ip_v = 4;
	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(packet->length());
	iph->ip_id = htons(0);
	iph->ip_p = IP_PROTO_UDP; // UDP protocol
	iph->ip_tos = 0x00;
	iph->ip_ttl = 64;
	iph->ip_dst = agentAddress.in_addr();
	iph->ip_src = _srcAddress.in_addr();
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
	packet->set_dst_ip_anno(IPAddress(iph->ip_dst));

	// UDP header
	click_udp *udpHeader = (click_udp *) (packet->data() + sizeof(click_ip));
	udpHeader->uh_sport = htons(portUDP);
	udpHeader->uh_dport = htons(434);
	udpHeader->uh_ulen = htons(packet->length() - sizeof(click_ip));
	udpHeader->uh_sum = 0;

	// Registration request part
	RegistrationRequest* request = (RegistrationRequest *) (packet->data() + sizeof(click_ip) + sizeof(click_udp));
	request->type = 1;
	request->S = 0;
	request->B = 0;
	request->D = 0;
	request->M = 0;
	request->G = 0;
	request->r = 0;
	request->T = 0;
	request->x = 0;
	request->lifetime = htons(lifetime);
	request->homeAddress = _srcAddress.addr();
	request->homeAgent = _homeAgent.addr();
	request->careOfAddress = coa.addr();
	request->identification = (uint64_t) generateRandomNumber(0, 4294967294);
	//click_chatter("[RequestGenerator] Random identification value %d", request->identification);

	// Set the UDP header checksum based on the initialized values
	unsigned csum = click_in_cksum((unsigned char *)udpHeader, sizeof(click_udp) + sizeof(RegistrationRequest));
	udpHeader->uh_sum = click_in_cksum_pseudohdr(csum, iph, sizeof(click_udp) + sizeof(RegistrationRequest));

	// MN needs to maintain the following data for each pending registration
	RegistrationData data;
	data.linkLayerAddress = 0;
	data.destinationIPAddress = IPAddress(iph->ip_dst).addr(); // TODO check this
	data.careOfAddress = request->careOfAddress;
	data.identification = request->identification;
	data.originalLifetime = ntohs(request->lifetime);
	data.remainingLifetime = ntohs(request->lifetime);
	_manageRegistrations(data);

	// If timer not yet scheduled ==> schedule it
	// Request is sent so keep remainingLifetime up to date
	if (!_timer.scheduled()){ _timer.schedule_after_sec(1);}

	LOG("[RequestGenerator] Sent a request with id %d", request->identification);

	// Push the packet to the private network
	output(0).push(packet);
}

void RequestGenerator::_decreaseRemainingLifetime(){
	for (int it=0; it<_pendingRegistrationsData.size(); it++){
		LOG("[RequestGenerator] Registration expires in %d seconds", _pendingRegistrationsData.at(it).remainingLifetime);
		// Don't decrement an infinite lifetime registration
		if (_pendingRegistrationsData.at(it).originalLifetime == 0xffff) continue;
		_pendingRegistrationsData.at(it).remainingLifetime--; // Decrement remainingLifetime
		// The current registration’s Lifetime is near expiration
		// so send a new registration request (page 42 RFC 5944)
		if (_pendingRegistrationsData.at(it).remainingLifetime <= 5){
			RegistrationData data = _pendingRegistrationsData.at(it);
			LOG("[RequestGenerator] Registration is almost expired <= 5 seconds, so renew it");
			generateRequest(IPAddress(data.destinationIPAddress), IPAddress(data.careOfAddress), data.originalLifetime);
		}
	}
}

void RequestGenerator::_manageRegistrations(RegistrationData data){
	bool isPresent = false;
	Vector<RegistrationData> updatedRegistrations;
	for (Vector<RegistrationData>::iterator it=_pendingRegistrationsData.begin(); it != _pendingRegistrationsData.end(); it++){
		if (it->careOfAddress == data.careOfAddress && it->destinationIPAddress == data.destinationIPAddress){
			LOG("Registration is already present so remove the old one");
			isPresent = true;
			updatedRegistrations.push_back(data);
			continue;
		}
		updatedRegistrations.push_back(*it);
	}
	if (!isPresent) updatedRegistrations.push_back(data);
	// Discard the old and keep the new registrations
	_pendingRegistrationsData = updatedRegistrations;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RequestGenerator)
