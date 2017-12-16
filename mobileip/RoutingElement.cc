#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "RoutingElement.hh"
#include "structs/RegistrationReply.hh"
#include "utils/Configurables.hh"
#include "utils/HelperFunctions.hh"

CLICK_DECLS
RoutingElement::RoutingElement(): _mobilityTimer(this){}

RoutingElement::~ RoutingElement(){}

int RoutingElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "PUBLIC", cpkM, cpIPAddress, &_agentAddressPublic, \
	 		"PRIVATE", cpkM, cpIPAddress, &_agentAddressPrivate,
			"ADVERTISER", cpkM, (Advertiser*) cpElement, &_advertiser, cpEnd) < 0){
			return -1;
	}
	return 0;
}

int RoutingElement::initialize(ErrorHandler *) {
	// Initialize timer object
	_mobilityTimer.initialize(this);
	_mobilityTimer.schedule_now();
	return 0;
}

void RoutingElement::run_timer(Timer* t){
	if (t == &_mobilityTimer){
		_decreaseLifetimeMobilityBindings();
		t->reschedule_after_sec(1);
	}
}

/*
 * Port 0: ICMP messages
 * Port 1: Messages coming from the corresponding node.
 */
void RoutingElement::push(int port, Packet* p){
	// LOG("[RoutingElement::push %s] Port: %d", _agentAddressPublic.unparse().c_str(), port);
	click_ip* iph = (click_ip*) p->data();

	// Message from corresponding node
	if (port == 1){
		// Don't manipulate the packet
		// LOG("[RoutingElement] Message from Corresponding Node");
		if (_mobilityBindings.empty()) {
			// Mobile node at home
			LOG("[RoutingElement] Mobile Node is at home -> Sending directly to local network");
			// sending to local network.
			output(0).push(p);
		} else {
			// Mobile node is away
			LOG("[RoutingElement] Mobile Node is away -> Sending IpinIP encap");
			IPAddress dstAddress = iph->ip_dst;
			IPAddress tunnelEndpoint = _findCareOfAddress(dstAddress);
			// LOG("Tunnel endpoint %s", tunnelEndpoint.unparse().c_str());
			// IP in IP encapsulate and send it to the public network
			_encapIPinIP(p, tunnelEndpoint);
		}
		return;
	}

	// ICMP
	LOG("[RoutingElement] Message for HA/FA, packet length = %d", p->length());
	switch (iph->ip_p) {
		case 1:
			// Solicitation message
			{
				_solicitationResponse(p);
				p->kill();
				return;
			}
		case 4:
			// IP in IP
			{
				LOG("[RoutingElement] Handling decapsulation, reached tunnel endpoint");
				// Decpasulate packet
				p->pull(sizeof(click_ip));
				// Forward to mobile node.
				click_ip* ipHeader = (click_ip*) p->data();
				p->set_dst_ip_anno(IPAddress(ipHeader->ip_dst));
				output(0).push(p);
			}
		case 17:
			// Mobile IP Registration
			{
				click_udp* udpHeader = (click_udp*) (p->data() + sizeof(click_ip));
				uint16_t destinationPort = ntohs(udpHeader->uh_dport);
				uint16_t sourcePort = ntohs(udpHeader-> uh_sport);
				if (destinationPort == 434) {
					// Registration request
					_registrationRequestResponse(p);
				}
				else if (sourcePort == 434) {
					// Registration reply relayed to the mobile node
					_registrationReplyRelay(p);
				}
				return;
			}
		default:
			output(2).push(p);
	}
}

void RoutingElement::_solicitationResponse(Packet* p) {
	LOG("[RoutingElement] ICMP related message");
	click_ip* iph = (click_ip*) p->data();
	ICMPSolicitation* solicitation = (ICMPSolicitation*) (p->data() + sizeof(click_ip));
 	const click_icmp *icmph = p->icmp_header();
 	unsigned icmp_len = p->length() - p->transport_header_offset();
	unsigned csum = click_in_cksum((unsigned char *)icmph, icmp_len) & 0xFFFF;
	if (solicitation->code != 0) {
		LOGERROR("[RoutingElement] Solicitation message is sent with code %d but it should be 0", solicitation->code);
	}
	else if (icmp_len % 8 != 0){
		LOGERROR("[RoutingElement] Solicitation message is sent with length %d which is not 8 or more octets", ntohs(iph->ip_len) - sizeof(click_ip));
	}
	else if (csum != 0){
		LOGERROR("[RoutingElement] Solicitation message is sent with an invalid checksum");
	}
	else if (solicitation->type == 10){
		LOGERROR("[RoutingElement] Received a solicitation and responding to it");
		// TODO handle solicitation message accordingly
		_advertiser->respondToSolicitation();
	}
	p->kill();
	return;
}

// Relay on output port 1
// Reply on port 3 private/4 public.
void RoutingElement::_registrationRequestResponse(Packet* p) {
	click_ip* iph = (click_ip*) p->data();
	click_udp* udpHeader = (click_udp*) (p->data() + sizeof(click_ip));
	LOG("[RoutingElement] Received a request message at agent side");
	RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
	// If the request is for another agent
	if (request->homeAgent != _agentAddressPublic.addr()){
		// Relay the registration request to port 1
		LOG("[RoutingElement] Received a request not for the agent itself, relaying it");
		iph->ip_src = _agentAddressPublic.in_addr();
		iph->ip_dst = IPAddress(request->homeAgent).in_addr();
		iph->ip_len = htons(p->length());
		p->set_dst_ip_anno(IPAddress(iph->ip_dst));
		// TODO FA needs to check incoming requests and generate possible replies to it (see chapter 3.4)
		// If incoming request at the FA is invalid ==> send reply immediately
		RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
		if (_checkRequest(request, false) != 1){
			LOG("[RoutingElement] FA received an invalid request, error code %d", _checkRequest(request, false));
			Packet* reply = _generateReply(IPAddress(request->homeAddress), udpHeader->uh_dport, udpHeader->uh_sport, request, false);
			p->kill();
			output(0).push(reply);
			return;
		}

		// Set the UDP header checksum based on the initialized values
		//unsigned csum = click_in_cksum((unsigned char *)udpHeader, sizeof(click_udp) + sizeof(RegistrationRequest));
		//udpHeader->uh_sum = click_in_cksum_pseudohdr(csum, iph, sizeof(click_udp) + sizeof(RegistrationRequest));
		output(1).push(p);
		return;
	}
	// If the request is for the agent itself or 255.255.255.255
	if (request->homeAgent == _agentAddressPublic.addr() || request->homeAgent == broadCast.addr()){
		// Handle the registration request
		LOG("[RoutingElement] Received a request for the agent itself, don't relay");
		RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));

		// Mobility binding management
		MobilityBinding mobilityData;
		mobilityData.homeAddress = request->homeAddress;
		mobilityData.careOfAddress = request->careOfAddress;
		mobilityData.lifetime = ntohs(request->lifetime);
		mobilityData.replyIdentification = request->identification;
		IPAddress replyDestination = _updateMobilityBindings(mobilityData);

		Packet* replyPacket = _generateReply(replyDestination, udpHeader->uh_dport, udpHeader->uh_sport, request, true);

		// Kill the request packet
		p->kill();

		// Push reply
		if (sameNetwork(replyPacket->dst_ip_anno(), _agentAddressPrivate)){
			// LOG("[RoutingElement] Pushing reply to local network");
			output(0).push(replyPacket);
			return;
		}
		output(1).push(replyPacket);
		return;
	}
}

// Relay the registration reply on the private network (to the MN)
void RoutingElement::_registrationReplyRelay(Packet* p) {
	click_ip* iph = (click_ip*) p->data();
	LOG("[RoutingElement] Received a reply message at agent side, forwarding to MN");
	RegistrationReply* reply = (RegistrationReply*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
	iph->ip_src = _agentAddressPrivate.in_addr();
	iph->ip_dst = IPAddress(reply->homeAddress).in_addr();
	iph->ip_len = htons(p->length());
	p->set_dst_ip_anno(IPAddress(iph->ip_dst));
	output(0).push(p);
}

void RoutingElement::_encapIPinIP(Packet* p, IPAddress careOfAddress){
	LOG("[RoutingElement] Encapsulate IPinIP and send to FA");
	click_ip* innerIP = (click_ip *) p->data();
	innerIP->ip_ttl++;
	innerIP->ip_sum = 0;
	innerIP->ip_sum = click_in_cksum((unsigned char *)innerIP, sizeof(click_ip));
	p->set_ip_header(innerIP, sizeof(click_ip));
	WritablePacket* newPacket = p->push(sizeof(click_ip)); // Create new packet with place for outer IP header
	click_ip* outerIP = reinterpret_cast<click_ip *>(newPacket->data());;
	outerIP->ip_v = 4;
	outerIP->ip_hl = sizeof(click_ip) >> 2;
	outerIP->ip_p = 4;
	outerIP->ip_off = 0;
	outerIP->ip_tos = innerIP->ip_tos;
	outerIP->ip_len = htons(newPacket->length());
	outerIP->ip_ttl = 64; // TODO change this possibly
	outerIP->ip_src = _agentAddressPublic.in_addr();
	outerIP->ip_dst = careOfAddress.in_addr();
	outerIP->ip_sum = click_in_cksum((unsigned char *)outerIP, sizeof(click_ip));
	newPacket->set_dst_ip_anno(IPAddress(outerIP->ip_dst));
	newPacket->set_ip_header(outerIP, sizeof(click_ip));
	output(1).push(newPacket);
}

Packet* RoutingElement::_generateReply(IPAddress dstAddress, uint16_t srcPort, uint16_t dstPort, RegistrationRequest* request, bool homeAgent){
	LOG("[RoutingElement] Reply to MobileIP request message");
	int tailroom = 0;
	int headroom = sizeof(click_ether) + 4;
	int packetsize = sizeof(click_ip) + sizeof(click_udp) + sizeof(RegistrationReply);
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
	iph->ip_dst = dstAddress.in_addr();
	if (homeAgent) iph->ip_src = _agentAddressPublic.in_addr();
	if (!homeAgent) iph->ip_src = _agentAddressPrivate.in_addr();
	iph->ip_sum = 0;
	packet->set_dst_ip_anno(IPAddress(iph->ip_dst));

	// UDP header
	click_udp *udpHeader = (click_udp *) (packet->data() + sizeof(click_ip));
	udpHeader->uh_sport = srcPort;
	udpHeader->uh_dport = dstPort;
	udpHeader->uh_ulen = htons(packet->length() - sizeof(click_ip));
	udpHeader->uh_sum = 0;


	RegistrationReply* reply = (RegistrationReply*) (packet->data() + sizeof(click_ip) + sizeof(click_udp));
	reply->type = 3;
	reply->code = _checkRequest(request, homeAgent);
	reply->lifetime = request->lifetime;
	if (homeAgent && (ntohs(request->lifetime) > registrationLifetime)) reply->lifetime = htons(registrationLifetime);
	if (!homeAgent && (reply->code == 69)) reply->lifetime = htons(maxLifetimeForeignAgent);
	reply->homeAddress = IPAddress(request->homeAddress).addr();
	reply->homeAgent = IPAddress(request->homeAgent).addr();
	reply->identification = request->identification;

	// Set the UDP header checksum based on the initialized values
	unsigned csum = click_in_cksum((unsigned char *)udpHeader, sizeof(click_udp) + sizeof(RegistrationReply));
	udpHeader->uh_sum = click_in_cksum_pseudohdr(csum, iph, sizeof(click_udp) + sizeof(RegistrationReply));

	return packet;
}

IPAddress RoutingElement::_findCareOfAddress(IPAddress mobileNodeAddress){
	IPAddress returnValue = IPAddress();
	for (int i=0; i < _mobilityBindings.size(); i++){
		MobilityBinding tempBinding = _mobilityBindings.at(i);
		if (IPAddress(tempBinding.homeAddress) == mobileNodeAddress){
			returnValue = IPAddress(tempBinding.careOfAddress);
			break;
		}
	}
	return returnValue;
}

IPAddress RoutingElement::_updateMobilityBindings(MobilityBinding data){
	LOG("[RoutingElement] Mobility bindings size = %d", _mobilityBindings.size());
	bool isPresent = false;
	for (Vector<MobilityBinding>::iterator it=_mobilityBindings.begin(); it != _mobilityBindings.end(); it++){
		if (data.homeAddress == it->homeAddress){ // MN has an active binding
			isPresent = true;
			if (data.careOfAddress == it->careOfAddress && data.lifetime == 0){
				// If MN deregisters a specific binding with lifetime 0
				// MN is back home
				_mobilityBindings.erase(it);
				return IPAddress(data.homeAddress);
			} else {
				// MN sends a new valid request for an existing binding
				// and the according binding is updated
				it->lifetime = data.lifetime;
				break;
			}
		}
	}
	// If MN has no active binding, add it to the vector
	if (!isPresent) _mobilityBindings.push_back(data);
	return IPAddress(data.careOfAddress);
}

void RoutingElement::_decreaseLifetimeMobilityBindings(){
	Vector<MobilityBinding> updatedBindings;
	for (Vector<MobilityBinding>::iterator it=_mobilityBindings.begin(); it != _mobilityBindings.end(); it++){
		it->lifetime--;
		if (it->lifetime <= 0) {
			LOG("Registration was not renewed in time, so delete it from the active bindings");
			continue;
		}
		updatedBindings.push_back(*it); // If lifetime is still valid (> 0) keep the binding
	}
	// Discard the expired and keep the active bindings
	_mobilityBindings = updatedBindings;
}

uint8_t RoutingElement::_checkRequest(RegistrationRequest* request, bool homeAgent){
	if (homeAgent){
		// In our annotated version of RFC5944 there is no need to support
		// a MN with a colocated care of address
		// so return a reply with code 128
		if (request->D == 1) return 128;

		// If the x and S bit are not 0 ==> poorly formed request
		if (request->x != 0 || request->S != 0) return 134;

		// If the home agent address 255.255.255.255
		// return code 136 (Unknown home agent address)
		if (request->homeAgent == broadCast.addr()) return 136;
	} else {
		// If the requested lifetime is too long ==> return code 69
		if (ntohs(request->lifetime) > maxLifetimeForeignAgent) return 69;

		// If the x and S bit are not 0 ==> poorly formed request
		if (request->x != 0 || request->S != 0) return 70;

		// TODO add support for error codes 71 and 72
	}

	// TODO check if correct to only allow 1 as reply code
	// Code 1 means that the registration was correct
	// but there is no support for simultaneous bindings
	return 1;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RoutingElement)
