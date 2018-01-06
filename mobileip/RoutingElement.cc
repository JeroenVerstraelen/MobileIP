#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "RoutingElement.hh"
#include "utils/Configurables.hh"
#include "utils/HelperFunctions.hh"

CLICK_DECLS
RoutingElement::RoutingElement(): _mobilityTimer(this){}

RoutingElement::~ RoutingElement(){}

int RoutingElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(
		conf, this, errh,
	        "PUBLIC", cpkM, cpIPAddress, &_agentAddressPublic, \
		"PRIVATE", cpkM, cpIPAddress, &_agentAddressPrivate, \
		"ADVERTISER", cpkM, (Advertiser*) cpElement, &_advertiser, \
		cpEnd) < 0) {
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
		_decreaseLifetimeVisitors();
		t->reschedule_after_sec(1);
	}
}

void RoutingElement::push(int port, Packet* p){
	click_ip* iph = (click_ip*) p->data();

	// Delivery to own ipnet
	if (port == 1){
		// Message from corresponding node
		if (_mobilityBindings.empty()) {
			// Mobile node at home
			LOG("[RoutingElement] Mobile Node is at home");
			// sending to local network.
			output(0).push(p);
		} else {
			// Mobile node is away
			LOG("[RoutingElement] Mobile Node is away");
			IPAddress dstAddress = iph->ip_dst;
			IPAddress tunnelEndpoint = _findCareOfAddress(dstAddress);
			// LOG("Tunnel endpoint %s", tunnelEndpoint.unparse().c_str());
			// IP in IP encapsulate and send it to the public network
			_encapIPinIP(p, tunnelEndpoint);
		}
		return;
	}

	// Delivery to own ip (private/public)
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
				// Decapsulate packet
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
	LOG("[RoutingElement] Solicitation response received");
	click_ip* iph = (click_ip*) p->data();
	ICMPSolicitation* solicitation = (ICMPSolicitation*) (p->data() + sizeof(click_ip));
 	const click_icmp *icmph = p->icmp_header();
 	unsigned icmp_len = p->length() - p->transport_header_offset();
	unsigned csum = click_in_cksum((unsigned char *)icmph, icmp_len) & 0xFFFF;
	if (solicitation->code != 0) {
		LOGERROR("[RoutingElement] Solicitation message is "
		 	 "sent with code %d but it should be 0",
			 solicitation->code);
	}
	else if (icmp_len % 8 != 0){
		LOGERROR("[RoutingElement] Solicitation message is "
			 "sent with length %d which is not 8 or more octets",
			 ntohs(iph->ip_len) - sizeof(click_ip));
	}
	else if (csum != 0){
		LOGERROR("[RoutingElement] Solicitation message is "
			 "sent with an invalid checksum");
	}
	else if (solicitation->type == 10){
		_advertiser->respondToSolicitation();
	}
	p->kill();
	return;
}

// Relay on output port 1
// Reply on port 3 private/4 public.
void RoutingElement::_registrationRequestResponse(Packet* p) {
	click_ip* iph = (click_ip*) p->data();
	uint32_t dstAddressRequest = ntohl(IPAddress(iph->ip_dst).addr());
	click_udp* udpHeader = (click_udp*) (p->data() + sizeof(click_ip));
	LOG("[RoutingElement] Received a registration request at agent side");
	RegistrationRequest* request =
	(RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
	// If the request is for another agent
	if (request->homeAgent != _agentAddressPublic.addr()){
		// Relay the registration request to port 1
		LOG("[RoutingElement] Received a request not for the agent itself, relaying it");
		iph->ip_src = _agentAddressPublic.in_addr();
		iph->ip_dst = IPAddress(request->homeAgent).in_addr();
		iph->ip_len = htons(p->length());
		p->set_dst_ip_anno(IPAddress(iph->ip_dst));
		// TODO FA needs to check incoming requests and
		// TODO generate possible replies to it (see chapter 3.3)
		// If incoming request at the FA is invalid ==> send reply immediately
		RegistrationRequest* request =
		(RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
		if (_checkRequest(request, false) != 1 &&
		    _checkRequest(request, false) != 0) {
			LOGERROR("[RoutingElement] FA received an invalid request, "
			 	 "error code %d", _checkRequest(request, false));
			Packet* reply = _generateReply(IPAddress(request->homeAddress),
						       udpHeader->uh_dport,
						       udpHeader->uh_sport,
						       request,
					       	       false);
			p->kill();
			output(0).push(reply);
			return;
		}

		// Request was valid so add entry in the visitors list
		uint16_t udpPort = ntohs(udpHeader->uh_sport);
		_addPendingVisitor(request, dstAddressRequest, udpPort);

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
		RegistrationRequest* request =
		(RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));

		uint8_t replyCode = _checkRequest(request, true);
		bool validRequest = (replyCode == 1 || replyCode == 0);
		MobilityBinding mobilityData;
		mobilityData.homeAddress = request->homeAddress;
		mobilityData.careOfAddress = request->careOfAddress;
		mobilityData.lifetime = ntohs(request->lifetime);
		mobilityData.replyIdentification = request->identification;
		IPAddress replyDestination = _updateMobilityBindings(mobilityData, validRequest);

		// Generate the reply
		Packet* replyPacket = _generateReply(replyDestination,
						     udpHeader->uh_dport,
						     udpHeader->uh_sport,
						     request, true);

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
	click_udp* udpHeader = (click_udp*) (p->data() + sizeof(click_ip));
	LOG("[RoutingElement] Received a reply message at agent side, forwarding to MN");
	RegistrationReply* reply =
	(RegistrationReply*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
	bool poorlyFormed = _poorlyFormed(reply);

	// Check if port is corresponding with the port used in the request
	// TODO delete entry here??
	VisitorEntry entry = _findVisitorEntry(reply);
	if (entry.udpSourcePort != ntohs(udpHeader->uh_dport)){
		LOGERROR("[RoutingElement] Received registration reply packet on UDP port %d, but expected port %d", ntohs(udpHeader->uh_dport), entry.udpSourcePort);
		p->kill();
		return;
	}
	if (poorlyFormed) {
		// TODO generate a new reply if the relayed reply is poorly formed
	}
	if (!poorlyFormed && (reply->code == 1 || reply->code == 0)) _updateVisitors(reply);
	if (reply->code != 0 && reply->code != 1) _deletePendingVisitor(reply);
	iph->ip_src = _agentAddressPrivate.in_addr();
	iph->ip_dst = IPAddress(reply->homeAddress).in_addr();
	iph->ip_len = htons(p->length());
	p->set_dst_ip_anno(IPAddress(iph->ip_dst));
	output(0).push(p);
}

void RoutingElement::_encapIPinIP(Packet* p, IPAddress careOfAddress){
	click_ip* innerIP = (click_ip *) p->data();
	innerIP->ip_ttl++;
	innerIP->ip_sum = 0;
	innerIP->ip_sum = click_in_cksum((unsigned char *)innerIP, sizeof(click_ip));
	p->set_ip_header(innerIP, sizeof(click_ip));
	// Create new packet with place for outer IP header
	WritablePacket* newPacket = p->push(sizeof(click_ip));
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
	iph->ip_src = _agentAddressPublic.in_addr();
	if (sameNetwork(_agentAddressPrivate, dstAddress))
		iph->ip_src = _agentAddressPrivate.in_addr();

	iph->ip_sum = 0;
	packet->set_dst_ip_anno(IPAddress(iph->ip_dst));

	// UDP header
	click_udp *udpHeader = (click_udp *) (packet->data() + sizeof(click_ip));
	udpHeader->uh_sport = srcPort;
	udpHeader->uh_dport = dstPort;
	udpHeader->uh_ulen = htons(packet->length() - sizeof(click_ip));
	udpHeader->uh_sum = 0;


	RegistrationReply* reply =
	(RegistrationReply*) (packet->data() + sizeof(click_ip) + sizeof(click_udp));
	reply->type = 3;
	reply->code = _checkRequest(request, homeAgent);
	reply->lifetime = request->lifetime;
	if (homeAgent && (ntohs(request->lifetime) > registrationLifetime)) reply->lifetime = htons(registrationLifetime);
	if (!homeAgent && (reply->code == 69)) reply->lifetime = htons(maxLifetimeForeignAgent);
	reply->homeAddress = IPAddress(request->homeAddress).addr();
	reply->homeAgent = IPAddress(request->homeAgent).addr();
	LOG("[RoutingElement] Received a request with id %d and sending a reply with it");
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

IPAddress RoutingElement::_updateMobilityBindings(MobilityBinding data, bool valid){
	LOG("[RoutingElement] Mobility bindings size = %d", _mobilityBindings.size());
	bool isPresent = false;
	for (Vector<MobilityBinding>::iterator it=_mobilityBindings.begin(); it != _mobilityBindings.end(); it++){
		if (data.homeAddress == it->homeAddress){ // MN has an active binding
			isPresent = true;
			if (data.lifetime == 0) {
				// If MN deregisters a specific binding with lifetime 0
				// MN is back home
				if (valid) 
					_mobilityBindings.erase(it);
				return IPAddress(data.homeAddress);
			} else {
				// MN sends a new valid request for an existing binding
				// and the according binding is updated
				if (valid) it->lifetime = data.lifetime;
				break;
			}
		}
	}
	// If MN has no active binding, add it to the vector
	if (!isPresent && valid) _mobilityBindings.push_back(data);
	return IPAddress(data.careOfAddress);
}

void RoutingElement::_updateVisitors(RegistrationReply* reply){
	// TODO delete the older entries if reply was valid and keep newest(page 53 RFC)
	for (Vector<VisitorEntry>::iterator it=_visitors.begin(); it != _visitors.end(); it++){
		// Found corresponding entry
		// MN source address is the same as the reply homeAddress
		if (ntohl(reply->homeAddress) == it->sourceIPAddress){
			if (ntohs(reply->lifetime) == 0) {
				_visitors.erase(it);
				continue;
			}
			it->remainingLifetime = ntohs(reply->lifetime);
			if (maxLifetimeForeignAgent < ntohs(reply->lifetime)) it->remainingLifetime = maxLifetimeForeignAgent;
			it->identification = reply->identification;
		}
	}
}

void RoutingElement::_addPendingVisitor(RegistrationRequest* request, uint32_t dst, uint16_t port){
	VisitorEntry entry;
	entry.linkLayerAddress = 0;
	entry.sourceIPAddress = ntohl(request->homeAddress);
	entry.destinationIPAddress = dst;
	entry.udpSourcePort = port;
	entry.homeAgentAddress = ntohl(request->homeAgent);
	entry.identification = request->identification;
	entry.requestLifetime = ntohs(request->lifetime);
	entry.remainingLifetime = entry.requestLifetime;
	_visitors.push_back(entry);
}

void RoutingElement::_deletePendingVisitor(RegistrationReply* reply){
	for (Vector<VisitorEntry>::iterator it=_visitors.begin(); it != _visitors.end(); it++){
		// Found corresponding entry
		// MN source address is the same as the reply homeAddress
		// and identification field match
		if (ntohl(reply->homeAddress) == it->sourceIPAddress && reply->identification == it->identification){
			_visitors.erase(it);
			return;
		}
	}
}

void RoutingElement::_decreaseLifetimeMobilityBindings(){
	Vector<MobilityBinding> updatedBindings;
	for (Vector<MobilityBinding>::iterator it=_mobilityBindings.begin(); it != _mobilityBindings.end(); it++){
		if (it->lifetime == 0xffff) { // If lifetime is infinity dont decrement it
			updatedBindings.push_back(*it);
			continue;
		}
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

void RoutingElement::_decreaseLifetimeVisitors(){
	Vector<VisitorEntry> updatedVisitors;
	for (Vector<VisitorEntry>::iterator it=_visitors.begin(); it != _visitors.end(); it++){
		if (it->requestLifetime == 0xffff){// If lifetime is infinity dont decrement it
			updatedVisitors.push_back(*it);
			continue;
		}
		it->remainingLifetime--;
		if (it->remainingLifetime <= 0) {
			LOG("Registration was not renewed in time, so delete it from the visitors list");
			continue;
		}
		updatedVisitors.push_back(*it); // If lifetime is still valid (> 0) keep the binding
	}
	// Discard the expired and keep the active visitors
	_visitors = updatedVisitors;
}

uint8_t RoutingElement::_checkRequest(RegistrationRequest* request, bool homeAgent){
	if (homeAgent){
		// In our annotated version of RFC5944
		// we only support a couple of things
		// so reply with code 128 if we don't support the requested functionality
		if (request->D == 1 || request->B == 1 || request->T == 1 || request->M == 1 || request->G == 1) return 128;

		// If the x and r bit are not 0 ==> poorly formed request
		if (request->x != 0 || request->r != 0) return 134;

		// If the home agent address 255.255.255.255
		// return code 136 (Unknown home agent address)
		if (request->homeAgent == broadCast.addr()) return 136;
	} else {
		// If the requested lifetime is too long ==> return code 69
		if (ntohs(request->lifetime) > maxLifetimeForeignAgent) return 69;

		// If the x and r bit are not 0 ==> poorly formed request
		if (request->x != 0 || request->r != 0) return 70;

		// GRE encapsulation and minimal encapsulation not supported in this version
		if (request->M == 1 || request->G == 1) return 72;

		// TODO add support for error code 64

	}

	// Supposed to be 1 but we keep it 0 for this evaluation
	return 0;
}

// Returns true if reply is poorly formed
bool RoutingElement::_poorlyFormed(RegistrationReply* reply){
	// TODO implement this
	return false;
};

VisitorEntry RoutingElement::_findVisitorEntry(RegistrationReply* reply){
	for (Vector<VisitorEntry>::iterator it=_visitors.begin(); it != _visitors.end(); it++){
		// Found corresponding entry
		// MN source address is the same as the reply homeAddress
		// and identification field match
		if (ntohl(reply->homeAddress) == it->sourceIPAddress && reply->identification == it->identification){
			return *it;
		}
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RoutingElement)
