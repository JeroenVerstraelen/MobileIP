#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "RoutingElement.hh"
#include "structs/ICMPSolicitation.hh"
#include "structs/RegistrationRequest.hh"
#include "structs/RegistrationReply.hh"
#include "utils/Configurables.hh"
#include "utils/HelperFunctions.hh"

CLICK_DECLS
RoutingElement::RoutingElement(){}

RoutingElement::~ RoutingElement(){}

int RoutingElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "PUBLIC", cpkM, cpIPAddress, &_agentAddressPublic, \
	 		"PRIVATE", cpkM, cpIPAddress, &_agentAddressPrivate,
			"ADVERTISER", cpkM, (Advertiser*) cpElement, &_advertiser, cpEnd) < 0){
			return -1;
	}
	return 0;
}

void RoutingElement::push(int port, Packet* p){
	// click_chatter("[RoutingElement::push %s] Port: %d", _agentAddressPublic.unparse().c_str(), port);
	click_ip* iph = (click_ip*) p->data();
	IPAddress srcIP = iph->ip_src;
	IPAddress dstAddress = iph->ip_dst;
	// Don't manipulate the packet coming from the CN
	if (port == 1){
		click_chatter("[RoutingElement] Message from Corresponding Node");
		if (_mobilityBindings.empty()) {
			click_chatter("[RoutingElement] Mobile Node is at home -> Sending directly to local network");
			// If all MN's are @ home just push it to the local network
			output(0).push(p);
		} else {
			// If MN is away IP in IP encapsulate and send it to the public network
			click_chatter("[RoutingElement] Mobile Node is away -> Sending IpinIP encap");
			IPAddress tunnelEndpoint = _findCareOfAddress(dstAddress);
			// click_chatter("Tunnel endpoint %s", tunnelEndpoint.unparse().c_str());
			_encapIPinIP(p, tunnelEndpoint);
		}
		return;
	}
	// click_chatter("[RoutingElement] Message for HA/FA, packet length = %d", p->length());
	// ICMP related part
	if (iph->ip_p == 1){
		click_chatter("[RoutingElement] ICMP related message");
		ICMPSolicitation* solicitation = (ICMPSolicitation*) (p->data() + sizeof(click_ip));
		if (solicitation->code != 0) { // TODO also add checksum check here
			p->kill();
			return;
		}
		if (solicitation->type == 10){
			click_chatter("[RoutingElement] Received a solicitation and responding to it");
			// TODO handle solicitation message accordingly
			_advertiser->respondToSolicitation();
			p->kill();
			return;
		}
		// output(1).push(p);
	}

	// IP in IP related part
	// Decapsulate packet here and forward to the MN
	if (iph->ip_p == 4){
		click_chatter("[RoutingElement] Handling decapsulation, reached tunnel endpoint");
		p->pull(sizeof(click_ip));
		click_ip* ipHeader = (click_ip*)p->data();
		p->set_dst_ip_anno(IPAddress(ipHeader->ip_dst));
		output(0).push(p);
	}

	// Registration related part (UDP message)
	if (iph->ip_p == 17){
		//const click_udp* udpHeader = p->udp_header();
		click_udp* udpHeader = (click_udp*) (p->data() + sizeof(click_ip));
		uint16_t destinationPort = ntohs(udpHeader->uh_dport);
		uint16_t sourcePort = ntohs(udpHeader-> uh_sport);
		if (destinationPort == 434){
			click_chatter("[RoutingElement] Received a request message at agent side");
			RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
			// if the request is for another agent ==> relay message
			if (request->homeAgent != _agentAddressPublic.addr()){
				click_chatter("[RoutingElement] Received a request not for the agent itself, relaying it");
				iph->ip_src = _agentAddressPublic.in_addr();
				iph->ip_dst = IPAddress(request->homeAgent).in_addr();
				iph->ip_len = htons(p->length());
				p->set_dst_ip_anno(IPAddress(iph->ip_dst));
				// Set the UDP header checksum based on the initialized values
				//unsigned csum = click_in_cksum((unsigned char *)udpHeader, sizeof(click_udp) + sizeof(RegistrationRequest));
				//udpHeader->uh_sum = click_in_cksum_pseudohdr(csum, iph, sizeof(click_udp) + sizeof(RegistrationRequest));
				output(1).push(p);
				return;
			}
			// if the request is for the agent itself ==> handle the message
			if (request->homeAgent == _agentAddressPublic.addr()){
				click_chatter("[RoutingElement] Received a request for the agent itself, don't relay");
				RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));

				// Create, update or delete MobilityBinding for the MN requestMobilityBinding mobilityData
				MobilityBinding mobilityData;
				mobilityData.homeAddress = request->homeAddress;
				mobilityData.careOfAddress = request->careOfAddress;
				mobilityData.lifetime = request->lifetime;
				mobilityData.replyIdentification = request->identification;
				IPAddress replyDestination = _updateMobilityBindings(mobilityData);

				Packet* replyPacket = _generateReply(replyDestination, IPAddress(request->homeAddress), IPAddress(request->homeAgent), request->identification, udpHeader->uh_dport, udpHeader->uh_sport);

				// Kill the request packet
				p->kill();
				// Push reply
				if (sameNetwork(replyPacket->dst_ip_anno(), _agentAddressPrivate)){
					// click_chatter("[RoutingElement] Pushing reply to local network");
					output(4).push(replyPacket);
					return;
				}
				output(3).push(replyPacket);
				return;
			}
		}
		if (sourcePort == 434){
			click_chatter("[RoutingElement] Received a reply message at agent side, forwarding to MN");
			RegistrationReply* reply = (RegistrationReply*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
			iph->ip_src = _agentAddressPrivate.in_addr();
			iph->ip_dst = IPAddress(reply->homeAddress).in_addr();
			iph->ip_len = htons(p->length());
			p->set_dst_ip_anno(IPAddress(iph->ip_dst));
			output(0).push(p);
			return;
		}

	}
	output(2).push(p);
}

void RoutingElement::_encapIPinIP(Packet* p, IPAddress careOfAddress){
	// click_chatter("[RoutingElement] Encapsulate IPinIP and send to FA");
	const click_ip* innerIP = p->ip_header(); //TODO dont let decl ip decrease the ttl
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

Packet* RoutingElement::_generateReply(IPAddress dstAddress, IPAddress homeAddress, IPAddress homeAgent, double id, uint16_t srcPort, uint16_t dstPort){
	click_chatter("[RoutingElement] Reply to MobileIP request message");
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
	iph->ip_sum = 0;
	packet->set_dst_ip_anno(IPAddress(iph->ip_dst));

	// UDP header
	click_udp *udpHeader = (click_udp *) (packet->data() + sizeof(click_ip));
	udpHeader->uh_sport = srcPort;
	udpHeader->uh_dport = dstPort;
	udpHeader->uh_ulen = htons(packet->length() - sizeof(click_ip));
	// udpHeader->uh_sum = 0;


	RegistrationReply* reply = (RegistrationReply*) (packet->data() + sizeof(click_ip) + sizeof(click_udp));
	reply->type = 3;
	reply->code = 0;
	reply->lifetime = htons(registrationLifetime);
	reply->homeAddress = homeAddress.addr();
	reply->homeAgent = homeAgent.addr();
	reply->identification = Timestamp(id).doubleval(); // TODO

	// Set the UDP header checksum based on the initialized values
	// unsigned csum = click_in_cksum((unsigned char *)udpHeader, sizeof(click_udp) + sizeof(RegistrationReply));
	// udpHeader->uh_sum = click_in_cksum_pseudohdr(csum, iph, sizeof(click_udp) + sizeof(RegistrationReply));

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
	click_chatter("[RoutingElement] Update mobility bindings size = %d", _mobilityBindings.size());
	bool isPresent = false;
	for (Vector<MobilityBinding>::iterator it=_mobilityBindings.begin(); it != _mobilityBindings.end(); it++){
		if (data.homeAddress == it->homeAddress){
			isPresent = true;
			// click_chatter("[RoutingElement] Binding already present in vector");
			if (data.careOfAddress == it->careOfAddress){
				// If MN is back home just return his home address to forward the reply to
				_mobilityBindings.erase(it);
				return IPAddress(data.homeAddress);
			}
			// TODO 3) update MobilityBinding when MN is still away but sends a new request
		}
	}
	// TODO 2) delete binding if lifetime of mobility binding expires before new valid request
	if (!isPresent) _mobilityBindings.push_back(data);
	return IPAddress(data.careOfAddress);
}
CLICK_ENDDECLS
EXPORT_ELEMENT(RoutingElement)
