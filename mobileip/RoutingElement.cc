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
	// Don't manipulate the packet coming from the CN
	if (port == 1){
		if (_mobilityBindings.empty()) {
			// If all MN's are @ home just push it to the local network
			output(0).push(p);
		} else {
			// TODO ip in ip encap
			// If MN is away IP in IP encapsulate and send it to the public network
			click_chatter("MN is on vacation, trying to tunnel messages to his COA");
			_encapIPinIP(p);
			output(1).push(p);
		}
		return;
	}
	click_chatter("Received a message at the agent side, packet length = %d", p->length());
	click_ip* iph = (click_ip*) p->data();
	IPAddress srcIP = iph->ip_src;

	// ICMP related part
	if (iph->ip_p == 1){
		ICMPSolicitation* solicitation = (ICMPSolicitation*) (p->data() + sizeof(click_ip));
		if (solicitation->code != 0) { // TODO also add checksum check here
			p->kill();
			return;
		}
		if (solicitation->type == 10){
			click_chatter("Received a solicitation @ agent side");
			// TODO handle solicitation message accordingly
			_advertiser->respondToSolicitation();
			p->kill();
			return;
		}
	}

	// Registration related part (UDP message)
	if (iph->ip_p == 17){
		//const click_udp* udpHeader = p->udp_header();
		click_udp* udpHeader = (click_udp*) (p->data() + sizeof(click_ip));
		uint16_t destinationPort = ntohs(udpHeader->uh_dport);
		uint16_t sourcePort = ntohs(udpHeader-> uh_sport);
		if (destinationPort == 434){
			click_chatter("Received a request message @ agent side");
			RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
			// if the request is for another agent ==> relay message
			if (request->homeAgent != _agentAddressPublic.addr()){
				click_chatter("Received a request not for the agent itself, relaying it");
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
				click_chatter("Received a request for the agent itself, don't relay");
				RegistrationRequest* request = (RegistrationRequest*) (p->data() + sizeof(click_ip) + sizeof(click_udp));
				_generateReply(IPAddress(request->careOfAddress), IPAddress(request->homeAddress), IPAddress(request->homeAgent), request->identification, udpHeader->uh_dport, udpHeader->uh_sport);

				// Create MobilityBinding for the MN request
				MobilityBinding mobilityData;
				mobilityData.homeAddress = request->homeAddress;
				mobilityData.careOfAddress = request->careOfAddress;
				mobilityData.lifetime = request->lifetime;
				mobilityData.replyIdentification = request->identification;
				_mobilityBindings.push_back(mobilityData);

				// TODO delete MobilityBinding when MN is at home
				// TODO update MobilityBinding when MN is still away but sends a new request

				output(2).push(p);
				return;
			}
		}
		if (sourcePort == 434){
			click_chatter("Received a reply message @ agent side, forwarding to MN");
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

void RoutingElement::_encapIPinIP(Packet* p){
	const click_ip* innerIP = p->ip_header(); //TODO check if TTL is decreased by the DecTTL @ ha.click
	WritablePacket* newPacket = p->push(sizeof(click_ip)); // Create new packet with place for outer IP header
	click_ip* outerIP;
	outerIP->ip_v = 4;
	outerIP->ip_hl = sizeof(click_ip) >> 2;
	outerIP->ip_p = 4;
	outerIP->ip_tos = innerIP->ip_tos;
	outerIP->ip_len = htons(newPacket->length());
	outerIP->ip_ttl = 10; // TODO change this possibly
	outerIP->ip_src = _agentAddressPublic.in_addr();
	outerIP->ip_dst = IPAddress("192.168.3.254").in_addr(); // TODO not hardcoded
	outerIP->ip_sum = click_in_cksum((unsigned char *)outerIP, sizeof(click_ip));
	newPacket->set_dst_ip_anno(IPAddress(outerIP->ip_dst));
	newPacket->set_ip_header(outerIP, sizeof(click_ip));
	output(1).push(newPacket);
}

void RoutingElement::_generateReply(IPAddress dstAddress, IPAddress homeAddress, IPAddress homeAgent, double id, uint16_t srcPort, uint16_t dstPort){
	click_chatter("Reply message");
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

	click_chatter("Pushing reply with length %d", packet->length());
	output(3).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RoutingElement)
