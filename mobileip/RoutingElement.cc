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

CLICK_DECLS
RoutingElement::RoutingElement(){}

RoutingElement::~ RoutingElement(){}

int RoutingElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "PUBLIC", cpkM, cpIPAddress, &_agentAddressPublic, "ADVERTISER", cpkM, (Advertiser*) cpElement, &_advertiser, cpEnd) < 0){
			return -1;
	}
	return 0;
}

void RoutingElement::push(int port, Packet* p){
	// Don't manipulate the packet coming from the CN
	if (port == 1){
		// TODO fix this with not a boolean value
		bool atHome = true;
		if (atHome) {
			// If MN is @ home just push it to the local network
			output(0).push(p);
		} else {
			// If MN is away IP in IP encapsulate and send it to the public network
			_encapIPinIP(p);
			output(1).push(p);
		}
		return;
	}
	click_chatter("Received a message at the agent side, packet length = %d", p->length());
	const click_ip* iph = p->ip_header();
	IPAddress srcIP = iph->ip_src;
	p->pull(sizeof(click_ip));

	// ICMP related part
	if (iph->ip_p == 1){
		ICMPSolicitation* solicitation = (ICMPSolicitation*) p->data();
		if (solicitation->code != 0) { // TODO also add checksum check here
			p->kill();
			return;
		}
		if (solicitation->type == 10){
			click_chatter("Received a solicitation @ agent side");
			// TODO handle solicitation message accordingly
			_advertiser->respondToSolicitation();
		}
	}

	// Registration related part (UDP message)
	if (iph->ip_p == 17){
		const click_udp* udpHeader = p->udp_header();
		uint16_t destinationPort = ntohs(udpHeader->uh_dport);
		uint16_t sourcePort = ntohs(udpHeader-> uh_sport);
		p->pull(sizeof(click_udp));
		if (destinationPort == 434){
			click_chatter("Received a request message @ agent side");
			RegistrationRequest* request = (RegistrationRequest*) p->data();
			// if the request is for the agent itself ==> handle message
			if (request->homeAgent != _agentAddressPublic.addr()){
				click_chatter("Received a request not for the agent itself, relaying it");
				// TODO relay the request here
			}
			// if the request is for another agent ==> relay the message
			if (request->homeAgent == _agentAddressPublic.addr()){
				click_chatter("Received a request for the agent itself, don't relay");
				// TODO generate reply here
			}
		}
		if (sourcePort == 434){
			click_chatter("Received a reply message @ agent side");
			RegistrationReply* reply = (RegistrationReply*) p->data();
			// TODO forward reply message to the MN
		}

	}

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

CLICK_ENDDECLS
EXPORT_ELEMENT(RoutingElement)
