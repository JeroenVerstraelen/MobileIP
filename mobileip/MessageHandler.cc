#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "MessageHandler.hh"
#include "structs/ICMPSolicitation.hh"
#include "structs/RegistrationRequest.hh"
#include "structs/RegistrationReply.hh"

CLICK_DECLS
MessageHandler::MessageHandler(){}

MessageHandler::~ MessageHandler(){}

int MessageHandler::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "PUBLIC", cpkM, cpIPAddress, &_agentAddressPublic, cpEnd) < 0){
			return -1;
	}
	return 0;
}

void MessageHandler::push(int, Packet* p){
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

CLICK_ENDDECLS
EXPORT_ELEMENT(MessageHandler)
