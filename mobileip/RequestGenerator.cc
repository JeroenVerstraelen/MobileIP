#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>

// Local imports
#include "RequestGenerator.hh"
#include "structs/RegistrationRequest.hh"
#include "utils/Configurables.hh"

CLICK_DECLS
RequestGenerator::RequestGenerator():_timer(this){}

RequestGenerator::~ RequestGenerator(){}

int RequestGenerator::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &_srcAddress,\
			"HA", cpkM, cpIPAddress, &_homeAgent, cpEnd) < 0){
			return -1;
	}
	_timer.initialize(this);
	//_timer.schedule_after_msec(10000);
	return 0;
}

void RequestGenerator::run_timer(Timer* t){
	_generateRequest();
}

void RequestGenerator::_generateRequest(){
  click_chatter("Request message");
	int tailroom = 0;
	int headroom = sizeof(click_ether);
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
  iph->ip_dst = IPAddress("192.168.3.254").in_addr(); // TODO use IP address found in potential agent vector here
  iph->ip_src = _srcAddress.in_addr();
  iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

  // UDP header
  click_udp *udpHeader = (click_udp *) (packet->data() + sizeof(click_ip));
  udpHeader->uh_sport = htons(0);
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
	request->lifetime = htons(requestLifetime);
	request->homeAddress = _srcAddress.addr();
	request->homeAgent = _homeAgent.addr();
	request->careOfAddress = IPAddress("0.0.0.0").addr(); //TODO fix the FA address here
	request->identification = Timestamp().now_steady().doubleval();

	// Set the UDP header checksum based on the initialized values
	unsigned csum = click_in_cksum((unsigned char *)udpHeader, sizeof(click_udp) + sizeof(RegistrationRequest));
	udpHeader->uh_sum = click_in_cksum_pseudohdr(csum, iph, sizeof(click_udp) + sizeof(RegistrationRequest));
	output(0).push(packet);
}
CLICK_ENDDECLS
EXPORT_ELEMENT(RequestGenerator)
