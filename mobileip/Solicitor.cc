#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>

// Local imports
#include "Solicitor.hh"
#include "structs/ICMPSolicitation.hh"
#include "utils/HelperFunctions.hh"

#define MAX_SOLICITATION_DELAY 1
#define SOLICITATION_INTERVAL 5

CLICK_DECLS
Solicitor::Solicitor():_solicitationTimer(this){}

Solicitor::~ Solicitor(){}

int Solicitor::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(
		conf, this, errh, \
		"SRC", cpkM, cpIPAddress, &_srcAddress, \
		cpEnd) < 0) {
			return -1;
	}
 	// Solicitation timer randomization uses IPAddress as seed
	srand (_srcAddress.addr());
	_solicitationTimer.initialize(this);
	// Generate solicitation on start up
	unsigned int delay = generateRandomNumber(0, MAX_SOLICITATION_DELAY*1000);
	_solicitationTimer.schedule_after_msec(delay);
	return 0;
}

void Solicitor::run_timer(Timer* t){
	if (t == &_solicitationTimer) {
		generateSolicitation();
		_solicitationTimer.schedule_after_sec(SOLICITATION_INTERVAL);
	}
}

void Solicitor::generateSolicitation() {
	LOG("[Solicitor] Sending ICMP router solicitation");
	int tailroom = 0;
	int headroom = sizeof(click_ether) + 4; // TODO check why necessary to add 4
	int packetsize = sizeof(click_ip) + sizeof(ICMPSolicitation);
	WritablePacket* packet = Packet::make(headroom, 0, packetsize, tailroom);
	memset(packet->data(), 0, packet->length());

	// IP header
	click_ip *iph = (click_ip *) packet->data();
	iph->ip_v = 4;
  	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(packet->length());
	iph->ip_id = htons(0);
  	iph->ip_p = 1;
	iph->ip_tos = 0x00;
  	iph->ip_ttl = 1;
	iph->ip_dst = IPAddress("255.255.255.255").in_addr();
	iph->ip_src = _srcAddress.in_addr();
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
	packet->set_dst_ip_anno(IPAddress(iph->ip_dst));

	// ICMP solicitation related part
	ICMPSolicitation* solicitation = (ICMPSolicitation*) (packet->data() + sizeof(click_ip));
	solicitation->type = 10;
	solicitation->code = 0;
	solicitation->checksum = 0x0;
	solicitation->reserved = htonl(0);

	// Checksum
	solicitation->checksum = click_in_cksum((unsigned char *) solicitation, sizeof(ICMPSolicitation));

	// Sent the solicitation to neighboring interface
	output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Solicitor)
