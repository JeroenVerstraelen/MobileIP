#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>

// Local imports
#include "Advertiser.hh"
#include "structs/ICMPAdvertisement.hh"
#include "structs/MobilityAgentAdvertisementExtension.hh"

CLICK_DECLS
Advertiser::Advertiser(): _advertisementCounter(0), _advertisementTimer(this){}

Advertiser::~ Advertiser(){}

int Advertiser::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "ROUTERADDRESS", cpkM, cpIPAddress, &_routerAddress, \
	"COA", cpkM, cpIPAddress, &_careOfAddress, cpEnd) < 0){
			return -1;
	}
	_advertisementTimer.initialize(this);
	_advertisementTimer.schedule_now();
	return 0;
}

void Advertiser::run_timer(Timer* t){
	if (t == &_advertisementTimer){
		_generateAdvertisement();
		t->clear();
	}
}

void Advertiser::_generateAdvertisement() {
	click_chatter("Router advertisement");
	int tailroom = 0;
	int headroom = sizeof(click_ether);
	int packetsize = sizeof(click_ip) + sizeof(ICMPAdvertisement) + sizeof(MobilityAgentAdvertisementExtension);
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
	iph->ip_src = _routerAddress.in_addr();
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

	// ICMP advertisement related part
	ICMPAdvertisement* advertisement = (ICMPAdvertisement*) (packet->data() + sizeof(click_ip));
	advertisement->type = 9;
	advertisement->code = 0;
	advertisement->checksum = 0x0;
	advertisement->numAddrs = 1;
	advertisement->addrEntrySize = 2;
	advertisement->lifetime = htons(45); //TODO
	advertisement->routerAddress = _routerAddress.addr();
	advertisement->preferenceLevel = htonl(0x1);
	
	// Mobility agent advertisement extension
	MobilityAgentAdvertisementExtension* extension = (MobilityAgentAdvertisementExtension*) (packet->data() + sizeof(click_ip) + sizeof(ICMPAdvertisement));
	extension->type = 16;
	extension->length = 6+(4*1); 	// TODO maybe add variable N value here, N = 1 momentarily
	extension->sequenceNumber = htons(_advertisementCounter);
	_advertisementCounter++;	// Keep track of amount of advertisements were sent
	extension->registrationLifetime = htons(30);	// TODO maybe change value
	extension->R = 1;
	extension->B = 0;
	extension->H = 1;
	extension->F = 0;	// In the future this must be configurable (agent can be HA and FA at the same time)
	extension->M = 0;
	extension->G = 0;
	extension->r = 0;
	extension->T = 0;
	extension->U = 0;
	extension->X = 0;
	extension->I = 0;
	extension->reserved = 0;
	extension->careOfAddress = _careOfAddress.addr();

		// Checksum
	advertisement->checksum = click_in_cksum((unsigned char *) advertisement, sizeof(ICMPAdvertisement) + sizeof(MobilityAgentAdvertisementExtension));

	// Sent the advertisement to neighboring interface
	output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Advertiser)
