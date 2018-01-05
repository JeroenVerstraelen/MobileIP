#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>

// Local imports
#include "Advertiser.hh"
#include "structs/ICMPAdvertisement.hh"
#include "structs/MobilityAgentAdvertisementExtension.hh"
#include "utils/Configurables.hh"
#include "utils/HelperFunctions.hh"
#include <iostream>
#include <stdlib.h>

#define MAX_INITIAL_ADVERT_INTERVAL 16
#define MAX_INITIAL_ADVERTISEMENTS 3
#define MAX_RESPONSE_DELAY 2

CLICK_DECLS
Advertiser::Advertiser(): _advertisementCounter(0), _advertisementTimer(this){}

Advertiser::~ Advertiser(){}

int Advertiser::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(
		conf, this, errh, 
		"PRIVATE", cpkM, cpIPAddress, &_routerAddressPrivate, \
		"PUBLIC", cpkM, cpIPAddress, &_routerAddressPublic, \
		cpEnd) < 0) {
			return -1;
	}
	return 0;
}

int Advertiser::initialize(ErrorHandler *) {
	// Initialize rand used for the advertisement timer
	srand (_routerAddressPrivate.addr());
	// Initialize timer object
	_advertisementTimer.initialize(this);
	return 0;
}

void Advertiser::run_timer(Timer* t){
	if (t == &_advertisementTimer){
		// Reschedule the timer
		unsigned int interval = generateRandomNumber(MinAdvertisementInterval*1000, 
							     MaxAdvertisementInterval*1000);
		// Router advertisement condition
		/*
		if (_advertisementCounter <= MAX_INITIAL_ADVERTISEMENTS) {
			if (interval > MAX_INITIAL_ADVERT_INTERVAL*1000)
				interval = MAX_INITIAL_ADVERT_INTERVAL*1000;
		}
		*/
		// Agent advertisement condition
		/*
		if (interval > (AdvertisementLifetime/3)*1000)
			interval = (AdvertisementLifetime/3)*1000;
		*/
		_advertisementTimer.reschedule_after_msec(interval);
		// Send advertisement
		_generateAdvertisement();
	}
}

void Advertiser::respondToSolicitation(){
	LOG("[Advertiser] Responding to solicitation");
	unsigned int delay = generateRandomNumber(0, MAX_RESPONSE_DELAY*1000);
	_advertisementTimer.schedule_after_msec(delay);
}

void Advertiser::_generateAdvertisement() {
	LOG("[Advertiser] Sending ICMP router advertisement");
	int tailroom = 0;
	int headroom = sizeof(click_ether) + 4;
	int packetsize = 
	sizeof(click_ip) +
	sizeof(ICMPAdvertisement) +
	sizeof(MobilityAgentAdvertisementExtension);

	WritablePacket* packet = 
	Packet::make(headroom, 0, packetsize, tailroom);
	memset(packet->data(), 0, packet->length());

	// IP header
	click_ip *iph = (click_ip *) packet->data();
	iph->ip_v = 4;
  	iph->ip_hl = sizeof(click_ip) >> 2;
	iph->ip_len = htons(packet->length());
	iph->ip_id = htons(_advertisementCounter);
  	iph->ip_p = 1;
	iph->ip_tos = 0x00;
  	iph->ip_ttl = 1;
	iph->ip_dst = AdvertisementAddress.in_addr();
	iph->ip_src = _routerAddressPrivate.in_addr();
	iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
	packet->set_dst_ip_anno(AdvertisementAddress);

	// ICMP advertisement
	ICMPAdvertisement* advertisement = 
	(ICMPAdvertisement*) (packet->data() + sizeof(click_ip));
	advertisement->type = 9;
	advertisement->code = 0;
	advertisement->checksum = 0x0;
	// Number of router addresses advertised
	advertisement->numAddrs = 1;
	advertisement->addrEntrySize = 2;
	advertisement->lifetime = htons(AdvertisementLifetime);
	advertisement->routerAddress = _routerAddressPublic.addr();
	advertisement->preferenceLevel = htonl(0x1);

	// Mobility agent advertisement extension
	MobilityAgentAdvertisementExtension* extension = 
	(MobilityAgentAdvertisementExtension*) (packet->data() +
					       sizeof(click_ip) +
                                               sizeof(ICMPAdvertisement));
	extension->type = 16;
	extension->length = 6+(4*1);
	extension->sequenceNumber = htons(_advertisementCounter);
	// Keep track of amount of advertisements were sent
	_advertisementCounter++;
	// Sequence numbers only go from 0 to 0xffff (65535)
	if (_advertisementCounter >= 65536) {
		_advertisementCounter = 256;
	}
	extension->registrationLifetime = htons(registrationLifetime);
	extension->R = 1;
	extension->B = 0;
	extension->H = 1;
	extension->F = 1;
	extension->M = 0;
	extension->G = 0;
	extension->r = 0;
	extension->T = 0;
	extension->U = 0;
	extension->X = 0;
	extension->I = 0;
	extension->reserved = 0;
	extension->careOfAddress = _routerAddressPublic.addr();

	// Checksum
	advertisement->checksum = 
	click_in_cksum((unsigned char *) advertisement,
		       sizeof(ICMPAdvertisement) + sizeof(MobilityAgentAdvertisementExtension));
	// Sent the advertisement to neighboring interface
	output(0).push(packet);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Advertiser)
