#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/icmp.h>

// Local imports
#include "EtherCheck.hh"

CLICK_DECLS
EtherCheck::EtherCheck(){}

EtherCheck::~ EtherCheck(){}

int EtherCheck::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(
		conf, this, errh,
		"MONITOR", cpkM, (Monitor*) cpElement, &_monitorMN,
		cpEnd) < 0) {
			return -1;
	}
	return 0;
}

void EtherCheck::push(int, Packet* p){
	click_ether* eth_h = (click_ether*) p->data();
	click_ip* ip_h = (click_ip*) (p->data() + sizeof(click_ether));
	if (ntohs(eth_h->ether_type) == 0x0800 && !_monitorMN->isHome()) {
		// ICMP message received while not at home.
		if (ip_h->ip_p == 1) {
			const click_icmp* icmp_h =  p->icmp_header();
			// ICMP agent advertisement
			if (icmp_h->icmp_type == 9) {
				// Record the source of the latest advertisement.
				for (int i=0; i<6; i++) 
					etherDest[i] = eth_h->ether_shost[i];
			}
			// Ping reply.
			if (icmp_h->icmp_type == 0) {
				// Change the destination address of the reply
				// Using the source from the latest advertisement.
				WritablePacket* q = p->uniqueify();
				q->pull(sizeof(click_ether));
				q->push(sizeof(click_ether));
				click_ether* newEtherHeader = (click_ether*) q->data();
				for (int i=0; i<6; i++) 
					newEtherHeader->ether_dhost[i] = etherDest[i];
				for (int i=0; i<6; i++) 
					newEtherHeader->ether_shost[i] = eth_h->ether_shost[i];
				newEtherHeader->ether_type = eth_h->ether_type;
				output(1).push(q);
				p->kill();
				return;
			}

		}

	}
	output(0).push(p);
};

CLICK_ENDDECLS
EXPORT_ELEMENT(EtherCheck)
