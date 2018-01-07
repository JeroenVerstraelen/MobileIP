// This file contains the struct for an ICMP solicitation message
// (sent by a mobile agent to learn if any prospective agents are present on the network)

struct ICMPSolicitation{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t reserved;
};
