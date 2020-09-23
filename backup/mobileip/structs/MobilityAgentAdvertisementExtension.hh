// This file contains the struct for the Mobility Agent Advertisement Extension (MAAE)
// This extension is added to the ICMP router advertisement message
struct MobilityAgentAdvertisementExtension{
	uint8_t type;
	uint8_t length;
	uint16_t sequenceNumber;
	uint16_t registrationLifetime;
	unsigned T:1;
	unsigned r:1;
	unsigned G:1;
	unsigned M:1;
	unsigned F:1;
	unsigned H:1;
	unsigned B:1;
	unsigned R:1;
	unsigned reserved:5;
	unsigned I:1;
	unsigned X:1;
	unsigned U:1;
	uint32_t careOfAddress;
};
