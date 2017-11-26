// This file contains the struct for the Mobility binding of a Mobile node
// This information is kept at the home agent

struct MobilityBinding {
    uint32_t homeAddress;
    uint32_t careOfAddress;
    uint16_t lifetime;
    double replyIdentification;
};
