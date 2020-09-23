// This file contains the struct for the registration reply
// sent by an agent as an answer to a registration request (which was sent by a mobile node)
// The struct has the packed attribute
// because we want to work with the actual size of the struct and not the padded one

struct __attribute__ ((__packed__)) RegistrationReply {
    uint8_t type;
    uint8_t code;
    uint16_t lifetime;
    uint32_t homeAddress;
    uint32_t homeAgent;
    uint64_t identification;
};
