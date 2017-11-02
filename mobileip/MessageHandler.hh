#ifndef CLICK_MESSAGEHANDLER_HH
#define CLICK_MESSAGEHANDLER_HH
#include <click/element.hh>
CLICK_DECLS

/*
 *	Click element that will handle incoming messages like the ICMP solicitations message
 *	and the registration request message at the agent side
 *	It will generate specific replies depending the current situation
 *	Input 0 ==> messages with DST 255.255.255.255
 *	Input 1 ==> directed messages to the agent itself
 * 	Output 0 ==> packets to private network
 *	Output 1 ==> packets to agent itself
*/
class MessageHandler : public Element {
	public:
		MessageHandler();
		~MessageHandler();

		const char *class_name() const	{ return "MessageHandler"; }
		const char *port_count() const	{ return "2/2"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		void push(int, Packet* p);

	private:
		// IPAddress of the agent
		IPAddress _agentAddressPublic;
};

CLICK_ENDDECLS
#endif
