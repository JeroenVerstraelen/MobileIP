#ifndef CLICK_REQUESTGENERATOR_HH
#define CLICK_REQUESTGENERATOR_HH
#include <click/element.hh>
#include <click/timer.hh>
CLICK_DECLS

/*
 *	Click element that will generate requests at the mobile node
 *	Mobile node will send requests when he has determined that his current agent is no longer online
 *  or if the mobile node has moved to a foreign network
*/
class RequestGenerator : public Element {
	public:
		RequestGenerator();
		~RequestGenerator();

		const char *class_name() const	{ return "RequestGenerator"; }
		const char *port_count() const	{ return "0/1"; } // TODO the generator will probably have an input in the future to deal with incoming replies
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void run_timer(Timer* t);


	private:
		// Source address of the mobile node
    IPAddress _srcAddress;

		// IP address of the mobile node's home agent
		IPAddress _homeAgent;

		// TODO delete this?
		Timer _timer;

    // Vector of potential agents
    // The generator will use the first IP address of the vector as destination address of its request message
    Vector<IPAddress> potentialAgents;

    // Generate a registration request and push it to output 0
    void _generateRequest();
};

CLICK_ENDDECLS
#endif
