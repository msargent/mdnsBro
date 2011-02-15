// $Id:$

#ifndef mdns_binpac_h
#define mdns_binpac_h

#include "UDP.h"
#include "TCP.h"

#include "dns_pac.h"

// FIXME: As the binpac analyer for DNS-TCP and DNS-UDP are currently
// structured, we cannot directly combine them into one analyzer. Can we
// change that easily? (Ideally, the TCP preprocessing would become a
// support-analyzer as it is done for the traditional DNS analyzer.)

class MDNS_Analyzer_binpac : public Analyzer {
public:
	MDNS_Analyzer_binpac(Connection* conn);
	virtual ~MDNS_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new MDNS_Analyzer_binpac(conn); }

	static bool Available()
		{ return (dns_request || dns_full_request) && FLAGS_use_binpac; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);

	int did_session_done;

	binpac::DNS::DNS_Conn* interp;
};

#endif
