# $Id:$

%include bro.pac

analyzer MDNS withcontext {
	connection:	DNS_Conn;
	flow:		DNS_Flow;
};

%include mdns-protocol.pac
%include mdns-analyzer.pac
