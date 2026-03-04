#ifndef ICMP_H
#define ICMP_H

// Some sick and twisted linux developer has if.h, which is included by icmp.h,
// include sys/socket.h (Which isn't usable here)
//
// The workaround i've found is to rip this struct from icmp.h
struct icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
		__u8 reserved[4];
	} un;
};

#endif
