#ifndef _XT_TLSEXT_H
#define _XT_TLSEXT_H

#include <linux/types.h>

#define XT_TLSEXT_OP_TYPE	0x01
#define XT_TLSEXT_OP_EXT	0x02

enum {
	O_TLSEXT_TYPE = 0,
	O_TLSEXT_EXT,
};

struct xt_tlsext_info {
	__u8	invert;
	__u8	type;
	__u16	ext;
};

#endif
