#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "xt_tlsext.h"

MODULE_AUTHOR("llccd <me@llccd.eu.org>");
MODULE_DESCRIPTION("Xtables: TLS extension match");
MODULE_LICENSE("GPL");

static bool tlsext_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_tlsext_info *info = par->matchinfo;
	struct tcphdr *tcph, _tcph;
	__u8 tmp[4];
	__u16 offset, tls_end_offset;

	tcph = skb_header_pointer(skb, par->thoff, sizeof(_tcph), &_tcph);
	offset = par->thoff + tcph->doff * 4;
	if (skb->len - offset <= 43)
		return false;

	// If this isn't an TLS handshake, abort
	skb_copy_bits(skb, offset, tmp, 1);
	if (tmp[0] != 0x16)
		return false;

	offset += 3;
	skb_copy_bits(skb, offset, tmp, 3);
	tls_end_offset = ((tmp[0] << 8) | tmp[1]) + offset + 2;

	// Even if we don't have all the data, try matching anyway
	if (tls_end_offset > skb->len)
		tls_end_offset = skb->len;

	if ((tmp[2] == info->type) ^ (info->invert & XT_TLSEXT_OP_TYPE)) {
		u_int extensions_end;
		__u8 compression_len, session_id_len;
		__u16 cipher_len, extensions_len;

		offset += 40;

		// Get the length of the session ID
		skb_copy_bits(skb, offset, &session_id_len, 1);
		offset += session_id_len + 1;

		if ((offset + 1) > tls_end_offset)
			return false;

		// Get the length of the ciphers
		skb_copy_bits(skb, offset, tmp, 2);
		cipher_len = (tmp[0] << 8) | tmp[1];
		offset += cipher_len + 2;

		if (offset > tls_end_offset)
			return false;

		// Get the length of the compression types
		skb_copy_bits(skb, offset, &compression_len, 1);
		offset += compression_len + 1;

		if ((offset + 1) > tls_end_offset)
			return false;

		// Get the length of all the extensions
		skb_copy_bits(skb, offset, tmp, 2);
		extensions_len = (tmp[0] << 8) | tmp[1];
		offset += 2;
		extensions_end = extensions_len + offset;

		if (extensions_end > tls_end_offset)
			extensions_end = tls_end_offset;

		// Loop through all the extensions
		while (offset + 3 < extensions_end) {
			u_int16_t extension_id, extension_len;

			skb_copy_bits(skb, offset, tmp, 4);
			extension_id = (tmp[0] << 8) | tmp[1];
			if (extension_id == info->ext)
				return !(info->invert & XT_TLSEXT_OP_EXT);

			extension_len = (tmp[2] << 8) | tmp[3];
			offset += extension_len + 4;
		}
		return info->invert & XT_TLSEXT_OP_EXT;
	}

	return false;
}

static struct xt_match tlsext_mt_regs[] __read_mostly = {
	{
		.name       = "tlsext",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.match      = tlsext_mt,
		.matchsize  = sizeof(struct xt_tlsext_info),
		.proto      = IPPROTO_TCP,
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name       = "tlsext",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.match      = tlsext_mt,
		.matchsize  = sizeof(struct xt_tlsext_info),
		.proto      = IPPROTO_TCP,
		.me         = THIS_MODULE,
	},
#endif
};

static int __init tlsext_init(void)
{
	return xt_register_matches(tlsext_mt_regs, ARRAY_SIZE(tlsext_mt_regs));
}

static void __exit tlsext_exit(void)
{
	xt_unregister_matches(tlsext_mt_regs, ARRAY_SIZE(tlsext_mt_regs));
}

module_init(tlsext_init);
module_exit(tlsext_exit);

MODULE_ALIAS("ipt_tlsext");
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
MODULE_ALIAS("ip6t_tlsext");
#endif
