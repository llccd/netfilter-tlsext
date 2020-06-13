#include <stdio.h>
#include <xtables.h>
#include "xt_tlsext.h"

static void tls_help(void)
{
	printf("tlsext match options:\n"
		"[!] --handshake-type type	TLS handshake type\n"
		"[!] --has-ext type		TLS extension\n");
}

static const struct xt_option_entry tls_opts[] = {
	{
		.name = "handshake-type",
		.id = O_TLSEXT_TYPE,
		.type = XTTYPE_UINT8,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tlsext_info, type),
	},
	{
		.name = "has-ext",
		.id = O_TLSEXT_EXT,
		.type = XTTYPE_UINT16,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tlsext_info, ext),
	},
	XTOPT_TABLEEND,
};

static void tls_parse(struct xt_option_call *cb)
{
	struct xt_tlsext_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_TLSEXT_TYPE:
			if (cb->invert)
				info->invert |= XT_TLSEXT_OP_TYPE;
			break;
		case O_TLSEXT_EXT:
			if (cb->invert)
				info->invert |= XT_TLSEXT_OP_EXT;
			break;
	}
}

static void tls_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tlsext_info *info = (const struct xt_tlsext_info *)match->data;

	printf(" tlsext match");
	printf("%s handshake-type %d", (info->invert & XT_TLSEXT_OP_TYPE) ? " !":"", info->type);
	printf("%s extension %d", (info->invert & XT_TLSEXT_OP_EXT) ? " !":"", info->ext);
}

static void tls_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tlsext_info *info = (const struct xt_tlsext_info *)match->data;

	printf("%s --handshake-type %d", (info->invert & XT_TLSEXT_OP_TYPE) ? " !":"", info->type);
	printf("%s --has-ext %d", (info->invert & XT_TLSEXT_OP_EXT) ? " !":"", info->ext);
}

static struct xtables_match tlsext_match = {
	.name		= "tlsext",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(struct xt_tlsext_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tlsext_info)),
	.help		= tls_help,
	.print		= tls_print,
	.save		= tls_save,
	.x6_parse	= tls_parse,
	.x6_options	= tls_opts,
};

void _init(void)
{
	xtables_register_match(&tlsext_match);
}
