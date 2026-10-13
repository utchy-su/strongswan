/*
 * Copyright (C) 2012-2013 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "ipsec_types.h"

ENUM(ipsec_mode_names, MODE_TRANSPORT, MODE_DROP,
	"TRANSPORT",
	"TUNNEL",
	"BEET",
	"PASS",
	"DROP"
);

ENUM(policy_dir_names, POLICY_IN, POLICY_FWD,
	"in",
	"out",
	"fwd"
);

ENUM(ipcomp_transform_names, IPCOMP_NONE, IPCOMP_LZJH,
	"IPCOMP_NONE",
	"IPCOMP_OUI",
	"IPCOMP_DEFLATE",
	"IPCOMP_LZS",
	"IPCOMP_LZJH"
);

ENUM(hw_offload_names, HW_OFFLOAD_NO, HW_OFFLOAD_AUTO,
	"no",
	"yes",
	"auto",
);

ENUM(dscp_copy_names, DSCP_COPY_OUT_ONLY, DSCP_COPY_NO,
	"out",
	"in",
	"yes",
	"no",
);

/*
 * See header
 */
bool ipsec_sa_cfg_equals(ipsec_sa_cfg_t *a, ipsec_sa_cfg_t *b)
{
	return a->mode == b->mode &&
		a->reqid == b->reqid &&
		a->policy_count == b->policy_count &&
		a->esp.use == b->esp.use &&
		a->esp.spi == b->esp.spi &&
		a->ah.use == b->ah.use &&
		a->ah.spi == b->ah.spi &&
		a->ipcomp.transform == b->ipcomp.transform &&
		a->ipcomp.cpi == b->ipcomp.cpi;
}

/**
 * Check if the given mask covers only the least significant bits.
 */
static bool mark_is_low_mask(uint32_t mask)
{
	return mask && !(mask & (mask + 1));
}

/**
 * Derive a shift count from a low-bit mask like 0xff.
 */
static bool shift_from_low_mask(u_long mask, uint8_t *shift)
{
	uint8_t width = 0;

	if (mask > (u_long)UINT32_MAX || !mark_is_low_mask(mask))
	{
		return FALSE;
	}
	while (mask)
	{
		width++;
		mask >>= 1;
	}
	if (width > 31)
	{
		return FALSE;
	}
	*shift = width;
	return TRUE;
}

/**
 * Parse an explicit shift count or a low-bit hexadecimal mask.
 */
static bool parse_mark_shift(char *shiftptr, char **endptr, uint8_t *shift)
{
	u_long parsed;

	parsed = strtoul(shiftptr, endptr, 0);
	if (shiftptr == *endptr)
	{
		DBG1(DBG_APP, "invalid mark shift: %s", shiftptr);
		return FALSE;
	}
	if (strcasepfx(shiftptr, "0x") && shift_from_low_mask(parsed, shift))
	{
		return TRUE;
	}
	if (parsed > 31)
	{
		DBG1(DBG_APP, "invalid mark shift: %lu", parsed);
		return FALSE;
	}
	*shift = parsed;
	return TRUE;
}

/*
 * See header
 */
bool mark_from_string(const char *value, mark_op_t ops, mark_t *mark)
{
	char *endptr, *shiftptr;
	bool mask = FALSE, same = FALSE;

	if (!value)
	{
		return FALSE;
	}
	*mark = (mark_t){};
	if (strcasepfx(value, "%unique"))
	{
		if (!(ops & MARK_OP_UNIQUE))
		{
			DBG1(DBG_APP, "unexpected use of %%unique mark", value);
			return FALSE;
		}
		endptr = (char*)value + strlen("%unique");
		if (strcasepfx(endptr, "-dir"))
		{
			mark->value = MARK_UNIQUE_DIR;
			endptr += strlen("-dir");
		}
		else if (!*endptr || *endptr == '/' || strpfx(endptr, "<<"))
		{
			mark->value = MARK_UNIQUE;
		}
		else
		{
			DBG1(DBG_APP, "invalid mark value: %s", value);
			return FALSE;
		}
	}
	else if (strcasepfx(value, "%same"))
	{
		if (!(ops & MARK_OP_SAME))
		{
			DBG1(DBG_APP, "unexpected use of %%same mark", value);
			return FALSE;
		}
		same = TRUE;
		endptr = (char*)value + strlen("%same");
		if (!*endptr || *endptr == '/' || strpfx(endptr, "<<"))
		{
			mark->value = MARK_SAME;
		}
		else
		{
			DBG1(DBG_APP, "invalid mark value: %s", value);
			return FALSE;
		}
	}
	else
	{
		mark->value = strtoul(value, &endptr, 0);
	}
	if (*endptr == '/')
	{
		mask = TRUE;
		mark->mask = strtoul(endptr+1, &endptr, 0);
	}
	else
	{
		mark->mask = 0xffffffff;
	}
	if (strpfx(endptr, "<<"))
	{
		if (same)
		{
			DBG1(DBG_APP, "unexpected use of mark shift: %s", value);
			return FALSE;
		}
		shiftptr = endptr + 2;
		if (!parse_mark_shift(shiftptr, &endptr, &mark->shift))
		{
			return FALSE;
		}
	}
	if (*endptr)
	{
		DBG1(DBG_LIB, "invalid mark value: %s", endptr);
		return FALSE;
	}
	if (mask && mark->shift && mark_is_low_mask(mark->mask))
	{
		mark->mask <<= mark->shift;
	}
	if (!MARK_IS_UNIQUE(mark->value))
	{
		if (mark->shift)
		{
			mark->value = mark_apply_unique(*mark, mark->value);
			mark->shift = 0;
		}
		else
		{
			/* apply the mask to ensure the value is in range */
			mark->value &= mark->mask;
		}
	}
	return TRUE;
}

/*
 * See header
 */
uint32_t mark_apply_unique(mark_t mark, uint32_t value)
{
	if (mark.shift)
	{
		value <<= mark.shift;
		value &= mark.mask;
	}
	return value;
}

/*
 * Described in header
 */
bool if_id_from_string(const char *value, uint32_t *if_id)
{
	char *endptr;

	if (!value)
	{
		return FALSE;
	}
	if (strcasepfx(value, "%unique"))
	{
		endptr = (char*)value + strlen("%unique");
		if (strcasepfx(endptr, "-dir"))
		{
			*if_id = IF_ID_UNIQUE_DIR;
			endptr += strlen("-dir");
		}
		else if (!*endptr)
		{
			*if_id = IF_ID_UNIQUE;
		}
		else
		{
			DBG1(DBG_APP, "invalid interface ID: %s", value);
			return FALSE;
		}
	}
	else
	{
		*if_id = strtoul(value, &endptr, 0);
	}
	if (*endptr)
	{
		DBG1(DBG_APP, "invalid interface ID: %s", value);
		return FALSE;
	}
	return TRUE;
}

/*
 * Described in header
 */
void allocate_unique_if_ids(uint32_t *in, uint32_t *out)
{
	static refcount_t unique_if_id = 0;

	if (IF_ID_IS_UNIQUE(*in) || IF_ID_IS_UNIQUE(*out))
	{
		refcount_t if_id = 0;
		bool unique_dir = *in == IF_ID_UNIQUE_DIR ||
						  *out == IF_ID_UNIQUE_DIR;

		if (!unique_dir)
		{
			if_id = ref_get(&unique_if_id);
		}
		if (IF_ID_IS_UNIQUE(*in))
		{
			*in = unique_dir ? ref_get(&unique_if_id) : if_id;
		}
		if (IF_ID_IS_UNIQUE(*out))
		{
			*out = unique_dir ? ref_get(&unique_if_id) : if_id;
		}
	}
}
