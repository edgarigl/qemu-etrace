/*
 * Stable hashes used by the ETrace wire format.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef ETRACE_HASH_H
#define ETRACE_HASH_H

#include <stddef.h>
#include <stdint.h>

static inline uint64_t etrace_code_hash(const void *data, size_t len)
{
	const uint8_t *bytes = data;
	uint64_t hash = UINT64_C(14695981039346656037);
	size_t i;

	for (i = 0; i < len; i++) {
		hash ^= bytes[i];
		hash *= UINT64_C(1099511628211);
	}
	return hash;
}

#endif
