/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/* This code is taken from the illumos kernel and is licensed under the CDDL */

#define BSWAP_64(x) (((uint64_t)(x) << 56) | \
      (((uint64_t)(x) << 40) & 0xff000000000000ULL) | \
      (((uint64_t)(x) << 24) & 0xff0000000000ULL) | \
      (((uint64_t)(x) << 8)  & 0xff00000000ULL) | \
      (((uint64_t)(x) >> 8)  & 0xff000000ULL) | \
      (((uint64_t)(x) >> 24) & 0xff0000ULL) | \
      (((uint64_t)(x) >> 40) & 0xff00ULL) | \
      ((uint64_t)(x)  >> 56))
