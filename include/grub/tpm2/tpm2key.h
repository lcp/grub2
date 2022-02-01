/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2023 SUSE LLC
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_TPM2_TPM2KEY_HEADER
#define GRUB_TPM2_TPM2KEY_HEADER 1

#include <grub/types.h>
#include <grub/libtasn1.h>

grub_err_t
grub_tpm2key_start_parsing (asn1_node *parsed_tpm2key, void *data, grub_size_t size);

void
grub_tpm2key_end_parsing (asn1_node tpm2key);

grub_err_t
grub_tpm2key_get_parent (asn1_node tpm2key, grub_uint32_t *parent);

grub_err_t
grub_tpm2key_get_pubkey (asn1_node tpm2key, void **data, grub_size_t *size);

grub_err_t
grub_tpm2key_get_privkey (asn1_node tpm2key, void **data, grub_size_t *size);

#endif /* GRUB_TPM2_TPM2KEY_HEADER */
