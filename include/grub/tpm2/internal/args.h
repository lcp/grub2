/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
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

#ifndef GRUB_TPM2_INTERNAL_ARGS_HEADER
#define GRUB_TPM2_INTERNAL_ARGS_HEADER 1

#include <grub/err.h>
#include <grub/tpm2/tpm2.h>

struct grub_srk_type
{
  TPMI_ALG_PUBLIC type;
  TPMI_ALG_HASH nameAlg;
  TPM_KEY_BITS aes_bits;
  union {
    TPM_KEY_BITS rsa_bits;
    TPM_ECC_CURVE ecc_curve;
  } detail;
};
typedef struct grub_srk_type grub_srk_type_t;

grub_err_t
grub_tpm2_protector_parse_pcrs (char *value, grub_uint8_t *pcrs,
				grub_uint8_t *pcr_count);

grub_err_t
grub_tpm2_protector_parse_asymmetric (const char *value,
				      grub_srk_type_t *srk_type);

grub_err_t
grub_tpm2_protector_parse_bank (const char *value, TPM_ALG_ID *bank);

grub_err_t
grub_tpm2_protector_parse_tpm_handle (const char *value, TPM_HANDLE *handle);

#endif /* ! GRUB_TPM2_INTERNAL_ARGS_HEADER */
