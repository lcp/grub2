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

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/tpm2/internal/args.h>

grub_err_t
grub_tpm2_protector_parse_pcrs (char *value, grub_uint8_t *pcrs,
				grub_uint8_t *pcr_count)
{
  char *current_pcr = value;
  char *next_pcr;
  unsigned long pcr;
  grub_uint8_t i;

  if (grub_strlen (value) == 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *pcr_count = 0;
  for (i = 0; i < TPM_MAX_PCRS; i++)
    {
      next_pcr = grub_strchr (current_pcr, ',');
      if (next_pcr == current_pcr)
	return grub_error (GRUB_ERR_BAD_ARGUMENT,
			   N_("Empty entry in PCR list"));
      if (next_pcr)
	*next_pcr = '\0';

      grub_errno = GRUB_ERR_NONE;
      pcr = grub_strtoul (current_pcr, NULL, 10);
      if (grub_errno != GRUB_ERR_NONE)
	return grub_error (grub_errno,
			   N_("Entry '%s' in PCR list is not a number"),
			   current_pcr);

      if (pcr > TPM_MAX_PCRS)
	return grub_error (GRUB_ERR_OUT_OF_RANGE,
			   N_("Entry %lu in PCR list is too large to be a PCR "
			      "number, PCR numbers range from 0 to %u"),
			   pcr, TPM_MAX_PCRS);

      pcrs[i] = (grub_uint8_t)pcr;
      *pcr_count += 1;

      if (next_pcr == NULL)
	break;

      current_pcr = next_pcr + 1;
      if (*current_pcr == '\0')
	return grub_error (GRUB_ERR_BAD_ARGUMENT,
			   N_("Trailing comma at the end of PCR list"));
    }

  if (i == TPM_MAX_PCRS)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("Too many PCRs in PCR list, the maximum number of "
			  "PCRs is %u"), TPM_MAX_PCRS);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2_protector_parse_asymmetric (const char *value,
				      TPM_ALG_ID *asymmetric,
				      TPM_KEY_BITS *rsa_bits,
				      TPM_ECC_CURVE *ecc_curve)
{
  if (grub_strcasecmp (value, "ECC") == 0 ||
      grub_strcasecmp (value, "ECC_NIST_P256") == 0)
    {
      *asymmetric = TPM_ALG_ECC;
      *ecc_curve = TPM_ECC_NIST_P256;
    }
  else if (grub_strcasecmp (value, "RSA") == 0 ||
	   grub_strcasecmp (value, "RSA2048") == 0)
    {
      *asymmetric = TPM_ALG_RSA;
      *rsa_bits = 2048;
    }
  else if (grub_strcasecmp (value, "RSA3072") == 0)
    {
      *asymmetric = TPM_ALG_RSA;
      *rsa_bits = 3072;
    }
  else if (grub_strcasecmp (value, "RSA4096") == 0)
    {
      *asymmetric = TPM_ALG_RSA;
      *rsa_bits = 4096;
    }
  else if (grub_strcasecmp (value, "ECC_NIST_P384") == 0)
    {
      *asymmetric = TPM_ALG_ECC;
      *ecc_curve = TPM_ECC_NIST_P384;
    }
  else if (grub_strcasecmp (value, "ECC_NIST_P521") == 0)
    {
      *asymmetric = TPM_ALG_ECC;
      *ecc_curve = TPM_ECC_NIST_P521;
    }
  else if (grub_strcasecmp (value, "ECC_BN_P256") == 0)
    {
      *asymmetric = TPM_ALG_ECC;
      *ecc_curve = TPM_ECC_BN_P256;
    }
  else if (grub_strcasecmp (value, "ECC_BN_P638") == 0)
    {
      *asymmetric = TPM_ALG_ECC;
      *ecc_curve = TPM_ECC_BN_P638;
    }
  else if (grub_strcasecmp (value, "ECC_SM2_P256") == 0)
    {
      *asymmetric = TPM_ALG_ECC;
      *ecc_curve = TPM_ECC_SM2_P256;
    }
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("Value '%s' is not a valid asymmetric key type"),
		       value);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2_protector_parse_bank (const char *value, TPM_ALG_ID *bank)
{
  if (grub_strcasecmp (value, "SHA1") == 0)
    *bank = TPM_ALG_SHA1;
  else if (grub_strcasecmp (value, "SHA256") == 0)
    *bank = TPM_ALG_SHA256;
  else if (grub_strcasecmp (value, "SHA384") == 0)
    *bank = TPM_ALG_SHA384;
  else if (grub_strcasecmp (value, "SHA512") == 0)
    *bank = TPM_ALG_SHA512;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("Value '%s' is not a valid PCR bank"), value);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2_protector_parse_tpm_handle (const char *value, TPM_HANDLE *handle)
{
  unsigned long num;

  grub_errno = GRUB_ERR_NONE;
  num = grub_strtoul (value, NULL, 0);
  if (grub_errno != GRUB_ERR_NONE)
    return grub_error (grub_errno, N_("TPM handle value '%s' is not a number"),
		       value);

  if (num > GRUB_UINT_MAX)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("Value %lu is too large to be a TPM handle, TPM "
			  "handles are unsigned 32-bit integers"), num);

  *handle = (TPM_HANDLE)num;

  return GRUB_ERR_NONE;
}
