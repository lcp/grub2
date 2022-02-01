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

#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/libtasn1.h>
#include <grub/tpm2/tpm2key.h>

extern asn1_static_node tpm2key_asn1_tab[];
const char *sealed_key_oid = "2.23.133.10.1.5";

static int
asn1_allocate_and_read (asn1_node node, const char *name, void **content, grub_size_t *content_size)
{
  grub_uint8_t *tmpstr = NULL;
  int tmpstr_size = 0;
  int ret;

  if (content == NULL)
    return ASN1_MEM_ERROR;

  ret = asn1_read_value (node, name, NULL, &tmpstr_size);
  if (ret != ASN1_MEM_ERROR)
    return ret;

  tmpstr = grub_malloc (tmpstr_size);
  if (tmpstr == NULL)
    return ASN1_MEM_ERROR;

  ret = asn1_read_value (node, name, tmpstr, &tmpstr_size);
  if (ret != ASN1_SUCCESS)
    return ret;

  *content = tmpstr;
  *content_size = tmpstr_size;

  return ASN1_SUCCESS;
}

static int
asn1_read_uint32 (asn1_node node, const char *name, grub_uint32_t *out)
{
  grub_uint32_t tmp = 0;
  grub_uint8_t *ptr;
  void *data = NULL;
  grub_size_t data_size;
  int ret;

  ret = asn1_allocate_and_read (node, name, &data, &data_size);
  if (ret != ASN1_SUCCESS)
    return ret;

  if (data_size > 4)
    {
      ret = ASN1_MEM_ERROR;
      goto error;
    }

  /* convert the big-endian integer to host uint32 */
  ptr = (grub_uint8_t *)&tmp + (4 - data_size);
  grub_memcpy (ptr, data, data_size);
  tmp = grub_be_to_cpu32 (tmp);

  *out = tmp;
error:
  if (data)
    grub_free (data);
  return ret;
}

grub_err_t
grub_tpm2key_start_parsing (asn1_node *parsed_tpm2key, void *data, grub_size_t size)
{
  asn1_node tpm2key;
  asn1_node tpm2key_asn1 = NULL;
  void *type_oid = NULL;
  grub_size_t type_oid_size = 0;
  void *empty_auth = NULL;
  grub_size_t empty_auth_size = 0;
  int tmp_size = 0;
  int ret;
  grub_err_t err;

  /*
    TPMKey ::= SEQUENCE {
        type        OBJECT IDENTIFIER,
        emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
        policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
        secret      [2] EXPLICIT OCTET STRING OPTIONAL,
        authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
        parent      INTEGER,
        pubkey      OCTET STRING,
        privkey     OCTET STRING
    }
  */
  ret = asn1_array2tree (tpm2key_asn1_tab, &tpm2key_asn1, NULL);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_BAD_ARGUMENT;

  ret = asn1_create_element (tpm2key_asn1, "TPM2KEY.TPMKey", &tpm2key);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_BAD_ARGUMENT;

  ret = asn1_der_decoding (&tpm2key, data, size, NULL);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_BAD_ARGUMENT;

  /* Check if 'type' is Sealed Key or not */
  ret = asn1_allocate_and_read (tpm2key, "type", &type_oid, &type_oid_size);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_BAD_FILE_TYPE;

  if (grub_memcmp (sealed_key_oid, type_oid, type_oid_size) != 0)
    {
      err = GRUB_ERR_BAD_FILE_TYPE;
      goto error;
    }

  /* 'emptyAuth' must be 'TRUE' since we don't support password authorization */
  ret = asn1_allocate_and_read (tpm2key, "emptyAuth", &empty_auth, &empty_auth_size);
  if (ret != ASN1_SUCCESS || grub_strncmp ("TRUE", empty_auth, empty_auth_size) != 0)
    {
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  /* 'secret' should not be in a sealed key */
  ret = asn1_read_value (tpm2key, "secret", NULL, &tmp_size);
  if (ret != ASN1_ELEMENT_NOT_FOUND)
    {
      err = GRUB_ERR_BAD_ARGUMENT;
      goto error;
    }

  *parsed_tpm2key = tpm2key;

  err = GRUB_ERR_NONE;

error:
  if (type_oid)
    grub_free (type_oid);

  if (empty_auth)
    grub_free (empty_auth);

  return err;
}

void
grub_tpm2key_end_parsing (asn1_node tpm2key)
{
  if (tpm2key)
    asn1_delete_structure (&tpm2key);
  tpm2key = NULL;
}

grub_err_t
grub_tpm2key_get_parent (asn1_node tpm2key, grub_uint32_t *parent)
{
  int ret;

  if (parent == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  if (tpm2key == NULL)
    return GRUB_ERR_READ_ERROR;

  ret = asn1_read_uint32 (tpm2key, "parent", parent);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_READ_ERROR;

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2key_get_octstring (asn1_node tpm2key, const char *name, void **data, grub_size_t *size)
{
  int ret;

  if (name == NULL || data == NULL || size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  if (tpm2key == NULL)
    return GRUB_ERR_READ_ERROR;

  ret = asn1_allocate_and_read (tpm2key, name, data, size);
  if (ret != ASN1_SUCCESS)
    return GRUB_ERR_READ_ERROR;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2key_get_pubkey (asn1_node tpm2key, void **data, grub_size_t *size)
{
  return tpm2key_get_octstring (tpm2key, "pubkey", data, size);
}

grub_err_t
grub_tpm2key_get_privkey (asn1_node tpm2key, void **data, grub_size_t *size)
{
  return tpm2key_get_octstring (tpm2key, "privkey", data, size);
}
