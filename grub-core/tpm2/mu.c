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

#include <grub/misc.h>
#include <grub/tpm2/mu.h>

void
grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (grub_tpm2_buffer_t buffer,
					const TPMS_AUTH_COMMAND* authCommand)
{
  grub_uint32_t start;
  grub_uint32_t tmp;

  grub_tpm2_buffer_pack_u32 (buffer, 0);
  start = buffer->size;

  grub_tpm2_buffer_pack_u32 (buffer, authCommand->sessionHandle);

  grub_tpm2_buffer_pack_u16 (buffer, authCommand->nonce.size);
  grub_tpm2_buffer_pack (buffer, authCommand->nonce.buffer,
			 authCommand->nonce.size);

  grub_tpm2_buffer_pack_u8 (buffer,
			    *((const grub_uint8_t*) &authCommand->sessionAttributes));

  grub_tpm2_buffer_pack_u16 (buffer, authCommand->hmac.size);
  grub_tpm2_buffer_pack (buffer, authCommand->hmac.buffer,
			 authCommand->hmac.size);

  tmp = grub_cpu_to_be32 (buffer->size - start);
  grub_memcpy (&buffer->data[start - sizeof (grub_uint32_t)], &tmp,
	       sizeof (tmp));
}

void
grub_tpm2_mu_TPM2B_Marshal (grub_tpm2_buffer_t buffer,
			    const grub_uint16_t size,
			    const grub_uint8_t* b)
{
  grub_tpm2_buffer_pack_u16 (buffer, size);

  for (grub_uint16_t i = 0; i < size; i++)
    grub_tpm2_buffer_pack_u8 (buffer, b[i]);
}

void
grub_tpm2_mu_TPMU_SYM_KEY_BITS_Marshal (grub_tpm2_buffer_t buffer,
					const TPMI_ALG_SYM_OBJECT algorithm,
					const TPMU_SYM_KEY_BITS *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
    case TPM_ALG_XOR:
      grub_tpm2_buffer_pack_u16 (buffer, *((const grub_uint16_t*) p));
      break;
    case TPM_ALG_NULL:
      break;
    }
}

void
grub_tpm2_mu_TPMU_SYM_MODE_Marshal (grub_tpm2_buffer_t buffer,
				    const TPMI_ALG_SYM_OBJECT algorithm,
				    const TPMU_SYM_MODE *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
      grub_tpm2_buffer_pack_u16 (buffer, *((const grub_uint16_t*) p));
      break;
    case TPM_ALG_XOR:
    case TPM_ALG_NULL:
      break;
    }
}

void
grub_tpm2_mu_TPMT_SYM_DEF_Marshal (grub_tpm2_buffer_t buffer,
				   const TPMT_SYM_DEF *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->algorithm);
  grub_tpm2_mu_TPMU_SYM_KEY_BITS_Marshal (buffer, p->algorithm, &p->keyBits);
  grub_tpm2_mu_TPMU_SYM_MODE_Marshal (buffer, p->algorithm, &p->mode);
}

void
grub_tpm2_mu_TPMS_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buffer,
					 const TPMS_PCR_SELECTION* pcrSelection)
{
  grub_tpm2_buffer_pack_u16 (buffer, pcrSelection->hash);
  grub_tpm2_buffer_pack_u8 (buffer, pcrSelection->sizeOfSelect);

  for (grub_uint32_t i = 0; i < pcrSelection->sizeOfSelect; i++)
    grub_tpm2_buffer_pack_u8 (buffer, pcrSelection->pcrSelect[i]);
}

void
grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buffer,
					 const TPML_PCR_SELECTION* pcrSelection)
{
  grub_tpm2_buffer_pack_u32 (buffer, pcrSelection->count);

  for (grub_uint32_t i = 0; i < pcrSelection->count; i++)
    grub_tpm2_mu_TPMS_PCR_SELECTION_Marshal (buffer,
					     &pcrSelection->pcrSelections[i]);
}

void
grub_tpm2_mu_TPMA_OBJECT_Marshal (grub_tpm2_buffer_t buffer,
				  const TPMA_OBJECT *p)
{
  grub_tpm2_buffer_pack_u32 (buffer, *((const grub_uint32_t*) p));
}

void
grub_tpm2_mu_TPMS_SCHEME_XOR_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMS_SCHEME_XOR *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hashAlg);
  grub_tpm2_buffer_pack_u16 (buffer, p->kdf);
}

void
grub_tpm2_mu_TPMS_SCHEME_HMAC_Marshal (grub_tpm2_buffer_t buffer,
				       const TPMS_SCHEME_HMAC *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hashAlg);
}

void
grub_tpm2_mu_TPMU_SCHEME_KEYEDHASH_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMI_ALG_KEYEDHASH_SCHEME scheme,
					    const TPMU_SCHEME_KEYEDHASH *p)
{
  switch (scheme)
    {
    case TPM_ALG_HMAC:
      grub_tpm2_mu_TPMS_SCHEME_HMAC_Marshal (buffer, &p->hmac);
      break;
    case TPM_ALG_XOR:
      grub_tpm2_mu_TPMS_SCHEME_XOR_Marshal (buffer, &p->exclusiveOr);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_KEYEDHASH_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMT_KEYEDHASH_SCHEME *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_tpm2_mu_TPMU_SCHEME_KEYEDHASH_Marshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMS_KEYEDHASH_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					   const TPMS_KEYEDHASH_PARMS *p)
{
  grub_tpm2_mu_TPMT_KEYEDHASH_SCHEME_Marshal (buffer, &p->scheme);
}

void
grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Marshal (grub_tpm2_buffer_t buffer,
					  const TPMT_SYM_DEF_OBJECT *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->algorithm);
  grub_tpm2_mu_TPMU_SYM_KEY_BITS_Marshal (buffer, p->algorithm, &p->keyBits);
  grub_tpm2_mu_TPMU_SYM_MODE_Marshal (buffer, p->algorithm, &p->mode);
}

void
grub_tpm2_mu_TPMU_ASYM_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				       const TPMI_ALG_RSA_DECRYPT scheme,
				       const TPMU_ASYM_SCHEME *p __attribute__ ((unused)))
{
  switch (scheme)
    {
    case TPM_ALG_NULL:
      break;
    default:
      /* Unsupported */
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_RSA_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_RSA_SCHEME *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_tpm2_mu_TPMU_ASYM_SCHEME_Marshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMS_RSA_PARMS_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_RSA_PARMS *p)
{
  grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Marshal (buffer, &p->symmetric);
  grub_tpm2_mu_TPMT_RSA_SCHEME_Marshal (buffer, &p->scheme);
  grub_tpm2_buffer_pack_u16 (buffer, p->keyBits);
  grub_tpm2_buffer_pack_u32 (buffer, p->exponent);
}

void
grub_tpm2_mu_TPMS_SYMCIPHER_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					   const TPMS_SYMCIPHER_PARMS *p)
{
  grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Marshal (buffer, &p->sym);
}

void
grub_tpm2_mu_TPMT_ECC_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_ECC_SCHEME *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_tpm2_mu_TPMU_ASYM_SCHEME_Marshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMU_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMI_ALG_KDF scheme,
				      const TPMU_KDF_SCHEME *p)
{
  switch (scheme)
    {
    case TPM_ALG_MGF1:
      grub_tpm2_buffer_pack_u16 (buffer, p->mgf1.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_56A:
      grub_tpm2_buffer_pack_u16 (buffer, p->kdf1_sp800_56a.hashAlg);
      break;
    case TPM_ALG_KDF2:
      grub_tpm2_buffer_pack_u16 (buffer, p->kdf2.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_108:
      grub_tpm2_buffer_pack_u16 (buffer, p->kdf1_sp800_108.hashAlg);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buffer,
				      const TPMT_KDF_SCHEME *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->scheme);
  grub_tpm2_mu_TPMU_KDF_SCHEME_Marshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMS_ECC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_ECC_PARMS *p)
{
  grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Marshal (buffer, &p->symmetric);
  grub_tpm2_mu_TPMT_ECC_SCHEME_Marshal (buffer, &p->scheme);
  grub_tpm2_buffer_pack_u16 (buffer, p->curveID);
  grub_tpm2_mu_TPMT_KDF_SCHEME_Marshal (buffer, &p->kdf);
}

void
grub_tpm2_mu_TPMU_PUBLIC_PARMS_Marshal (grub_tpm2_buffer_t buffer,
					const grub_uint32_t type,
					const TPMU_PUBLIC_PARMS *p)
{
  switch (type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_tpm2_mu_TPMS_KEYEDHASH_PARMS_Marshal (buffer, &p->keyedHashDetail);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_tpm2_mu_TPMS_SYMCIPHER_PARMS_Marshal (buffer, &p->symDetail);
      break;
    case TPM_ALG_RSA:
      grub_tpm2_mu_TPMS_RSA_PARMS_Marshal (buffer, &p->rsaDetail);
      break;
    case TPM_ALG_ECC:
      grub_tpm2_mu_TPMS_ECC_PARMS_Marshal (buffer, &p->eccDetail);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMS_ECC_POINT_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMS_ECC_POINT *p)
{
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->x.size, p->x.buffer);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->y.size, p->y.buffer);
}

void
grub_tpm2_mu_TPMU_PUBLIC_ID_Marshal (grub_tpm2_buffer_t buffer,
				     const TPMI_ALG_PUBLIC type,
				     const TPMU_PUBLIC_ID *p)
{
  switch(type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->keyedHash.size,
				  p->keyedHash.buffer);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->sym.size, p->sym.buffer);
      break;
    case TPM_ALG_RSA:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->rsa.size, p->rsa.buffer);
      break;
    case TPM_ALG_ECC:
      grub_tpm2_mu_TPMS_ECC_POINT_Marshal (buffer, &p->ecc);
      break;
    }
}

void
grub_tpm2_mu_TPMT_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				  const TPMT_PUBLIC *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->type);
  grub_tpm2_buffer_pack_u16 (buffer, p->nameAlg);
  grub_tpm2_mu_TPMA_OBJECT_Marshal (buffer, &p->objectAttributes);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->authPolicy.size, p->authPolicy.buffer);
  grub_tpm2_mu_TPMU_PUBLIC_PARMS_Marshal (buffer, p->type, &p->parameters);
  grub_tpm2_mu_TPMU_PUBLIC_ID_Marshal (buffer, p->type, &p->unique);
}

void
grub_tpm2_mu_TPM2B_PUBLIC_Marshal (grub_tpm2_buffer_t buffer,
				   const TPM2B_PUBLIC *p)
{
  grub_uint32_t start;
  grub_uint16_t size;

  if (p)
    {
      grub_tpm2_buffer_pack_u16 (buffer, p->size);

      start = buffer->size;
      grub_tpm2_mu_TPMT_PUBLIC_Marshal (buffer, &p->publicArea);
      size = grub_cpu_to_be16 (buffer->size - start);
      grub_memcpy (&buffer->data[start - sizeof (grub_uint16_t)], &size,
		   sizeof (size));
    }
  else
    grub_tpm2_buffer_pack_u16 (buffer, 0);
}

void
grub_tpm2_mu_TPMS_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buffer,
					    const TPMS_SENSITIVE_CREATE *p)
{
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->userAuth.size, p->userAuth.buffer);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->data.size, p->data.buffer);
}

void
grub_tpm2_mu_TPMU_SENSITIVE_COMPOSITE_Marshal (grub_tpm2_buffer_t buffer,
                                               const TPMI_ALG_PUBLIC type,
                                               const TPMU_SENSITIVE_COMPOSITE *p)
{
  switch(type)
    {
    case TPM_ALG_RSA:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->rsa.size, p->rsa.buffer);
      break;
    case TPM_ALG_ECC:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->ecc.size, p->ecc.buffer);
      break;
    case TPM_ALG_KEYEDHASH:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->bits.size, p->bits.buffer);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_tpm2_mu_TPM2B_Marshal (buffer, p->sym.size, p->sym.buffer);
      break;
    default:
      buffer->error = 1;
    }
}

void
grub_tpm2_mu_TPMT_SENSITIVE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMT_SENSITIVE *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->sensitiveType);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->authValue.size, p->authValue.buffer);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->seedValue.size, p->seedValue.buffer);
  grub_tpm2_mu_TPMU_SENSITIVE_COMPOSITE_Marshal (buffer, p->sensitiveType,
                                                 &p->sensitive);
}

void
grub_tpm2_mu_TPM2B_SENSITIVE_Marshal (grub_tpm2_buffer_t buffer,
                                      const TPM2B_SENSITIVE *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->size);
  grub_tpm2_mu_TPMT_SENSITIVE_Marshal (buffer, &p->sensitiveArea);
}

void
grub_tpm2_mu_TPM2B_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buffer,
					     const TPM2B_SENSITIVE_CREATE *sensitiveCreate)
{
  grub_uint32_t start;
  grub_uint16_t size;

  if (sensitiveCreate)
    {
      grub_tpm2_buffer_pack_u16 (buffer, sensitiveCreate->size);
      start = buffer->size;
      grub_tpm2_mu_TPMS_SENSITIVE_CREATE_Marshal (buffer,
						  &sensitiveCreate->sensitive);
      size = grub_cpu_to_be16 (buffer->size - start);

      grub_memcpy (&buffer->data[start - sizeof (grub_uint16_t)], &size,
		   sizeof (size));
    }
  else
    grub_tpm2_buffer_pack_u16 (buffer, 0);
}

void
grub_tpm2_mu_TPMS_SIGNATURE_RSA_Marshal (grub_tpm2_buffer_t buffer,
                                         const TPMS_SIGNATURE_RSA *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hash);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->sig.size, p->sig.buffer);
}

void
grub_tpm2_mu_TPMS_SIGNATURE_ECC_Marshal (grub_tpm2_buffer_t buffer,
                                         const TPMS_SIGNATURE_ECC *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hash);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->signatureR.size, p->signatureR.buffer);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->signatureS.size, p->signatureS.buffer);
}

void
grub_tpm2_mu_TPMU_HA_Marshal (grub_tpm2_buffer_t buffer,
                              const TPMI_ALG_HASH hashAlg,
                              const TPMU_HA *p)
{
  switch (hashAlg)
    {
    case TPM_ALG_SHA1:
      for (grub_uint16_t i = 0; i < TPM_SHA1_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha1[i]);
      break;
    case TPM_ALG_SHA256:
      for (grub_uint16_t i = 0; i < TPM_SHA256_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha256[i]);
      break;
    case TPM_ALG_SHA384:
      for (grub_uint16_t i = 0; i < TPM_SHA384_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha384[i]);
      break;
    case TPM_ALG_SHA512:
      for (grub_uint16_t i = 0; i < TPM_SHA512_DIGEST_SIZE; i++)
        grub_tpm2_buffer_pack_u8 (buffer, p->sha512[i]);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_HA_Marshal (grub_tpm2_buffer_t buffer,
                              const TPMT_HA *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->hashAlg);
  grub_tpm2_mu_TPMU_HA_Marshal (buffer, p->hashAlg, &p->digest);
}

void
grub_tpm2_mu_TPMU_SIGNATURE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMI_ALG_SIG_SCHEME sigAlg,
                                     const TPMU_SIGNATURE *p)
{
  switch (sigAlg)
    {
    case TPM_ALG_RSASSA:
      grub_tpm2_mu_TPMS_SIGNATURE_RSA_Marshal (buffer, (TPMS_SIGNATURE_RSA *)&p->rsassa);
      break;
    case TPM_ALG_RSAPSS:
      grub_tpm2_mu_TPMS_SIGNATURE_RSA_Marshal (buffer, (TPMS_SIGNATURE_RSA *)&p->rsapss);
      break;
    case TPM_ALG_ECDSA:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC *)&p->ecdsa);
      break;
    case TPM_ALG_ECDAA:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC *)&p->ecdaa);
      break;
    case TPM_ALG_SM2:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC *)&p->sm2);
      break;
    case TPM_ALG_ECSCHNORR:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Marshal (buffer, (TPMS_SIGNATURE_ECC *)&p->ecschnorr);
      break;
    case TPM_ALG_HMAC:
      grub_tpm2_mu_TPMT_HA_Marshal (buffer, &p->hmac);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_SIGNATURE_Marshal (grub_tpm2_buffer_t buffer,
                                     const TPMT_SIGNATURE *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->sigAlg);
  grub_tpm2_mu_TPMU_SIGNATURE_Marshal (buffer, p->sigAlg, &p->signature);
}

void
grub_tpm2_mu_TPMT_TK_VERIFIED_Marshal (grub_tpm2_buffer_t buffer,
                                       const TPMT_TK_VERIFIED *p)
{
  grub_tpm2_buffer_pack_u16 (buffer, p->tag);
  grub_tpm2_buffer_pack_u32 (buffer, p->hierarchy);
  grub_tpm2_mu_TPM2B_Marshal (buffer, p->digest.size, p->digest.buffer);
}

void
grub_tpm2_mu_TPM2B_Unmarshal (grub_tpm2_buffer_t buffer,
			      TPM2B* p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->size);

  for (grub_uint16_t i = 0; i < p->size; i++)
    grub_tpm2_buffer_unpack_u8 (buffer, &p->buffer[i]);
}

void
grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (grub_tpm2_buffer_t buffer,
					   TPMS_AUTH_RESPONSE* p)
{
  grub_uint8_t tmp;
  grub_uint32_t tmp32;

  grub_tpm2_buffer_unpack_u16 (buffer, &p->nonce.size);

  if (p->nonce.size)
    grub_tpm2_buffer_unpack (buffer, &p->nonce.buffer, p->nonce.size);

  grub_tpm2_buffer_unpack_u8 (buffer, &tmp);
  tmp32 = tmp;
  grub_memcpy (&p->sessionAttributes, &tmp32, sizeof (grub_uint32_t));

  grub_tpm2_buffer_unpack_u16 (buffer, &p->hmac.size);

  if (p->hmac.size)
    grub_tpm2_buffer_unpack (buffer, &p->hmac.buffer, p->hmac.size);
}

void
grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (grub_tpm2_buffer_t buffer,
				     TPM2B_DIGEST* digest)
{
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*)digest);
}

void
grub_tpm2_mu_TPMA_OBJECT_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPMA_OBJECT *p)
{
  grub_tpm2_buffer_unpack_u32 (buffer, (grub_uint32_t*)p);
}

void
grub_tpm2_mu_TPMS_SCHEME_HMAC_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMS_SCHEME_HMAC *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->hashAlg);
}

void
grub_tpm2_mu_TPMS_SCHEME_XOR_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMS_SCHEME_XOR *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->hashAlg);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf);
}

void
grub_tpm2_mu_TPMU_SCHEME_KEYEDHASH_Unmarshal (grub_tpm2_buffer_t buffer,
					      TPMI_ALG_KEYEDHASH_SCHEME scheme,
					      TPMU_SCHEME_KEYEDHASH *p)
{
  switch (scheme)
    {
    case TPM_ALG_HMAC:
      grub_tpm2_mu_TPMS_SCHEME_HMAC_Unmarshal (buffer, &p->hmac);
      break;
    case TPM_ALG_XOR:
      grub_tpm2_mu_TPMS_SCHEME_XOR_Unmarshal (buffer, &p->exclusiveOr);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_KEYEDHASH_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					      TPMT_KEYEDHASH_SCHEME *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_tpm2_mu_TPMU_SCHEME_KEYEDHASH_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMS_KEYEDHASH_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_KEYEDHASH_PARMS *p)
{
  grub_tpm2_mu_TPMT_KEYEDHASH_SCHEME_Unmarshal (buffer, &p->scheme);
}

void
grub_tpm2_mu_TPMU_SYM_KEY_BITS_Unmarshal (grub_tpm2_buffer_t buffer,
					  TPMI_ALG_SYM_OBJECT algorithm,
					  TPMU_SYM_KEY_BITS *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
    case TPM_ALG_XOR:
      grub_tpm2_buffer_unpack_u16 (buffer, (grub_uint16_t*) p);
      break;
    case TPM_ALG_NULL:
      break;
    }
}

void
grub_tpm2_mu_TPMU_SYM_MODE_Unmarshal (grub_tpm2_buffer_t buffer,
				      TPMI_ALG_SYM_OBJECT algorithm,
				      TPMU_SYM_MODE *p)
{
  switch (algorithm)
    {
    case TPM_ALG_AES:
    case TPM_ALG_SM4:
    case TPM_ALG_CAMELLIA:
      grub_tpm2_buffer_unpack_u16 (buffer, (grub_uint16_t*) p);
      break;
    case TPM_ALG_XOR:
    case TPM_ALG_NULL:
      break;
    }
}

void
grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Unmarshal (grub_tpm2_buffer_t buffer,
					    TPMT_SYM_DEF_OBJECT *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->algorithm);
  grub_tpm2_mu_TPMU_SYM_KEY_BITS_Unmarshal (buffer, p->algorithm, &p->keyBits);
  grub_tpm2_mu_TPMU_SYM_MODE_Unmarshal (buffer, p->algorithm, &p->mode);
}

void
grub_tpm2_mu_TPMS_SYMCIPHER_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_SYMCIPHER_PARMS *p)
{
  grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Unmarshal (buffer, &p->sym);
}

void
grub_tpm2_mu_TPMU_ASYM_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMI_ALG_RSA_DECRYPT scheme,
					 TPMU_ASYM_SCHEME *p __attribute__((unused)))
{
  switch (scheme)
    {
    case TPM_ALG_NULL:
      break;
    default:
      /* Unsupported */
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_RSA_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_RSA_SCHEME *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_tpm2_mu_TPMU_ASYM_SCHEME_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMS_RSA_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_RSA_PARMS *p)
{
  grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Unmarshal (buffer, &p->symmetric);
  grub_tpm2_mu_TPMT_RSA_SCHEME_Unmarshal (buffer, &p->scheme);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->keyBits);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->exponent);
}

void
grub_tpm2_mu_TPMT_ECC_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_ECC_SCHEME *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_tpm2_mu_TPMU_ASYM_SCHEME_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMU_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMI_ALG_KDF scheme,
					TPMU_KDF_SCHEME *p)
{
  switch (scheme)
    {
    case TPM_ALG_MGF1:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->mgf1.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_56A:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf1_sp800_56a.hashAlg);
      break;
    case TPM_ALG_KDF2:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf2.hashAlg);
      break;
    case TPM_ALG_KDF1_SP800_108:
      grub_tpm2_buffer_unpack_u16 (buffer, &p->kdf1_sp800_108.hashAlg);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buffer,
					TPMT_KDF_SCHEME *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->scheme);
  grub_tpm2_mu_TPMU_KDF_SCHEME_Unmarshal (buffer, p->scheme, &p->details);
}

void
grub_tpm2_mu_TPMS_ECC_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_ECC_PARMS *p)
{
  grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Unmarshal (buffer, &p->symmetric);
  grub_tpm2_mu_TPMT_ECC_SCHEME_Unmarshal (buffer, &p->scheme );
  grub_tpm2_buffer_unpack_u16 (buffer, &p->curveID);
  grub_tpm2_mu_TPMT_KDF_SCHEME_Unmarshal (buffer, &p->kdf);
}

void
grub_tpm2_mu_TPMU_PUBLIC_PARMS_Unmarshal (grub_tpm2_buffer_t buffer,
					  grub_uint32_t type,
					  TPMU_PUBLIC_PARMS *p)
{
  switch (type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_tpm2_mu_TPMS_KEYEDHASH_PARMS_Unmarshal (buffer, &p->keyedHashDetail);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_tpm2_mu_TPMS_SYMCIPHER_PARMS_Unmarshal (buffer, &p->symDetail);
      break;
    case TPM_ALG_RSA:
      grub_tpm2_mu_TPMS_RSA_PARMS_Unmarshal (buffer, &p->rsaDetail);
      break;
    case TPM_ALG_ECC:
      grub_tpm2_mu_TPMS_ECC_PARMS_Unmarshal (buffer, &p->eccDetail);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMS_ECC_POINT_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_ECC_POINT *p)
{
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->x);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->y);
}

void
grub_tpm2_mu_TPMU_PUBLIC_ID_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMI_ALG_PUBLIC type,
				       TPMU_PUBLIC_ID *p)
{
  switch(type)
    {
    case TPM_ALG_KEYEDHASH:
      grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->keyedHash);
      break;
    case TPM_ALG_SYMCIPHER:
      grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->sym);
      break;
    case TPM_ALG_RSA:
      grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->rsa);
      break;
    case TPM_ALG_ECC:
      grub_tpm2_mu_TPMS_ECC_POINT_Unmarshal (buffer, &p->ecc);
      break;
    }
}

void
grub_tpm2_mu_TPMT_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				    TPMT_PUBLIC *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->type);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->nameAlg);
  grub_tpm2_mu_TPMA_OBJECT_Unmarshal (buffer, &p->objectAttributes);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->authPolicy);
  grub_tpm2_mu_TPMU_PUBLIC_PARMS_Unmarshal (buffer, p->type, &p->parameters);
  grub_tpm2_mu_TPMU_PUBLIC_ID_Unmarshal (buffer, p->type, &p->unique);
}

void
grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				     TPM2B_PUBLIC *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->size);
  grub_tpm2_mu_TPMT_PUBLIC_Unmarshal (buffer, &p->publicArea);
}

void
grub_tpm2_mu_TPMS_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
				       TPMS_NV_PUBLIC *p)
{
  grub_tpm2_buffer_unpack_u32 (buffer, &p->nvIndex);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->nameAlg);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->attributes);
  grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (buffer, &p->authPolicy);
  grub_tpm2_buffer_unpack_u16 (buffer, &p->dataSize);
}

void
grub_tpm2_mu_TPM2B_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buffer,
					TPM2B_NV_PUBLIC *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->size);
  grub_tpm2_mu_TPMS_NV_PUBLIC_Unmarshal (buffer, &p->nvPublic);
}

void
grub_tpm2_mu_TPM2B_NAME_Unmarshal (grub_tpm2_buffer_t buffer,
				   TPM2B_NAME *n)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &n->size);
  grub_tpm2_buffer_unpack (buffer, n->name, n->size);
}

void
grub_tpm2_mu_TPMS_TAGGED_PROPERTY_Unmarshal (grub_tpm2_buffer_t buffer,
					     TPMS_TAGGED_PROPERTY* property)
{
  grub_tpm2_buffer_unpack_u32 (buffer, &property->property);
  grub_tpm2_buffer_unpack_u32 (buffer, &property->value);
}

void
grub_tpm2_mu_TPMS_CAPABILITY_DATA_tpmProperties_Unmarshal (grub_tpm2_buffer_t buffer,
							   TPMS_CAPABILITY_DATA* capabilityData)
{
  grub_tpm2_buffer_unpack_u32 (buffer,
			       &capabilityData->data.tpmProperties.count);

  if (buffer->error)
    return;

  for (grub_uint32_t i = 0; i < capabilityData->data.tpmProperties.count; i++)
    grub_tpm2_mu_TPMS_TAGGED_PROPERTY_Unmarshal (buffer,
						 &capabilityData->data.tpmProperties.tpmProperty[i]);
}

void
grub_tpm2_mu_TPMT_TK_CREATION_Unmarshal (grub_tpm2_buffer_t buffer,
					 TPMT_TK_CREATION *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->tag);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->hierarchy);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->digest);
}

void
grub_tpm2_mu_TPMT_TK_HASHCHECK_Unmarshal (grub_tpm2_buffer_t buffer,
                                          TPMT_TK_HASHCHECK *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->tag);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->hierarchy);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->digest);
}

void
grub_tpm2_mu_TPMT_TK_VERIFIED_Unmarshal (grub_tpm2_buffer_t buffer,
                                         TPMT_TK_VERIFIED *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->tag);
  grub_tpm2_buffer_unpack_u32 (buffer, &p->hierarchy);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*) &p->digest);
}

void
grub_tpm2_mu_TPMS_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buf,
					   TPMS_PCR_SELECTION* pcrSelection)
{
  grub_tpm2_buffer_unpack_u16 (buf, &pcrSelection->hash);
  grub_tpm2_buffer_unpack_u8 (buf, &pcrSelection->sizeOfSelect);

  for (grub_uint32_t i = 0; i < pcrSelection->sizeOfSelect; i++)
    grub_tpm2_buffer_unpack_u8 (buf, &pcrSelection->pcrSelect[i]);
}

void
grub_tpm2_mu_TPML_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buf,
					   TPML_PCR_SELECTION* pcrSelection)
{
  grub_tpm2_buffer_unpack_u32 (buf, &pcrSelection->count);

  for (grub_uint32_t i = 0; i < pcrSelection->count; i++)
    grub_tpm2_mu_TPMS_PCR_SELECTION_Unmarshal (buf, &pcrSelection->pcrSelections[i]);
}

void
grub_tpm2_mu_TPML_DIGEST_Unmarshal (grub_tpm2_buffer_t buf,
				    TPML_DIGEST* digest)
{
  grub_tpm2_buffer_unpack_u32 (buf, &digest->count);

  for (grub_uint32_t i = 0; i < digest->count; i++)
    grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (buf, &digest->digests[i]);
}

void
grub_tpm2_mu_TPMS_SIGNATURE_RSA_Unmarshal (grub_tpm2_buffer_t buffer,
                                           TPMS_SIGNATURE_RSA *rsa)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &rsa->hash);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*)&rsa->sig);
}

void
grub_tpm2_mu_TPMS_SIGNATURE_ECC_Unmarshal (grub_tpm2_buffer_t buffer,
                                           TPMS_SIGNATURE_ECC *ecc)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &ecc->hash);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*)&ecc->signatureR);
  grub_tpm2_mu_TPM2B_Unmarshal (buffer, (TPM2B*)&ecc->signatureS);
}

void
grub_tpm2_mu_TPMU_HA_Unmarshal (grub_tpm2_buffer_t buffer,
                                TPMI_ALG_HASH hashAlg,
                                TPMU_HA *p)
{
  switch (hashAlg)
    {
    case TPM_ALG_SHA1:
      grub_tpm2_buffer_unpack (buffer, &p->sha1, TPM_SHA1_DIGEST_SIZE);
      break;
    case TPM_ALG_SHA256:
      grub_tpm2_buffer_unpack (buffer, &p->sha256, TPM_SHA256_DIGEST_SIZE);
      break;
    case TPM_ALG_SHA384:
      grub_tpm2_buffer_unpack (buffer, &p->sha384, TPM_SHA384_DIGEST_SIZE);
      break;
    case TPM_ALG_SHA512:
      grub_tpm2_buffer_unpack (buffer, &p->sha512, TPM_SHA512_DIGEST_SIZE);
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_HA_Unmarshal (grub_tpm2_buffer_t buffer,
                                TPMT_HA *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->hashAlg);
  grub_tpm2_mu_TPMU_HA_Unmarshal (buffer, p->hashAlg, &p->digest);
}

void
grub_tpm2_mu_TPMU_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buffer,
                                       TPMI_ALG_SIG_SCHEME sigAlg,
                                       TPMU_SIGNATURE *p)
{
  switch (sigAlg)
    {
    case TPM_ALG_RSASSA:
      grub_tpm2_mu_TPMS_SIGNATURE_RSA_Unmarshal (buffer, (TPMS_SIGNATURE_RSA *)&p->rsassa);
      break;
    case TPM_ALG_RSAPSS:
      grub_tpm2_mu_TPMS_SIGNATURE_RSA_Unmarshal (buffer, (TPMS_SIGNATURE_RSA *)&p->rsapss);
      break;
    case TPM_ALG_ECDSA:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC *)&p->ecdsa);
      break;
    case TPM_ALG_ECDAA:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC *)&p->ecdaa);
      break;
    case TPM_ALG_SM2:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC *)&p->sm2);
      break;
    case TPM_ALG_ECSCHNORR:
      grub_tpm2_mu_TPMS_SIGNATURE_ECC_Unmarshal (buffer, (TPMS_SIGNATURE_ECC *)&p->ecschnorr);
      break;
    case TPM_ALG_HMAC:
      grub_tpm2_mu_TPMT_HA_Unmarshal (buffer, &p->hmac);
      break;
    case TPM_ALG_NULL:
      break;
    default:
      buffer->error = 1;
      break;
    }
}

void
grub_tpm2_mu_TPMT_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buffer,
                                       TPMT_SIGNATURE *p)
{
  grub_tpm2_buffer_unpack_u16 (buffer, &p->sigAlg);
  grub_tpm2_mu_TPMU_SIGNATURE_Unmarshal (buffer, p->sigAlg, &p->signature);
}
