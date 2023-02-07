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

#ifndef GRUB_TPM2_MU_HEADER
#define GRUB_TPM2_MU_HEADER 1

#include <grub/tpm2/buffer.h>
#include <grub/tpm2/tpm2.h>

void
grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (grub_tpm2_buffer_t buf,
					const TPMS_AUTH_COMMAND* authCommand);

void
grub_tpm2_mu_TPM2B_Marshal (grub_tpm2_buffer_t buf,
			    const grub_uint16_t size,
			    const grub_uint8_t* buffer);

void
grub_tpm2_mu_TPMU_SYM_KEY_BITS_Marshal (grub_tpm2_buffer_t buf,
					const TPMI_ALG_SYM_OBJECT algorithm,
					const TPMU_SYM_KEY_BITS *p);

void
grub_tpm2_mu_TPMU_SYM_MODE_Marshal (grub_tpm2_buffer_t buf,
				    const TPMI_ALG_SYM_OBJECT algorithm,
				    const TPMU_SYM_MODE *p);

void
grub_tpm2_mu_TPMT_SYM_DEF_Marshal (grub_tpm2_buffer_t buf,
				   const TPMT_SYM_DEF *p);

void
grub_tpm2_mu_TPMS_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buf,
					 const TPMS_PCR_SELECTION* pcrSelection);

void
grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (grub_tpm2_buffer_t buf,
					 const TPML_PCR_SELECTION* pcrSelection);

void
grub_tpm2_mu_TPMA_OBJECT_Marshal (grub_tpm2_buffer_t buf,
				  const TPMA_OBJECT *p);

void
grub_tpm2_mu_TPMS_SCHEME_XOR_Marshal (grub_tpm2_buffer_t buf,
				      const TPMS_SCHEME_XOR *p);

void
grub_tpm2_mu_TPMS_SCHEME_HMAC_Marshal (grub_tpm2_buffer_t buf,
				       const TPMS_SCHEME_HMAC *p);

void
grub_tpm2_mu_TPMU_SCHEME_KEYEDHASH_Marshal (grub_tpm2_buffer_t buf,
					    const TPMI_ALG_KEYEDHASH_SCHEME scheme,
					    const TPMU_SCHEME_KEYEDHASH *p);

void
grub_tpm2_mu_TPMT_KEYEDHASH_SCHEME_Marshal (grub_tpm2_buffer_t buf,
					    const TPMT_KEYEDHASH_SCHEME *p);

void
grub_tpm2_mu_TPMS_KEYEDHASH_PARMS_Marshal (grub_tpm2_buffer_t buf,
					   const TPMS_KEYEDHASH_PARMS *p);

void
grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Marshal (grub_tpm2_buffer_t buf,
					  const TPMT_SYM_DEF_OBJECT *p);

void
grub_tpm2_mu_TPMU_ASYM_SCHEME_Marshal (grub_tpm2_buffer_t buf,
				       const TPMI_ALG_RSA_DECRYPT scheme,
				       const TPMU_ASYM_SCHEME *p);

void
grub_tpm2_mu_TPMT_RSA_SCHEME_Marshal (grub_tpm2_buffer_t buf,
				      const TPMT_RSA_SCHEME *p);

void
grub_tpm2_mu_TPMS_RSA_PARMS_Marshal (grub_tpm2_buffer_t buf,
				     const TPMS_RSA_PARMS *p);

void
grub_tpm2_mu_TPMS_SYMCIPHER_PARMS_Marshal (grub_tpm2_buffer_t buf,
					   const TPMS_SYMCIPHER_PARMS *p);

void
grub_tpm2_mu_TPMT_ECC_SCHEME_Marshal (grub_tpm2_buffer_t buf,
				      const TPMT_ECC_SCHEME *p);

void
grub_tpm2_mu_TPMU_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buf,
				      const TPMI_ALG_KDF scheme,
				      const TPMU_KDF_SCHEME *p);

void
grub_tpm2_mu_TPMT_KDF_SCHEME_Marshal (grub_tpm2_buffer_t buf,
				      const TPMT_KDF_SCHEME *p);

void
grub_tpm2_mu_TPMS_ECC_PARMS_Marshal (grub_tpm2_buffer_t buf,
				     const TPMS_ECC_PARMS *p);

void
grub_tpm2_mu_TPMU_PUBLIC_PARMS_Marshal (grub_tpm2_buffer_t buf,
					const grub_uint32_t type,
					const TPMU_PUBLIC_PARMS *p);

void
grub_tpm2_mu_TPMS_ECC_POINT_Marshal (grub_tpm2_buffer_t buf,
				     const TPMS_ECC_POINT *p);

void
grub_tpm2_mu_TPMU_PUBLIC_ID_Marshal (grub_tpm2_buffer_t buf,
				     const TPMI_ALG_PUBLIC type,
				     const TPMU_PUBLIC_ID *p);

void
grub_tpm2_mu_TPMT_PUBLIC_Marshal (grub_tpm2_buffer_t buf,
				  const TPMT_PUBLIC *p);

void
grub_tpm2_mu_TPM2B_PUBLIC_Marshal (grub_tpm2_buffer_t buf,
				   const TPM2B_PUBLIC *p);

void
grub_tpm2_mu_TPMS_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buf,
					    const TPMS_SENSITIVE_CREATE *p);

void
grub_tpm2_mu_TPM2B_SENSITIVE_CREATE_Marshal (grub_tpm2_buffer_t buf,
					     const TPM2B_SENSITIVE_CREATE *sensitiveCreate);

void
grub_tpm2_mu_TPMU_SENSITIVE_COMPOSITE_Marshal (grub_tpm2_buffer_t buf,
                                               const TPMI_ALG_PUBLIC type,
                                               const TPMU_SENSITIVE_COMPOSITE *p);
void
grub_tpm2_mu_TPMT_SENSITIVE_Marshal (grub_tpm2_buffer_t buf,
                                     const TPMT_SENSITIVE *p);

void
grub_tpm2_mu_TPM2B_SENSITIVE_Marshal (grub_tpm2_buffer_t buf,
                                      const TPM2B_SENSITIVE *p);

void
grub_tpm2_mu_TPMS_SIGNATURE_RSA_Marshal (grub_tpm2_buffer_t buf,
                                         const TPMS_SIGNATURE_RSA *p);

void
grub_tpm2_mu_TPMS_SIGNATURE_ECC_Marshal (grub_tpm2_buffer_t buf,
                                         const TPMS_SIGNATURE_ECC *p);

void
grub_tpm2_mu_TPMU_HA_Marshal (grub_tpm2_buffer_t buf,
                              const TPMI_ALG_HASH hashAlg,
                              const TPMU_HA *p);

void
grub_tpm2_mu_TPMT_HA_Marshal (grub_tpm2_buffer_t buf,
                              const TPMT_HA *p);

void
grub_tpm2_mu_TPMU_SIGNATURE_Marshal (grub_tpm2_buffer_t buf,
                                     const TPMI_ALG_SIG_SCHEME sigAlg,
                                     const TPMU_SIGNATURE *p);

void
grub_tpm2_mu_TPMT_SIGNATURE_Marshal (grub_tpm2_buffer_t buf,
                                     const TPMT_SIGNATURE *p);

void
grub_tpm2_mu_TPMT_TK_VERIFIED_Marshal (grub_tpm2_buffer_t buf,
                                       const TPMT_TK_VERIFIED *p);
void
grub_tpm2_mu_TPM2B_Unmarshal (grub_tpm2_buffer_t buf,
			      TPM2B* p);

void
grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (grub_tpm2_buffer_t buf,
					   TPMS_AUTH_RESPONSE* p);

void
grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (grub_tpm2_buffer_t buf,
				     TPM2B_DIGEST* digest);

void
grub_tpm2_mu_TPMA_OBJECT_Unmarshal (grub_tpm2_buffer_t buf,
				    TPMA_OBJECT *p);

void
grub_tpm2_mu_TPMS_SCHEME_HMAC_Unmarshal (grub_tpm2_buffer_t buf,
					 TPMS_SCHEME_HMAC *p);

void
grub_tpm2_mu_TPMS_SCHEME_XOR_Unmarshal (grub_tpm2_buffer_t buf,
					TPMS_SCHEME_XOR *p);

void
grub_tpm2_mu_TPMU_SCHEME_KEYEDHASH_Unmarshal (grub_tpm2_buffer_t buf,
					      TPMI_ALG_KEYEDHASH_SCHEME scheme,
					      TPMU_SCHEME_KEYEDHASH *p);

void
grub_tpm2_mu_TPMT_KEYEDHASH_SCHEME_Unmarshal (grub_tpm2_buffer_t buf,
					      TPMT_KEYEDHASH_SCHEME *p);

void
grub_tpm2_mu_TPMS_KEYEDHASH_PARMS_Unmarshal (grub_tpm2_buffer_t buf,
					     TPMS_KEYEDHASH_PARMS *p);

void
grub_tpm2_mu_TPMU_SYM_KEY_BITS_Unmarshal (grub_tpm2_buffer_t buf,
					  TPMI_ALG_SYM_OBJECT algorithm,
					  TPMU_SYM_KEY_BITS *p);

void
grub_tpm2_mu_TPMU_SYM_MODE_Unmarshal (grub_tpm2_buffer_t buf,
				      TPMI_ALG_SYM_OBJECT algorithm,
				      TPMU_SYM_MODE *p);

void
grub_tpm2_mu_TPMT_SYM_DEF_OBJECT_Unmarshal (grub_tpm2_buffer_t buf,
					    TPMT_SYM_DEF_OBJECT *p);

void
grub_tpm2_mu_TPMS_SYMCIPHER_PARMS_Unmarshal (grub_tpm2_buffer_t buf,
					     TPMS_SYMCIPHER_PARMS *p);

void
grub_tpm2_mu_TPMU_ASYM_SCHEME_Unmarshal (grub_tpm2_buffer_t buf,
					 TPMI_ALG_RSA_DECRYPT scheme,
					 TPMU_ASYM_SCHEME *p);

void
grub_tpm2_mu_TPMT_RSA_SCHEME_Unmarshal (grub_tpm2_buffer_t buf,
					TPMT_RSA_SCHEME *p);

void
grub_tpm2_mu_TPMS_RSA_PARMS_Unmarshal (grub_tpm2_buffer_t buf,
				       TPMS_RSA_PARMS *p);

void
grub_tpm2_mu_TPMT_ECC_SCHEME_Unmarshal (grub_tpm2_buffer_t buf,
					TPMT_ECC_SCHEME *p);

void
grub_tpm2_mu_TPMU_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buf,
					TPMI_ALG_KDF scheme,
					TPMU_KDF_SCHEME *p);

void
grub_tpm2_mu_TPMT_KDF_SCHEME_Unmarshal (grub_tpm2_buffer_t buf,
					TPMT_KDF_SCHEME *p);

void
grub_tpm2_mu_TPMS_ECC_PARMS_Unmarshal (grub_tpm2_buffer_t buf,
				       TPMS_ECC_PARMS *p);

void
grub_tpm2_mu_TPMU_PUBLIC_PARMS_Unmarshal (grub_tpm2_buffer_t buf,
					  grub_uint32_t type,
					  TPMU_PUBLIC_PARMS *p);

void
grub_tpm2_mu_TPMS_ECC_POINT_Unmarshal (grub_tpm2_buffer_t buf,
				       TPMS_ECC_POINT *p);

void
grub_tpm2_mu_TPMU_PUBLIC_ID_Unmarshal (grub_tpm2_buffer_t buf,
				       TPMI_ALG_PUBLIC type,
				       TPMU_PUBLIC_ID *p);

void
grub_tpm2_mu_TPMT_PUBLIC_Unmarshal (grub_tpm2_buffer_t buf,
				    TPMT_PUBLIC *p);

void
grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (grub_tpm2_buffer_t buf,
				     TPM2B_PUBLIC *p);

void
grub_tpm2_mu_TPMS_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buf,
				       TPMS_NV_PUBLIC *p);

void
grub_tpm2_mu_TPM2B_NV_PUBLIC_Unmarshal (grub_tpm2_buffer_t buf,
					TPM2B_NV_PUBLIC *p);

void
grub_tpm2_mu_TPM2B_NAME_Unmarshal (grub_tpm2_buffer_t buf,
				   TPM2B_NAME *n);

void
grub_tpm2_mu_TPMS_TAGGED_PROPERTY_Unmarshal (grub_tpm2_buffer_t buf,
					     TPMS_TAGGED_PROPERTY* property);

void
grub_tpm2_mu_TPMS_CAPABILITY_DATA_tpmProperties_Unmarshal (grub_tpm2_buffer_t buf,
							   TPMS_CAPABILITY_DATA* capabilityData);

void
grub_tpm2_mu_TPMT_TK_CREATION_Unmarshal (grub_tpm2_buffer_t buf,
					 TPMT_TK_CREATION *p);

void
grub_tpm2_mu_TPMT_TK_HASHCHECK_Unmarshal (grub_tpm2_buffer_t buf,
                                          TPMT_TK_HASHCHECK *p);

void
grub_tpm2_mu_TPMT_TK_VERIFIED_Unmarshal (grub_tpm2_buffer_t buf,
                                         TPMT_TK_VERIFIED *p);

void
grub_tpm2_mu_TPMS_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buf,
					   TPMS_PCR_SELECTION* pcrSelection);

void
grub_tpm2_mu_TPML_PCR_SELECTION_Unmarshal (grub_tpm2_buffer_t buf,
					   TPML_PCR_SELECTION* pcrSelection);

void
grub_tpm2_mu_TPML_DIGEST_Unmarshal (grub_tpm2_buffer_t buf,
				    TPML_DIGEST* digest);

void
grub_tpm2_mu_TPMS_SIGNATURE_RSA_Unmarshal (grub_tpm2_buffer_t buf,
                                           TPMS_SIGNATURE_RSA *p);

void
grub_tpm2_mu_TPMS_SIGNATURE_ECC_Unmarshal (grub_tpm2_buffer_t buf,
                                           TPMS_SIGNATURE_ECC *p);

void
grub_tpm2_mu_TPMU_HA_Unmarshal (grub_tpm2_buffer_t buf,
                                TPMI_ALG_HASH hashAlg,
                                TPMU_HA *p);

void
grub_tpm2_mu_TPMT_HA_Unmarshal (grub_tpm2_buffer_t buf,
                                TPMT_HA *p);

void
grub_tpm2_mu_TPMU_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buf,
                                       TPMI_ALG_SIG_SCHEME sigAlg,
                                       TPMU_SIGNATURE *p);

void
grub_tpm2_mu_TPMT_SIGNATURE_Unmarshal (grub_tpm2_buffer_t buf,
                                       TPMT_SIGNATURE *p);

#endif /* ! GRUB_TPM2_MU_HEADER */
