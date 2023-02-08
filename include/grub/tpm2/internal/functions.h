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

#ifndef GRUB_TPM2_INTERNAL_FUNCTIONS_HEADER
#define GRUB_TPM2_INTERNAL_FUNCTIONS_HEADER 1

#include <grub/tpm2/internal/structs.h>

TPM_RC
TPM2_CreatePrimary (const TPMI_RH_HIERARCHY primaryHandle,
		    const TPMS_AUTH_COMMAND *authCommand,
		    const TPM2B_SENSITIVE_CREATE *inSensitive,
		    const TPM2B_PUBLIC *inPublic,
		    const TPM2B_DATA *outsideInfo,
		    const TPML_PCR_SELECTION *creationPCR,
		    TPM_HANDLE *objectHandle,
		    TPM2B_PUBLIC *outPublic,
		    TPM2B_CREATION_DATA *creationData,
		    TPM2B_DIGEST *creationHash,
		    TPMT_TK_CREATION *creationTicket,
		    TPM2B_NAME *name,
		    TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_StartAuthSession (const TPMI_DH_OBJECT tpmKey,
		       const TPMI_DH_ENTITY bind,
		       const TPMS_AUTH_COMMAND *authCommand,
		       const TPM2B_NONCE *nonceCaller,
		       const TPM2B_ENCRYPTED_SECRET *encryptedSalt,
		       const TPM_SE sessionType,
		       const TPMT_SYM_DEF *symmetric,
		       const TPMI_ALG_HASH authHash,
		       TPMI_SH_AUTH_SESSION *sessionHandle,
		       TPM2B_NONCE *nonceTpm,
		       TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_PolicyPCR (const TPMI_SH_POLICY policySession,
		const TPMS_AUTH_COMMAND *authCommand,
		const TPM2B_DIGEST *pcrDigest,
		const TPML_PCR_SELECTION *pcrs,
		TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_ReadPublic (const TPMI_DH_OBJECT objectHandle,
		 const TPMS_AUTH_COMMAND* authCommand,
		 TPM2B_PUBLIC *outPublic);

TPM_RC
TPM2_Load (const TPMI_DH_OBJECT parent_handle,
	   const TPMS_AUTH_COMMAND *authCommand,
	   const TPM2B_PRIVATE *inPrivate,
	   const TPM2B_PUBLIC *inPublic,
	   TPM_HANDLE *objectHandle,
	   TPM2B_NAME *name,
	   TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_LoadExternal (const TPMS_AUTH_COMMAND *authCommand,
                   const TPM2B_SENSITIVE *inPrivate,
                   const TPM2B_PUBLIC *inPublic,
                   const TPMI_RH_HIERARCHY hierarchy,
                   TPM_HANDLE *objectHandle,
                   TPM2B_NAME *name,
                   TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_Unseal (const TPMI_DH_OBJECT item_handle,
	     const TPMS_AUTH_COMMAND *authCommand,
	     TPM2B_SENSITIVE_DATA *outData,
	     TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_FlushContext (const TPMI_DH_CONTEXT handle);

TPM_RC
TPM2_PCR_Read (const TPMS_AUTH_COMMAND *authCommand,
	       const TPML_PCR_SELECTION *pcrSelectionIn,
	       grub_uint32_t *pcrUpdateCounter,
	       TPML_PCR_SELECTION *pcrSelectionOut,
	       TPML_DIGEST *pcrValues,
	       TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_PolicyGetDigest (const TPMI_SH_POLICY policySession,
		      const TPMS_AUTH_COMMAND *authCommand,
		      TPM2B_DIGEST *policyDigest,
		      TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_Create (const TPMI_DH_OBJECT parentHandle,
	     const TPMS_AUTH_COMMAND *authCommand,
	     const TPM2B_SENSITIVE_CREATE *inSensitive,
	     const TPM2B_PUBLIC *inPublic,
	     const TPM2B_DATA *outsideInfo,
	     const TPML_PCR_SELECTION *creationPCR,
	     TPM2B_PRIVATE *outPrivate,
	     TPM2B_PUBLIC *outPublic,
	     TPM2B_CREATION_DATA *creationData,
	     TPM2B_DIGEST *creationHash,
	     TPMT_TK_CREATION *creationTicket,
	     TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_EvictControl (const TPMI_RH_PROVISION auth,
		   const TPMI_DH_OBJECT objectHandle,
		   const TPMS_AUTH_COMMAND *authCommand,
		   const TPMI_DH_PERSISTENT persistentHandle,
		   TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_HashSequenceStart (const TPMS_AUTH_COMMAND *authCommand,
                        const TPM2B_AUTH *auth,
                        const TPMI_ALG_HASH hashAlg,
                        TPMI_DH_OBJECT *sequenceHandle,
                        TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_SequenceUpdate (const TPMI_DH_OBJECT sequenceHandle,
                     const TPMS_AUTH_COMMAND *authCommand,
                     const TPM2B_MAX_BUFFER *buffer,
                     TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_SequenceComplete (const TPMI_DH_OBJECT sequenceHandle,
                       const TPMS_AUTH_COMMAND *authCommand,
                       const TPM2B_MAX_BUFFER *buffer,
                       const TPMI_RH_HIERARCHY hierarchy,
                       TPM2B_DIGEST *result,
                       TPMT_TK_HASHCHECK *validation,
                       TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_Hash (const TPMS_AUTH_COMMAND *authCommand,
           const TPM2B_MAX_BUFFER *data,
           const TPMI_ALG_HASH hashAlg,
           const TPMI_RH_HIERARCHY hierarchy,
           TPM2B_DIGEST *outHash,
           TPMT_TK_HASHCHECK *validation,
           TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_VerifySignature (const TPMI_DH_OBJECT keyHandle,
                      const TPMS_AUTH_COMMAND *authCommand,
                      const TPM2B_DIGEST *digest,
                      const TPMT_SIGNATURE *signature,
                      TPMT_TK_VERIFIED *validation,
                      TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_PolicyAuthorize (const TPMI_SH_POLICY policySession,
                      const TPMS_AUTH_COMMAND *authCommand,
                      const TPM2B_DIGEST *approvedPolicy,
                      const TPM2B_NONCE *policyRef,
                      const TPM2B_NAME *keySign,
                      const TPMT_TK_VERIFIED *checkTicket,
                      TPMS_AUTH_RESPONSE *authResponse);

#endif /* ! GRUB_TPM2_INTERNAL_FUNCTIONS_HEADER */
