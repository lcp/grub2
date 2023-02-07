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
TPM2_CreatePrimary (TPMI_RH_HIERARCHY primaryHandle,
		    const TPMS_AUTH_COMMAND *authCommand,
		    TPM2B_SENSITIVE_CREATE *inSensitive,
		    TPM2B_PUBLIC *inPublic,
		    TPM2B_DATA *outsideInfo,
		    TPML_PCR_SELECTION *creationPCR,
		    TPM_HANDLE *objectHandle,
		    TPM2B_PUBLIC *outPublic,
		    TPM2B_CREATION_DATA *creationData,
		    TPM2B_DIGEST *creationHash,
		    TPMT_TK_CREATION *creationTicket,
		    TPM2B_NAME *name,
		    TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_StartAuthSession (TPMI_DH_OBJECT tpmKey,
		       TPMI_DH_ENTITY bind,
		       const TPMS_AUTH_COMMAND *authCommand,
		       TPM2B_NONCE *nonceCaller,
		       TPM2B_ENCRYPTED_SECRET *encryptedSalt,
		       TPM_SE sessionType,
		       TPMT_SYM_DEF *symmetric,
		       TPMI_ALG_HASH authHash,
		       TPMI_SH_AUTH_SESSION *sessionHandle,
		       TPM2B_NONCE *nonceTpm,
		       TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_PolicyPCR (TPMI_SH_POLICY policySession,
		const TPMS_AUTH_COMMAND *authCommand,
		TPM2B_DIGEST *pcrDigest,
		TPML_PCR_SELECTION *pcrs,
		TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_ReadPublic (TPMI_DH_OBJECT objectHandle,
		 const TPMS_AUTH_COMMAND* authCommand,
		 TPM2B_PUBLIC *outPublic);

TPM_RC
TPM2_Load (TPMI_DH_OBJECT parent_handle,
	   TPMS_AUTH_COMMAND const *authCommand,
	   TPM2B_PRIVATE *inPrivate,
	   TPM2B_PUBLIC *inPublic,
	   TPM_HANDLE *objectHandle,
	   TPM2B_NAME *name,
	   TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_Unseal (TPMI_DH_OBJECT item_handle,
	     const TPMS_AUTH_COMMAND *authCommand,
	     TPM2B_SENSITIVE_DATA *outData,
	     TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_FlushContext (TPMI_DH_CONTEXT handle);

TPM_RC
TPM2_PCR_Read (const TPMS_AUTH_COMMAND *authCommand,
	       TPML_PCR_SELECTION  *pcrSelectionIn,
	       grub_uint32_t *pcrUpdateCounter,
	       TPML_PCR_SELECTION *pcrSelectionOut,
	       TPML_DIGEST *pcrValues,
	       TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_PolicyGetDigest (TPMI_SH_POLICY policySession,
		      const TPMS_AUTH_COMMAND *authCommand,
		      TPM2B_DIGEST *policyDigest,
		      TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_Create (TPMI_DH_OBJECT parentHandle,
	     const TPMS_AUTH_COMMAND *authCommand,
	     TPM2B_SENSITIVE_CREATE *inSensitive,
	     TPM2B_PUBLIC *inPublic,
	     TPM2B_DATA *outsideInfo,
	     TPML_PCR_SELECTION *creationPCR,
	     TPM2B_PRIVATE *outPrivate,
	     TPM2B_PUBLIC *outPublic,
	     TPM2B_CREATION_DATA *creationData,
	     TPM2B_DIGEST *creationHash,
	     TPMT_TK_CREATION *creationTicket,
	     TPMS_AUTH_RESPONSE *authResponse);

TPM_RC
TPM2_EvictControl (TPMI_RH_PROVISION auth,
		   TPMI_DH_OBJECT objectHandle,
		   const TPMS_AUTH_COMMAND *authCommand,
		   TPMI_DH_PERSISTENT persistentHandle,
		   TPMS_AUTH_RESPONSE *authResponse);

#endif /* ! GRUB_TPM2_INTERNAL_FUNCTIONS_HEADER */
