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
#include <grub/misc.h>
#include <grub/tpm2/buffer.h>
#include <grub/tpm2/mu.h>
#include <grub/tpm2/tcg2.h>
#include <grub/tpm2/tpm2.h>
#include <grub/types.h>

static TPM_RC
grub_tpm2_submit_command_real (const TPMI_ST_COMMAND_TAG tag,
			       const TPM_CC commandCode,
			       TPM_RC *responseCode,
			       const struct grub_tpm2_buffer *in,
			       struct grub_tpm2_buffer *out)
{
  grub_err_t err;
  struct grub_tpm2_buffer buf;
  TPMI_ST_COMMAND_TAG tag_out;
  grub_uint32_t command_size;
  grub_size_t max_output_size;

  /* Marshal */
  grub_tpm2_buffer_init (&buf);
  grub_tpm2_buffer_pack_u16 (&buf, tag);
  grub_tpm2_buffer_pack_u32 (&buf, 0);
  grub_tpm2_buffer_pack_u32 (&buf, commandCode);
  grub_tpm2_buffer_pack (&buf, in->data, in->size);

  if (buf.error)
    return TPM_RC_FAILURE;

  command_size = grub_swap_bytes32 (buf.size);
  grub_memcpy (&buf.data[sizeof (grub_uint16_t)], &command_size,
	       sizeof (command_size));

  /* Stay within output block limits */
  err = grub_tcg2_get_max_output_size (&max_output_size);
  if (err || max_output_size > out->cap)
    max_output_size = out->cap - 1;

  /* Submit */
  err = grub_tcg2_submit_command (buf.size, buf.data, max_output_size,
				  out->data);
  if (err)
    return TPM_RC_FAILURE;

  /* Unmarshal*/
  out->size = sizeof (grub_uint16_t) + sizeof (grub_uint32_t) +
	      sizeof (grub_uint32_t);
  grub_tpm2_buffer_unpack_u16 (out, &tag_out);
  grub_tpm2_buffer_unpack_u32 (out, &command_size);
  grub_tpm2_buffer_unpack_u32 (out, responseCode);
  out->size = command_size;
  if (out->error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

static TPM_RC
grub_tpm2_submit_command (const TPMI_ST_COMMAND_TAG tag,
			  const TPM_CC commandCode,
			  TPM_RC *responseCode,
			  const struct grub_tpm2_buffer *in,
			  struct grub_tpm2_buffer *out)
{
  TPM_RC err;
  int retry_cnt = 0;

  /* Catch TPM_RC_RETRY and send the command again */
  do {
    err = grub_tpm2_submit_command_real (tag, commandCode, responseCode,
					 in, out);
    if (*responseCode != TPM_RC_RETRY)
      break;

    retry_cnt++;
  } while (retry_cnt < 3);

  return err;
}

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
		    TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_HANDLE objectHandleTmp;
  TPM2B_PUBLIC outPublicTmp;
  TPM2B_CREATION_DATA creationDataTmp;
  TPM2B_DIGEST creationHashTmp;
  TPMT_TK_CREATION creationTicketTmp;
  TPM2B_NAME nameTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t parameterSize;

  if (!inSensitive || !inPublic || !outsideInfo || !creationPCR)
    return TPM_RC_VALUE;

  if (!objectHandle)
    objectHandle = &objectHandleTmp;
  if (!outPublic)
    outPublic = &outPublicTmp;
  if (!creationData)
    creationData = &creationDataTmp;
  if (!creationHash)
    creationHash = &creationHashTmp;
  if (!creationTicket)
    creationTicket = &creationTicketTmp;
  if (!name)
    name = &nameTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (outPublic, 0, sizeof (*outPublic));
  grub_memset (creationData, 0, sizeof (*creationData));
  grub_memset (creationHash, 0, sizeof (*creationHash));
  grub_memset (creationTicket, 0, sizeof (*creationTicket));
  grub_memset (name, 0, sizeof (*name));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, primaryHandle);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPM2B_SENSITIVE_CREATE_Marshal (&in, inSensitive);
  grub_tpm2_mu_TPM2B_PUBLIC_Marshal (&in, inPublic);
  grub_tpm2_mu_TPM2B_Marshal (&in, outsideInfo->size, outsideInfo->buffer);
  grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (&in, creationPCR);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_CreatePrimary, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  grub_tpm2_buffer_unpack_u32 (&out, objectHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&out, outPublic);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)creationData);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)creationHash);
  grub_tpm2_mu_TPMT_TK_CREATION_Unmarshal (&out, creationTicket);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)name);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

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
		       TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_SH_AUTH_SESSION sessionHandleTmp;
  TPM2B_NONCE nonceTpmTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!nonceCaller || !symmetric)
    return TPM_RC_VALUE;

  if (tpmKey == TPM_RH_NULL &&
      (encryptedSalt && encryptedSalt->size != 0))
    return TPM_RC_VALUE;

  if (!sessionHandle)
    sessionHandle = &sessionHandleTmp;
  if (!nonceTpm)
    nonceTpm = &nonceTpmTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (sessionHandle, 0, sizeof (*sessionHandle));
  grub_memset (nonceTpm, 0, sizeof (*nonceTpm));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, tpmKey);
  grub_tpm2_buffer_pack_u32 (&in, bind);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPM2B_Marshal (&in, nonceCaller->size, nonceCaller->buffer);
  if (encryptedSalt)
    grub_tpm2_mu_TPM2B_Marshal (&in, encryptedSalt->size, encryptedSalt->secret);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_buffer_pack_u8 (&in, sessionType);
  grub_tpm2_mu_TPMT_SYM_DEF_Marshal (&in, symmetric);
  grub_tpm2_buffer_pack_u16 (&in, authHash);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_StartAuthSession, &responseCode,
				 &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  grub_tpm2_buffer_unpack_u32 (&out, sessionHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)nonceTpm);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_PolicyPCR (const TPMI_SH_POLICY policySessions,
		const TPMS_AUTH_COMMAND *authCommand,
		const TPM2B_DIGEST *pcrDigest,
		const TPML_PCR_SELECTION *pcrs,
		TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!pcrs)
    return TPM_RC_VALUE;

  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, policySessions);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (pcrDigest)
    grub_tpm2_mu_TPM2B_Marshal (&in, pcrDigest->size, pcrDigest->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (&in, pcrs);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_PolicyPCR, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_ReadPublic (const TPMI_DH_OBJECT objectHandle,
		 const TPMS_AUTH_COMMAND* authCommand,
		 TPM2B_PUBLIC *outPublic)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t parameterSize;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, objectHandle);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_ReadPublic, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&out, outPublic);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_Load (const TPMI_DH_OBJECT parent_handle,
	   const TPMS_AUTH_COMMAND *authCommand,
	   const TPM2B_PRIVATE *inPrivate,
	   const TPM2B_PUBLIC *inPublic,
	   TPM_HANDLE *objectHandle,
	   TPM2B_NAME *name,
	   TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_HANDLE objectHandleTmp;
  TPM2B_NAME nonceTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!inPrivate || !inPublic)
    return TPM_RC_VALUE;

  if (!objectHandle)
    objectHandle = &objectHandleTmp;
  if (!name)
    name = &nonceTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (objectHandle, 0, sizeof (*objectHandle));
  grub_memset (name, 0, sizeof (*name));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, parent_handle);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPM2B_Marshal (&in, inPrivate->size, inPrivate->buffer);
  grub_tpm2_mu_TPM2B_PUBLIC_Marshal (&in, inPublic);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_Load, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  grub_tpm2_buffer_unpack_u32 (&out, objectHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)name);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_LoadExternal (const TPMS_AUTH_COMMAND *authCommand,
                   const TPM2B_SENSITIVE *inPrivate,
                   const TPM2B_PUBLIC *inPublic,
                   const TPMI_RH_HIERARCHY hierarchy,
                   TPM_HANDLE *objectHandle,
                   TPM2B_NAME *name,
                   TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_HANDLE objectHandleTmp;
  TPM2B_NAME nameTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!inPublic)
    return TPM_RC_VALUE;

  if (!objectHandle)
    objectHandle = &objectHandleTmp;
  if (!name)
    name = &nameTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (objectHandle, 0, sizeof (*objectHandle));
  grub_memset (name, 0, sizeof (*name));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (inPrivate)
    grub_tpm2_mu_TPM2B_SENSITIVE_Marshal (&in, inPrivate);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_mu_TPM2B_PUBLIC_Marshal (&in, inPublic);
  grub_tpm2_buffer_pack_u32 (&in, hierarchy);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_LoadExternal, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  grub_tpm2_buffer_unpack_u32 (&out, objectHandle);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)name);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_Unseal (const TPMI_DH_OBJECT itemHandle,
	     const TPMS_AUTH_COMMAND *authCommand,
	     TPM2B_SENSITIVE_DATA *outData,
	     TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM2B_SENSITIVE_DATA outDataTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!outData)
    outData = &outDataTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (outData, 0, sizeof (*outData));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, itemHandle);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_Unseal, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  // Unmarhsal
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)outData);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_FlushContext (const TPMI_DH_CONTEXT handle)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM_RC responseCode;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, handle);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (TPM_ST_NO_SESSIONS, TPM_CC_FlushContext,
				 &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_PCR_Read (const TPMS_AUTH_COMMAND *authCommand,
	       const TPML_PCR_SELECTION  *pcrSelectionIn,
	       grub_uint32_t *pcrUpdateCounter,
	       TPML_PCR_SELECTION *pcrSelectionOut,
	       TPML_DIGEST *pcrValues,
	       TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  grub_uint32_t pcrUpdateCounterTmp;
  TPML_PCR_SELECTION pcrSelectionOutTmp;
  TPML_DIGEST pcrValuesTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t parameterSize;

  if (!pcrSelectionIn)
    return TPM_RC_VALUE;

  if (!pcrUpdateCounter)
    pcrUpdateCounter = &pcrUpdateCounterTmp;
  if (!pcrSelectionOut)
    pcrSelectionOut = &pcrSelectionOutTmp;
  if (!pcrValues)
    pcrValues = &pcrValuesTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (&in, pcrSelectionIn);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_PCR_Read, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_buffer_unpack_u32 (&out, pcrUpdateCounter);
  grub_tpm2_mu_TPML_PCR_SELECTION_Unmarshal (&out, pcrSelectionOut);
  grub_tpm2_mu_TPML_DIGEST_Unmarshal (&out, pcrValues);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_PolicyGetDigest (const TPMI_SH_POLICY policySession,
		      const TPMS_AUTH_COMMAND *authCommand,
		      TPM2B_DIGEST *policyDigest,
		      TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPM2B_DIGEST policyDigestTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t parameterSize;

  if (!authResponse)
    authResponse = &authResponseTmp;
  if (!policyDigest)
    policyDigest = &policyDigestTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));
  grub_memset (policyDigest, 0, sizeof (*policyDigest));

  /* Submit */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, policySession);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_PolicyGetDigest, &responseCode,
				 &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)policyDigest);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

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
	     TPMS_AUTH_RESPONSE *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM2B_PUBLIC outPublicTmp;
  TPM2B_PRIVATE outPrivateTmp;
  TPM2B_CREATION_DATA creationDataTmp;
  TPM2B_DIGEST creationHashTmp;
  TPMT_TK_CREATION creationTicketTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS:TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  TPM_RC rc;
  grub_uint32_t parameterSize;

  if (!inSensitive || !inPublic || !outsideInfo || !creationPCR)
    return TPM_RC_VALUE;

  if (!outPrivate)
    outPrivate = &outPrivateTmp;
  if (!outPublic)
    outPublic = &outPublicTmp;
  if (!creationData)
    creationData = &creationDataTmp;
  if (!creationHash)
    creationHash = &creationHashTmp;
  if (!creationTicket)
    creationTicket = &creationTicketTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (outPrivate, 0, sizeof (*outPrivate));
  grub_memset (outPublic, 0, sizeof (*outPublic));
  grub_memset (creationData, 0, sizeof (*creationData));
  grub_memset (creationHash, 0, sizeof (*creationHash));
  grub_memset (creationTicket, 0, sizeof (*creationTicket));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, parentHandle);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPM2B_SENSITIVE_CREATE_Marshal (&in, inSensitive);
  grub_tpm2_mu_TPM2B_PUBLIC_Marshal (&in, inPublic);
  grub_tpm2_mu_TPM2B_Marshal (&in, outsideInfo->size, outsideInfo->buffer);
  grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (&in, creationPCR);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_Create, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
   grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)outPrivate);
  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&out, outPublic);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)creationData);
  grub_tpm2_mu_TPM2B_Unmarshal (&out, (TPM2B*)creationHash);
  grub_tpm2_mu_TPMT_TK_CREATION_Unmarshal (&out, creationTicket);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_EvictControl (const TPMI_RH_PROVISION auth,
		   const TPMI_DH_OBJECT objectHandle,
		   const TPMS_AUTH_COMMAND *authCommand,
		   const TPMI_DH_PERSISTENT persistentHandle,
		   TPMS_AUTH_RESPONSE *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  TPM_RC rc;
  grub_uint32_t parameterSize;

  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, auth);
  grub_tpm2_buffer_pack_u32 (&in, objectHandle);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_buffer_pack_u32 (&in, persistentHandle);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_EvictControl, &responseCode, &in,
				 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    {
      grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
      grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
    }
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_HashSequenceStart (const TPMS_AUTH_COMMAND *authCommand,
                        const TPM2B_AUTH *auth,
                        const TPMI_ALG_HASH hashAlg,
                        TPMI_DH_OBJECT *sequenceHandle,
                        TPMS_AUTH_RESPONSE *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMI_DH_OBJECT sequenceHandleTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  TPM_RC rc;
  grub_uint32_t parameterSize;

  if (!auth)
    return TPM_RC_VALUE;

  if (!sequenceHandle)
    sequenceHandle = &sequenceHandleTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (sequenceHandle, 0, sizeof (*sequenceHandle));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPM2B_Marshal (&in, auth->size, auth->buffer);
  grub_tpm2_buffer_pack_u16 (&in, hashAlg);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_HashSequenceStart, &responseCode, &in,
                                 &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, sequenceHandle);
  if (tag == TPM_ST_SESSIONS)
    {
      grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
      grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
    }
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_SequenceUpdate (const TPMI_DH_OBJECT sequenceHandle,
                     const TPMS_AUTH_COMMAND *authCommand,
                     const TPM2B_MAX_BUFFER *buffer,
                     TPMS_AUTH_RESPONSE *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPM_RC responseCode;
  TPM_RC rc;
  grub_uint32_t parameterSize;

  if (!authCommand)
    return TPM_RC_VALUE;

  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, sequenceHandle);
  grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (buffer)
    grub_tpm2_mu_TPM2B_Marshal (&in, buffer->size, buffer->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (TPM_ST_SESSIONS, TPM_CC_SequenceUpdate,
                                 &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_SequenceComplete (const TPMI_DH_OBJECT sequenceHandle,
                       const TPMS_AUTH_COMMAND *authCommand,
                       const TPM2B_MAX_BUFFER *buffer,
                       const TPMI_RH_HIERARCHY hierarchy,
                       TPM2B_DIGEST *result,
                       TPMT_TK_HASHCHECK *validation,
                       TPMS_AUTH_RESPONSE *authResponse)
{
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPM2B_DIGEST resultTmp;
  TPMT_TK_HASHCHECK validationTmp;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPM_RC responseCode;
  TPM_RC rc;
  grub_uint32_t parameterSize;

  if (!authCommand)
    return TPM_RC_VALUE;

  if (!result)
    result = &resultTmp;
  if (!validation)
    validation = &validationTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (result, 0, sizeof (*result));
  grub_memset (validation, 0, sizeof (*validation));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, sequenceHandle);
  grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (buffer)
    grub_tpm2_mu_TPM2B_Marshal (&in, buffer->size, buffer->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_buffer_pack_u32 (&in, hierarchy);

  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (TPM_ST_SESSIONS, TPM_CC_SequenceComplete,
                                 &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal */
  grub_tpm2_buffer_unpack_u32 (&out, &parameterSize);
  grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (&out, result);
  grub_tpm2_mu_TPMT_TK_HASHCHECK_Unmarshal (&out, validation);
  grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal(&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_Hash (const TPMS_AUTH_COMMAND *authCommand,
           const TPM2B_MAX_BUFFER *data,
           const TPMI_ALG_HASH hashAlg,
           const TPMI_RH_HIERARCHY hierarchy,
           TPM2B_DIGEST *outHash,
           TPMT_TK_HASHCHECK *validation,
           TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPM2B_DIGEST outHashTmp;
  TPMT_TK_HASHCHECK validationTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (hashAlg == TPM_ALG_NULL)
    return TPM_RC_VALUE;

  if (!outHash)
    outHash = &outHashTmp;
  if (!validation)
    validation = &validationTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (outHash, 0, sizeof (*outHash));
  grub_memset (validation, 0, sizeof (*validation));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  if (data)
    grub_tpm2_mu_TPM2B_Marshal (&in, data->size, data->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_buffer_pack_u16 (&in, hashAlg);
  grub_tpm2_buffer_pack_u32 (&in, hierarchy);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_Hash, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (&out, outHash);
  grub_tpm2_mu_TPMT_TK_HASHCHECK_Unmarshal (&out, validation);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_VerifySignature (const TPMI_DH_OBJECT keyHandle,
                      const TPMS_AUTH_COMMAND *authCommand,
                      const TPM2B_DIGEST *digest,
                      const TPMT_SIGNATURE *signature,
                      TPMT_TK_VERIFIED *validation,
                      TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPMT_TK_VERIFIED validationTmp;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!digest || !signature)
    return TPM_RC_VALUE;

  if (!validation)
    validation = &validationTmp;
  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (validation, 0, sizeof (*validation));
  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_buffer_pack_u32 (&in, keyHandle);
  grub_tpm2_mu_TPM2B_Marshal (&in, digest->size, digest->buffer);
  grub_tpm2_mu_TPMT_SIGNATURE_Marshal (&in, signature);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_VerifySignature, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  grub_tpm2_mu_TPMT_TK_VERIFIED_Unmarshal (&out, validation);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}

TPM_RC
TPM2_PolicyAuthorize (const TPMI_SH_POLICY policySession,
                      const TPMS_AUTH_COMMAND *authCommand,
                      const TPM2B_DIGEST *approvedPolicy,
                      const TPM2B_NONCE *policyRef,
                      const TPM2B_NAME *keySign,
                      const TPMT_TK_VERIFIED *checkTicket,
                      TPMS_AUTH_RESPONSE *authResponse)
{
  TPM_RC rc;
  struct grub_tpm2_buffer in;
  struct grub_tpm2_buffer out;
  TPMS_AUTH_RESPONSE authResponseTmp;
  TPMI_ST_COMMAND_TAG tag = authCommand ? TPM_ST_SESSIONS : TPM_ST_NO_SESSIONS;
  TPM_RC responseCode;
  grub_uint32_t param_size;

  if (!approvedPolicy || !keySign || !checkTicket)
    return TPM_RC_VALUE;

  if (!authResponse)
    authResponse = &authResponseTmp;

  grub_memset (authResponse, 0, sizeof (*authResponse));

  /* Marshal */
  grub_tpm2_buffer_init (&in);
  grub_tpm2_buffer_pack_u32 (&in, policySession);
  if (authCommand)
    grub_tpm2_mu_TPMS_AUTH_COMMAND_Marshal (&in, authCommand);
  grub_tpm2_mu_TPM2B_Marshal (&in, approvedPolicy->size, approvedPolicy->buffer);
  if (policyRef)
    grub_tpm2_mu_TPM2B_Marshal (&in, policyRef->size, policyRef->buffer);
  else
    grub_tpm2_buffer_pack_u16 (&in, 0);
  grub_tpm2_mu_TPM2B_Marshal (&in, keySign->size, keySign->name);
  grub_tpm2_mu_TPMT_TK_VERIFIED_Marshal (&in, checkTicket);
  if (in.error)
    return TPM_RC_FAILURE;

  /* Submit */
  grub_tpm2_buffer_init (&out);
  rc = grub_tpm2_submit_command (tag, TPM_CC_PolicyAuthorize, &responseCode, &in, &out);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (responseCode != TPM_RC_SUCCESS)
    return responseCode;

  /* Unmarshal*/
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_buffer_unpack_u32 (&out, &param_size);
  if (tag == TPM_ST_SESSIONS)
    grub_tpm2_mu_TPMS_AUTH_RESPONSE_Unmarshal (&out, authResponse);
  if (out.error)
    return TPM_RC_FAILURE;

  return TPM_RC_SUCCESS;
}
