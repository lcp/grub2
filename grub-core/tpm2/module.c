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

#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/libtasn1.h>
#include <grub/list.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/protector.h>
#include <grub/tpm2/buffer.h>
#include <grub/tpm2/internal/args.h>
#include <grub/tpm2/internal/types.h>
#include <grub/tpm2/mu.h>
#include <grub/tpm2/tpm2.h>
#include <grub/tpm2/tpm2key.h>

GRUB_MOD_LICENSE ("GPLv3+");

typedef enum grub_tpm2_protector_mode
{
  GRUB_TPM2_PROTECTOR_MODE_UNSET,
  GRUB_TPM2_PROTECTOR_MODE_SRK,
  GRUB_TPM2_PROTECTOR_MODE_NV
} grub_tpm2_protector_mode_t;

enum grub_tpm2_protector_options
{
  OPTION_MODE,
  OPTION_PCRS,
  OPTION_BANK,
  OPTION_TPM2KEY,
  OPTION_KEYFILE,
  OPTION_SRK,
  OPTION_ASYMMETRIC,
  OPTION_NVINDEX
};

struct grub_tpm2_protector_context
{
  grub_tpm2_protector_mode_t mode;
  grub_uint8_t pcrs[TPM_MAX_PCRS];
  grub_uint8_t pcr_count;
  TPM_ALG_ID asymmetric;
  TPM_KEY_BITS rsa_bits;
  TPM_ECC_CURVE ecc_curve;
  TPM_ALG_ID bank;
  const char *tpm2key;
  const char *keyfile;
  TPM_HANDLE srk;
  TPM_HANDLE nv;
};

static const struct grub_arg_option grub_tpm2_protector_init_cmd_options[] =
  {
    /* Options for all modes */
    {
      .longarg  = "mode",
      .shortarg = 'm',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Unseal key using SRK ('srk') (default) or retrieve it from an NV "
	   "Index ('nv')."),
    },
    {
      .longarg  = "pcrs",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Comma-separated list of PCRs used to authorize key release "
	   "(e.g., '7,11', default is 7."),
    },
    {
      .longarg  = "bank",
      .shortarg = 'b',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Bank of PCRs used to authorize key release: "
	   "SHA1, SHA256 (default), SHA384 or SHA512."),
    },
    /* SRK-mode options */
    {
      .longarg  = "tpm2key",
      .shortarg = 'T',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Required in SRK mode, path to the key file in TPM 2.0 Key File Format "
	   "to unseal using the TPM (e.g., (hd0,gpt1)/boot/grub2/secret.tpm)."),
    },
    {
      .longarg  = "keyfile",
      .shortarg = 'k',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Required in SRK mode, path to the sealed key file to unseal using "
	   "the TPM (e.g., (hd0,gpt1)/boot/grub2/sealed_key). "
           "Use '-tpm2key' instead"),
    },
    {
      .longarg  = "srk",
      .shortarg = 's',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("In SRK mode, the SRK handle if the SRK is persistent."),
    },
    {
      .longarg  = "asymmetric",
      .shortarg = 'a',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("In SRK mode, the type of SRK: RSA (RSA2048), RSA3072, "
	   "RSA4096, ECC (ECC_NIST_P256), ECC_NIST_P384, "
	   "ECC_NIST_P521, ECC_BN_P256, ECC_BN_P638, and ECC_SM2_P256. "
	   "(default is RSA2048)"),
    },
    /* NV Index-mode options */
    {
      .longarg  = "nvindex",
      .shortarg = 'n',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
	N_("Required in NV Index mode, the NV handle to read which must "
	   "readily exist on the TPM and which contains the key."),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

static grub_extcmd_t grub_tpm2_protector_init_cmd;
static grub_extcmd_t grub_tpm2_protector_clear_cmd;
static struct grub_tpm2_protector_context grub_tpm2_protector_ctx = { 0 };

static grub_err_t
grub_tpm2_protector_srk_read_file (const char *filepath, void **buffer,
				   grub_size_t *buffer_size)
{
  grub_file_t file;
  grub_off_t file_size;
  void *read_buffer;
  grub_off_t read_n;
  grub_err_t err;

  /* Using GRUB_FILE_TYPE_SIGNATURE ensures we do not hash the keyfile into PCR9
   * otherwise we'll never be able to predict the value of PCR9 at unseal time */
  file = grub_file_open (filepath, GRUB_FILE_TYPE_SIGNATURE);
  if (file == NULL)
    {
      /* Push errno from grub_file_open() into the error message stack */
      grub_error_push();
      err = grub_error (GRUB_ERR_FILE_NOT_FOUND,
			N_("Could not open file: %s\n"),
			filepath);
      goto error;
    }

  file_size = grub_file_size (file);
  if (file_size == 0)
    {
      err = grub_error (GRUB_ERR_OUT_OF_RANGE,
			N_("Could not read file size: %s"),
			filepath);
      goto error;
    }

  read_buffer = grub_malloc (file_size);
  if (read_buffer == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
			N_("Could not allocate buffer for %s"),
			filepath);
      goto error;
    }

  read_n = grub_file_read (file, read_buffer, file_size);
  if (read_n != file_size)
    {
      grub_free (read_buffer);
      err = grub_error (GRUB_ERR_FILE_READ_ERROR,
			N_("Could not retrieve file contents: %s"),
			filepath);
      goto error;
    }

  *buffer = read_buffer;
  *buffer_size = file_size;

  err = GRUB_ERR_NONE;

error:
  grub_file_close (file);

  return err;
}

static grub_err_t
grub_tpm2_protector_srk_unmarshal_keyfile (void *sealed_key,
					   grub_size_t sealed_key_size,
					   TPM2_SEALED_KEY *sk)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  if (sealed_key_size > buf.cap)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("Sealed key larger than %" PRIuGRUB_SIZE " bytes"),
		       buf.cap);

  grub_memcpy (buf.data, sealed_key, sealed_key_size);
  buf.size = sealed_key_size;

  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&buf, &sk->public);
  grub_tpm2_mu_TPM2B_Unmarshal (&buf, (TPM2B *)&sk->private);

  if (buf.error)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Malformed TPM wire key file"));

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_srk_unmarshal_tpm2key (void *sealed_key,
					   grub_size_t sealed_key_size,
					   tpm2key_policy_t *policy_seq,
					   tpm2key_authpolicy_t *authpol_seq,
					   grub_uint32_t *parent,
					   TPM2_SEALED_KEY *sk)
{
  asn1_node tpm2key = NULL;
  grub_uint32_t parent_tmp;
  void *sealed_pub = NULL;
  grub_size_t sealed_pub_size;
  void *sealed_priv = NULL;
  grub_size_t sealed_priv_size;
  struct grub_tpm2_buffer buf;
  grub_err_t err;

  /*
   * Start to parse the tpm2key file
   * TPMKey ::= SEQUENCE {
   *     type        OBJECT IDENTIFIER,
   *     emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
   *     policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
   *     secret      [2] EXPLICIT OCTET STRING OPTIONAL,
   *     authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
   *     parent      INTEGER,
   *     pubkey      OCTET STRING,
   *     privkey     OCTET STRING
   * }
   */
  err = grub_tpm2key_start_parsing (&tpm2key, sealed_key, sealed_key_size);
  if (err != GRUB_ERR_NONE)
    return err;

  /*
   * Retrieve the policy sequence from 'policy'
   * policy_seq will be NULL when 'policy' is not available
   */
  err = grub_tpm2key_get_policy_seq (tpm2key, policy_seq);
  if (err != GRUB_ERR_NONE)
    goto error;

  /*
   * Retrieve the authpolicy sequence from 'authPolicy'
   * authpol_seq will be NULL when 'authPolicy' is not available
   */
  err = grub_tpm2key_get_authpolicy_seq (tpm2key, authpol_seq);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Retrieve the parent handle */
  err = grub_tpm2key_get_parent (tpm2key, &parent_tmp);
  if (err != GRUB_ERR_NONE)
    goto error;
  *parent = parent_tmp;

  /* Retrieve the public part of the sealed key */
  err = grub_tpm2key_get_pubkey (tpm2key, &sealed_pub, &sealed_pub_size);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Retrieve the private part of the sealed key */
  err = grub_tpm2key_get_privkey (tpm2key, &sealed_priv, &sealed_priv_size);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Unmarshal the sealed key */
  grub_tpm2_buffer_init (&buf);
  if (sealed_pub_size + sealed_priv_size > buf.cap)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT,
			N_("Sealed key larger than %" PRIuGRUB_SIZE " bytes"),
			buf.cap);
      goto error;
    }

  grub_tpm2_buffer_pack (&buf, sealed_pub, sealed_pub_size);
  grub_tpm2_buffer_pack (&buf, sealed_priv, sealed_priv_size);

  buf.offset = 0;

  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&buf, &sk->public);
  grub_tpm2_mu_TPM2B_Unmarshal (&buf, (TPM2B *)&sk->private);

  if (buf.error)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Malformed TPM 2.0 key file"));
      goto error;
    }

  err = GRUB_ERR_NONE;

error:
  /* End the parsing */
  grub_tpm2key_end_parsing (tpm2key);
  grub_free (sealed_pub);
  grub_free (sealed_priv);

  return err;
}

static grub_err_t
grub_tpm2_protector_srk_get (const struct grub_tpm2_protector_context *ctx,
			     TPM_HANDLE parent, TPM_HANDLE *srk)
{
  TPM_RC rc;
  TPM2B_PUBLIC public;
  TPMS_AUTH_COMMAND authCommand = { 0 };
  TPM2B_SENSITIVE_CREATE inSensitive = { 0 };
  TPM2B_PUBLIC inPublic = { 0 };
  TPM2B_DATA outsideInfo = { 0 };
  TPML_PCR_SELECTION creationPcr = { 0 };
  TPM2B_PUBLIC outPublic = { 0 };
  TPM2B_CREATION_DATA creationData = { 0 };
  TPM2B_DIGEST creationHash = { 0 };
  TPMT_TK_CREATION creationTicket = { 0 };
  TPM2B_NAME srkName = { 0 };
  TPM_HANDLE srkHandle;

  if (ctx->srk != 0)
    {
      /* Find SRK */
      rc = TPM2_ReadPublic (ctx->srk, NULL, &public);
      if (rc == TPM_RC_SUCCESS)
	{
	  *srk = ctx->srk;
	  return GRUB_ERR_NONE;
	}

      return grub_error (GRUB_ERR_BAD_DEVICE,
			 N_("Failed to retrieve SRK (TPM2_ReadPublic: 0x%x)"),
			 rc);
    }

  /* Create SRK */
  authCommand.sessionHandle = TPM_RS_PW;
  inPublic.publicArea.type = ctx->asymmetric;
  inPublic.publicArea.nameAlg  = TPM_ALG_SHA256;
  inPublic.publicArea.objectAttributes.restricted = 1;
  inPublic.publicArea.objectAttributes.userWithAuth = 1;
  inPublic.publicArea.objectAttributes.decrypt = 1;
  inPublic.publicArea.objectAttributes.fixedTPM = 1;
  inPublic.publicArea.objectAttributes.fixedParent = 1;
  inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
  inPublic.publicArea.objectAttributes.noDA = 1;

  if (ctx->asymmetric == TPM_ALG_RSA)
    {
      inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.rsaDetail.keyBits = ctx->rsa_bits;
      inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    }
  else if (ctx->asymmetric == TPM_ALG_ECC)
    {
      inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.eccDetail.curveID = ctx->ecc_curve;
      inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    }
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Unknown SRK algorithm"));

  rc = TPM2_CreatePrimary (parent, &authCommand, &inSensitive, &inPublic,
			   &outsideInfo, &creationPcr, &srkHandle, &outPublic,
			   &creationData, &creationHash, &creationTicket,
			   &srkName, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("Could not create SRK (TPM2_CreatePrimary: 0x%x)"),
		       rc);

  *srk = srkHandle;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_policypcr (TPMI_SH_AUTH_SESSION session,
			       struct grub_tpm2_buffer *cmd_buf)
{
  TPM2B_DIGEST pcr_digest;
  TPML_PCR_SELECTION pcr_sel;
  TPM_RC rc;

  grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (cmd_buf, &pcr_digest);
  grub_tpm2_mu_TPML_PCR_SELECTION_Unmarshal (cmd_buf, &pcr_sel);
  if (cmd_buf->error)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("Failed to unmarshal CommandPolicy for TPM2_PolicyPCR"));

  rc = TPM2_PolicyPCR (session, NULL, &pcr_digest, &pcr_sel, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("Failed to submit PCR policy (TPM2_PolicyPCR: 0x%x)"),
		       rc);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_policyauthorize (TPMI_SH_AUTH_SESSION session,
				     struct grub_tpm2_buffer *cmd_buf)
{
  TPM2B_PUBLIC pubkey;
  TPM2B_DIGEST policy_ref;
  TPMT_SIGNATURE signature;
  TPM2B_DIGEST pcr_policy;
  TPM2B_DIGEST pcr_policy_hash;
  TPMI_ALG_HASH sig_hash;
  TPMT_TK_VERIFIED verification_ticket;
  TPM_HANDLE pubkey_handle = 0;
  TPM2B_NAME pubname;
  TPM_RC rc;
  grub_err_t err;

  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (cmd_buf, &pubkey);
  grub_tpm2_mu_TPM2B_DIGEST_Unmarshal (cmd_buf, &policy_ref);
  grub_tpm2_mu_TPMT_SIGNATURE_Unmarshal (cmd_buf, &signature);
  if (cmd_buf->error != 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("Failed to unmarshal the buffer for TPM2_PolicyAuthorize"));

  /* Retrieve Policy Digest */
  rc = TPM2_PolicyGetDigest (session, NULL, &pcr_policy, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("Failed to get policy digest (TPM2_PolicyGetDigest: 0x%x)."),
		       rc);

  /* Calculate the digest of the polcy for VerifySignature */
  sig_hash = TPMT_SIGNATURE_get_hash_alg (&signature);
  if (sig_hash == TPM_ALG_NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("Failed to get the hash algorithm of the signature"));

  rc = TPM2_Hash (NULL, (TPM2B_MAX_BUFFER *)&pcr_policy, sig_hash,
		  TPM_RH_NULL, &pcr_policy_hash, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("Failed to create PCR policy hash (TPM2_Hash: 0x%x)"),
		       rc);

  /* Load the public key */
  rc = TPM2_LoadExternal (NULL, NULL, &pubkey, TPM_RH_OWNER,
			  &pubkey_handle, &pubname, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("Failed to load public key (TPM2_LoadExternal: 0x%x)"),
		       rc);

  /* Verify the signature against the public key and the policy digest */
  rc = TPM2_VerifySignature (pubkey_handle, NULL, &pcr_policy_hash, &signature,
			     &verification_ticket, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE,
			N_("Failed to verify signature (TPM2_VerifySignature: 0x%x)"),
			rc);
      goto error;
    }

  /* Authorize the signed policy with the public key and the verification ticket */
  rc = TPM2_PolicyAuthorize (session, NULL, &pcr_policy, &policy_ref, &pubname,
			     &verification_ticket, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE,
			N_("Failed to authorize PCR policy (TPM2_PolicyAuthorize: 0x%x)"),
			rc);
      goto error;
    }

  err = GRUB_ERR_NONE;

error:
  TPM2_FlushContext (pubkey_handle);

  return err;
}

static grub_err_t
grub_tpm2_protector_enforce_policy (tpm2key_policy_t policy, TPMI_SH_AUTH_SESSION session)
{
  struct grub_tpm2_buffer buf;
  grub_err_t err;

  grub_tpm2_buffer_init (&buf);
  if (policy->cmd_policy_len > buf.cap)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("CommandPolicy larger than TPM buffer"));

  grub_memcpy (buf.data, policy->cmd_policy, policy->cmd_policy_len);
  buf.size = policy->cmd_policy_len;

  switch (policy->cmd_code)
    {
    case TPM_CC_PolicyPCR:
      err = grub_tpm2_protector_policypcr (session, &buf);
      break;
    case TPM_CC_PolicyAuthorize:
      err = grub_tpm2_protector_policyauthorize (session, &buf);
      break;
    default:
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
			 N_("Unknown TPM Command: 0x%x"), policy->cmd_code);
    }

  return err;
}

static grub_err_t
grub_tpm2_protector_enforce_policy_seq (tpm2key_policy_t policy_seq,
					TPMI_SH_AUTH_SESSION session)
{
  tpm2key_policy_t policy;
  grub_err_t err;

  FOR_LIST_ELEMENTS (policy, policy_seq)
    {
      err = grub_tpm2_protector_enforce_policy (policy, session);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_simple_policy_seq (const struct grub_tpm2_protector_context *ctx,
				       tpm2key_policy_t *policy_seq)
{
  tpm2key_policy_t policy = NULL;
  struct grub_tpm2_buffer buf;
  TPML_PCR_SELECTION pcr_sel = {
    .count = 1,
    .pcrSelections = {
      {
	.hash = ctx->bank,
	.sizeOfSelect = 3,
	.pcrSelect = { 0 }
      },
    }
  };
  grub_uint8_t i;
  grub_err_t err;

  if (policy_seq == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  grub_tpm2_buffer_init (&buf);

  for (i = 0; i < ctx->pcr_count; i++)
    TPMS_PCR_SELECTION_SelectPCR (&pcr_sel.pcrSelections[0], ctx->pcrs[i]);

  grub_tpm2_buffer_pack_u16 (&buf, 0);
  grub_tpm2_mu_TPML_PCR_SELECTION_Marshal (&buf, &pcr_sel);

  if (buf.error)
    return GRUB_ERR_BAD_ARGUMENT;

  policy = grub_malloc (sizeof(struct tpm2key_policy));
  if (policy == NULL)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }
  policy->cmd_code = TPM_CC_PolicyPCR;
  policy->cmd_policy = grub_malloc (buf.size);
  if (policy->cmd_policy == NULL)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto error;
    }
  grub_memcpy (policy->cmd_policy, buf.data, buf.size);
  policy->cmd_policy_len = buf.size;

  grub_list_push (GRUB_AS_LIST_P (policy_seq), GRUB_AS_LIST (policy));

  return GRUB_ERR_NONE;

error:
  grub_free (policy);

  return err;
}

static grub_err_t
grub_tpm2_protector_unseal (tpm2key_policy_t policy_seq, TPM_HANDLE sealed_handle,
			    grub_uint8_t **key, grub_size_t *key_size)
{
  TPMS_AUTH_COMMAND authCmd = { 0 };
  TPM2B_SENSITIVE_DATA data;
  TPM2B_NONCE nonceCaller = { 0 };
  TPMT_SYM_DEF symmetric = { 0 };
  TPMI_SH_AUTH_SESSION session;
  grub_uint8_t *key_out;
  TPM_RC rc;
  grub_err_t err;

  /* Start Auth Session */
  nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
  symmetric.algorithm = TPM_ALG_NULL;
  rc = TPM2_StartAuthSession (TPM_RH_NULL, TPM_RH_NULL, NULL, &nonceCaller, NULL,
			      TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256,
			      &session, NULL, NULL);
  if (rc != TPM_RC_SUCCESS)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("Failed to start auth session (TPM2_StartAuthSession: 0x%x)"),
		       rc);

  /* Enforce the policy command sequence */
  err = grub_tpm2_protector_enforce_policy_seq (policy_seq, session);
  if (err != GRUB_ERR_NONE)
    goto error;

  /* Unseal Sealed Key */
  authCmd.sessionHandle = session;
  rc = TPM2_Unseal (sealed_handle, &authCmd, &data, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE,
			N_("Failed to unseal sealed key (TPM2_Unseal: 0x%x)"),
			rc);
      goto error;
    }

  /* Epilogue */
  key_out = grub_malloc (data.size);
  if (key_out == NULL)
    {
      err = grub_error (GRUB_ERR_OUT_OF_MEMORY,
			N_("No memory left to allocate unlock key buffer"));
      goto error;
    }

  grub_memcpy (key_out, data.buffer, data.size);

  *key = key_out;
  *key_size = data.size;

  err = GRUB_ERR_NONE;

error:
  TPM2_FlushContext (session);

  return err;
}

static grub_err_t
grub_tpm2_protector_srk_recover (const struct grub_tpm2_protector_context *ctx,
				 grub_uint8_t **key, grub_size_t *key_size)
{
  TPMS_AUTH_COMMAND authCmd = { 0 };
  TPM2_SEALED_KEY sealed_key = { 0 };
  TPM2B_NAME name = { 0 };
  void *file_bytes = NULL;
  grub_size_t file_size = 0;
  TPM_HANDLE parent_handle = 0;
  TPM_HANDLE srk_handle = 0;
  TPM_HANDLE sealed_handle = 0;
  tpm2key_policy_t policy_seq = NULL;
  tpm2key_authpolicy_t authpol = NULL;
  tpm2key_authpolicy_t authpol_seq = NULL;
  TPM_RC rc;
  grub_err_t err;

  /*
   * Retrieve sealed key, parent handle, policy sequence, and authpolicy
   * sequence from the key file
  */
  if (ctx->tpm2key)
    {
      err = grub_tpm2_protector_srk_read_file (ctx->tpm2key, &file_bytes,
					       &file_size);
      if (err != GRUB_ERR_NONE)
	return err;

      err = grub_tpm2_protector_srk_unmarshal_tpm2key (file_bytes,
						       file_size,
						       &policy_seq,
						       &authpol_seq,
						       &parent_handle,
						       &sealed_key);
      if (err != GRUB_ERR_NONE)
	goto exit1;
    }
  else
    {
      err = grub_tpm2_protector_srk_read_file (ctx->keyfile, &file_bytes,
					       &file_size);
      if (err != GRUB_ERR_NONE)
	return err;

      parent_handle = TPM_RH_OWNER;
      err = grub_tpm2_protector_srk_unmarshal_keyfile (file_bytes,
						       file_size,
						       &sealed_key);
      if (err != GRUB_ERR_NONE)
	goto exit1;
    }

  /* Get the SRK to unseal the sealed key */
  err = grub_tpm2_protector_srk_get (ctx, parent_handle, &srk_handle);
  if (err != GRUB_ERR_NONE)
    goto exit1;

  /* Load the sealed key and associate it with the SRK */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = TPM2_Load (srk_handle, &authCmd, &sealed_key.private, &sealed_key.public,
		  &sealed_handle, &name, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      err = grub_error (GRUB_ERR_BAD_DEVICE,
			N_("Failed to load sealed key (TPM2_Load: 0x%x)"),
			rc);
      goto exit2;
    }

  /*
   * Set err to an error code to trigger the standalone policy sequence
   * if there is no authpolicy sequence
   */
  err = GRUB_ERR_READ_ERROR;

  /* Iterate the authpolicy sequence to find one that unseals the key */
  FOR_LIST_ELEMENTS (authpol, authpol_seq)
    {
      err = grub_tpm2_protector_unseal (authpol->policy_seq, sealed_handle,
					key, key_size);
      if (err == GRUB_ERR_NONE)
        break;

      /*
       * Push the error message into the grub_error stack
       * Note: The grub_error stack may overflow if there are too many policy
       *       sequences. Anyway, we still can keep the error messages from
       *       the first few policy sequences which are usually most likely to
       *       unseal the key.
       */
      grub_error_push();
    }

  /* Give the standalone policy sequence a try */
  if (err != GRUB_ERR_NONE)
    {
      /*
       * Create a basic policy sequence based on the given PCR selection if the
       * key file doesn't provide one
       */
      if (policy_seq == NULL)
	{
	  err = grub_tpm2_protector_simple_policy_seq (ctx, &policy_seq);
	  if (err != GRUB_ERR_NONE)
	    goto exit3;
	}

      err = grub_tpm2_protector_unseal (policy_seq, sealed_handle, key, key_size);
    }

  /* Pop error messages on success */
  if (err == GRUB_ERR_NONE)
    while (grub_error_pop ());

exit3:
  TPM2_FlushContext (sealed_handle);

exit2:
  TPM2_FlushContext (srk_handle);

exit1:
  grub_tpm2key_free_policy_seq (policy_seq);
  grub_tpm2key_free_authpolicy_seq (authpol_seq);
  grub_free (file_bytes);
  return err;
}

static grub_err_t
grub_tpm2_protector_nv_recover (const struct grub_tpm2_protector_context *ctx,
				grub_uint8_t **key, grub_size_t *key_size)
{
  TPM_HANDLE sealed_handle = ctx->nv;
  tpm2key_policy_t policy_seq = NULL;
  grub_err_t err;

  /* Create a basic policy sequence based on the given PCR selection */
  err = grub_tpm2_protector_simple_policy_seq (ctx, &policy_seq);
  if (err != GRUB_ERR_NONE)
    goto exit;

  err = grub_tpm2_protector_unseal (policy_seq, sealed_handle, key, key_size);

  /* Pop error messages on success */
  if (err == GRUB_ERR_NONE)
    while (grub_error_pop ());

exit:
  TPM2_FlushContext (sealed_handle);

  grub_tpm2key_free_policy_seq (policy_seq);

  return err;
}

static grub_err_t
grub_tpm2_protector_recover (const struct grub_tpm2_protector_context *ctx,
			     grub_uint8_t **key, grub_size_t *key_size)
{
  switch (ctx->mode)
    {
    case GRUB_TPM2_PROTECTOR_MODE_SRK:
      return grub_tpm2_protector_srk_recover (ctx, key, key_size);
    case GRUB_TPM2_PROTECTOR_MODE_NV:
      return grub_tpm2_protector_nv_recover (ctx, key, key_size);
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }
}

static grub_err_t
grub_tpm2_protector_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  /* Expect a call to tpm2_protector_init before anybody tries to use us */
  if (grub_tpm2_protector_ctx.mode == GRUB_TPM2_PROTECTOR_MODE_UNSET)
    return grub_error (GRUB_ERR_INVALID_COMMAND,
		       N_("Cannot use TPM2 key protector without initializing "
			  "it, call tpm2_protector_init first"));

  if (key == NULL || key_size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  return grub_tpm2_protector_recover (&grub_tpm2_protector_ctx, key, key_size);
}

static grub_err_t
grub_tpm2_protector_check_args (struct grub_tpm2_protector_context *ctx)
{
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_UNSET)
    ctx->mode = GRUB_TPM2_PROTECTOR_MODE_SRK;

  /* Checks for SRK mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->keyfile == NULL
      && ctx->tpm2key == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In SRK mode, a key file must be specified: "
			  "--tpm2key/-T or --keyfile/-k"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->keyfile
      && ctx->tpm2key)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In SRK mode, please specify a key file with "
			  "only --tpm2key/-T or --keyfile/-k"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->nv)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In SRK mode, an NV Index cannot be specified"));

  /* Checks for NV mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->nv == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In NV Index mode, an NV Index must be specified: "
			   "--nvindex or -n"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV &&
      (ctx->tpm2key || ctx->keyfile))
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In NV Index mode, a keyfile cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->srk)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In NV Index mode, an SRK cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->asymmetric)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("In NV Index mode, an asymmetric key type cannot be "
			  "specified"));

  /* Defaults assignment */
  if (ctx->bank == TPM_ALG_ERROR)
    ctx->bank = TPM_ALG_SHA256;

  if (ctx->pcr_count == 0)
    {
      ctx->pcrs[0] = 7;
      ctx->pcr_count = 1;
    }

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK)
    {
      if (!ctx->asymmetric)
        {
	  ctx->asymmetric = TPM_ALG_RSA;
	  ctx->rsa_bits = 2048;
        }
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_parse_file (const char *value, const char **file)
{
  if (grub_strlen (value) == 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *file = grub_strdup (value);
  if (*file == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("No memory to duplicate file path"));

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_parse_mode (const char *value,
				grub_tpm2_protector_mode_t *mode)
{
  if (grub_strcmp (value, "srk") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_SRK;
  else if (grub_strcmp (value, "nv") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_NV;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("Value '%s' is not a valid TPM2 key protector mode"),
		       value);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
				      char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  grub_err_t err;

  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("The TPM2 key protector does not accept any "
			  "non-option arguments (i.e., like -o and/or --option "
			  "only)"));

  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  if (state[OPTION_MODE].set)  /* mode */
    {
      err = grub_tpm2_protector_parse_mode (state[OPTION_MODE].arg,
					    &grub_tpm2_protector_ctx.mode);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_PCRS].set)  /* pcrs */
    {
      err = grub_tpm2_protector_parse_pcrs (state[OPTION_PCRS].arg,
					    grub_tpm2_protector_ctx.pcrs,
					    &grub_tpm2_protector_ctx.pcr_count);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_BANK].set)  /* bank */
    {
      err = grub_tpm2_protector_parse_bank (state[OPTION_BANK].arg,
					    &grub_tpm2_protector_ctx.bank);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_TPM2KEY].set)  /* tpm2key */
    {
      err = grub_tpm2_protector_parse_file (state[OPTION_TPM2KEY].arg,
					    &grub_tpm2_protector_ctx.tpm2key);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_KEYFILE].set)  /* keyfile */
    {
      err = grub_tpm2_protector_parse_file (state[OPTION_KEYFILE].arg,
					    &grub_tpm2_protector_ctx.keyfile);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_SRK].set)  /* srk */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[OPTION_SRK].arg,
						  &grub_tpm2_protector_ctx.srk);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_ASYMMETRIC].set)  /* asymmetric */
    {
      err = grub_tpm2_protector_parse_asymmetric (state[OPTION_ASYMMETRIC].arg,
						  &grub_tpm2_protector_ctx.asymmetric,
						  &grub_tpm2_protector_ctx.rsa_bits,
						  &grub_tpm2_protector_ctx.ecc_curve);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (state[OPTION_NVINDEX].set)  /* nvindex */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[OPTION_NVINDEX].arg,
						  &grub_tpm2_protector_ctx.nv);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  err = grub_tpm2_protector_check_args (&grub_tpm2_protector_ctx);

  /* This command only initializes the protector, so nothing else to do. */

  return err;
}

static grub_err_t
grub_tpm2_protector_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
				       int argc,
				       char **args __attribute__ ((unused)))
{
  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		       N_("tpm2_key_protector_clear accepts no arguments"));

  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  return GRUB_ERR_NONE;
}

static struct grub_key_protector grub_tpm2_key_protector =
  {
    .name = "tpm2",
    .recover_key = grub_tpm2_protector_recover_key
  };

GRUB_MOD_INIT (tpm2)
{
  grub_tpm2_protector_init_cmd =
    grub_register_extcmd ("tpm2_key_protector_init",
			  grub_tpm2_protector_init_cmd_handler, 0,
			  N_("[-m mode] "
			     "[-p pcr_list] "
			     "[-b pcr_bank] "
			     "[-T tpm2_key_file_path] "
			     "[-k sealed_key_file_path] "
			     "[-s srk_handle] "
			     "[-a asymmetric_key_type] "
			     "[-n nv_index]"),
			  N_("Initialize the TPM2 key protector."),
			  grub_tpm2_protector_init_cmd_options);
  grub_tpm2_protector_clear_cmd =
    grub_register_extcmd ("tpm2_key_protector_clear",
			  grub_tpm2_protector_clear_cmd_handler, 0, NULL,
			  N_("Clear the TPM2 key protector if previously initialized."),
			  NULL);
  grub_key_protector_register (&grub_tpm2_key_protector);
}

GRUB_MOD_FINI (tpm2)
{
  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  grub_key_protector_unregister (&grub_tpm2_key_protector);
  grub_unregister_extcmd (grub_tpm2_protector_clear_cmd);
  grub_unregister_extcmd (grub_tpm2_protector_init_cmd);
}
