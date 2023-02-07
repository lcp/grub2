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

#ifndef GRUB_TPM2_INTERNAL_STRUCTS_HEADER
#define GRUB_TPM2_INTERNAL_STRUCTS_HEADER 1

#include <grub/tpm2/internal/types.h>

/* TPMS_TAGGED_PROPERTY Structure */
struct TPMS_TAGGED_PROPERTY
{
  TPM_PT property;
  grub_uint32_t value;
};
typedef struct TPMS_TAGGED_PROPERTY TPMS_TAGGED_PROPERTY;

/* TPML_TAGGED_TPM_PROPERTY Structure */
struct TPML_TAGGED_TPM_PROPERTY
{
  grub_uint32_t count;
  TPMS_TAGGED_PROPERTY tpmProperty[TPM_MAX_TPM_PROPERTIES];
};
typedef struct TPML_TAGGED_TPM_PROPERTY TPML_TAGGED_TPM_PROPERTY;

/* TPMU_CAPABILITIES Structure */
union TPMU_CAPABILITIES
{
  TPML_TAGGED_TPM_PROPERTY tpmProperties;
};
typedef union TPMU_CAPABILITIES TPMU_CAPABILITIES;

/* TPMS_CAPABILITY_DATA Structure */
struct TPMS_CAPABILITY_DATA
{
  TPM_CAP capability;
  TPMU_CAPABILITIES data;
};
typedef struct TPMS_CAPABILITY_DATA TPMS_CAPABILITY_DATA;

/* TPMS_PCR_SELECT Structure */
struct TPMS_PCR_SELECT
{
  grub_uint8_t sizeOfSelect;
  grub_uint8_t pcrSelect[TPM_PCR_SELECT_MAX];
};
typedef struct TPMS_PCR_SELECT TPMS_PCR_SELECT;

/* TPMS_PCR_SELECTION Structure */
struct TPMS_PCR_SELECTION
{
  TPMI_ALG_HASH hash;
  grub_uint8_t sizeOfSelect;
  grub_uint8_t pcrSelect[TPM_PCR_SELECT_MAX];
};
typedef struct TPMS_PCR_SELECTION TPMS_PCR_SELECTION;

static inline void TPMS_PCR_SELECTION_SelectPCR(TPMS_PCR_SELECTION* self, grub_uint32_t n)
{
  self->pcrSelect[(n / 8)] |= (1 << (n % 8));
}

/* TPML_PCR_SELECTION Structure */
struct TPML_PCR_SELECTION
{
  grub_uint32_t count;
  TPMS_PCR_SELECTION pcrSelections[TPM_NUM_PCR_BANKS];
};
typedef struct TPML_PCR_SELECTION TPML_PCR_SELECTION;

/* TPMU_HA Structure */
union TPMU_HA
{
  grub_uint8_t sha1[TPM_SHA1_DIGEST_SIZE];
  grub_uint8_t sha256[TPM_SHA256_DIGEST_SIZE];
  grub_uint8_t sha384[TPM_SHA384_DIGEST_SIZE];
  grub_uint8_t sha512[TPM_SHA512_DIGEST_SIZE];
  grub_uint8_t sm3_256[TPM_SM3_256_DIGEST_SIZE];
};
typedef union TPMU_HA TPMU_HA;

/* TPM2B Structure */
struct TPM2B
{
  grub_uint16_t size;
  grub_uint8_t buffer[1];
};
typedef struct TPM2B TPM2B;

/* TPM2B_DIGEST Structure */
struct TPM2B_DIGEST
{
  grub_uint16_t size;
  grub_uint8_t buffer[sizeof(TPMU_HA)];
};
typedef struct TPM2B_DIGEST TPM2B_DIGEST;

/* TPML_DIGEST Structure */
struct TPML_DIGEST
{
  grub_uint32_t count;
  TPM2B_DIGEST digests[8];
};
typedef struct TPML_DIGEST TPML_DIGEST;

/* TPM2B_NONCE Type */
typedef TPM2B_DIGEST TPM2B_NONCE;

/* TPMA_SESSION Structure */
struct TPMA_SESSION
{
  unsigned int continueSession:1;
  unsigned int auditExclusive:1;
  unsigned int auditReset:1;
  unsigned int reserved1:2;
  unsigned int decrypt:1;
  unsigned int encrypt:1;
  unsigned int audit:1;
  unsigned int reserved:24;
};
typedef struct TPMA_SESSION TPMA_SESSION;

/* TPM2B_AUTH Type */
typedef TPM2B_DIGEST TPM2B_AUTH;

/* TPMS_AUTH_COMMAND Structure */
struct TPMS_AUTH_COMMAND
{
  TPMI_SH_AUTH_SESSION sessionHandle;
  TPM2B_NONCE nonce;
  TPMA_SESSION sessionAttributes;
  TPM2B_AUTH hmac;
};
typedef struct TPMS_AUTH_COMMAND TPMS_AUTH_COMMAND;

/* TPMS_AUTH_RESPONSE Structure */
struct TPMS_AUTH_RESPONSE
{
  TPM2B_NONCE nonce;
  TPMA_SESSION sessionAttributes;
  TPM2B_AUTH hmac;
};
typedef struct TPMS_AUTH_RESPONSE TPMS_AUTH_RESPONSE;

/* TPM2B_SENSITIVE_DATA Structure */
struct TPM2B_SENSITIVE_DATA
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_SYM_DATA];
};
typedef struct TPM2B_SENSITIVE_DATA TPM2B_SENSITIVE_DATA;

/* TPMS_SENSITIVE_CREATE Structure */
struct TPMS_SENSITIVE_CREATE
{
  TPM2B_AUTH userAuth;
  TPM2B_SENSITIVE_DATA data;
};
typedef struct TPMS_SENSITIVE_CREATE TPMS_SENSITIVE_CREATE;

/* TPM2B_SENSITIVE_CREATE Structure */
struct TPM2B_SENSITIVE_CREATE
{
  grub_uint16_t size;
  TPMS_SENSITIVE_CREATE sensitive;
};
typedef struct TPM2B_SENSITIVE_CREATE TPM2B_SENSITIVE_CREATE;

/* TPMA_OBJECT Structure */
struct TPMA_OBJECT
{
  unsigned int reserved1:1;
  unsigned int fixedTPM:1;
  unsigned int stClear:1;
  unsigned int reserved2:1;
  unsigned int fixedParent:1;
  unsigned int sensitiveDataOrigin:1;
  unsigned int userWithAuth:1;
  unsigned int adminWithPolicy:1;
  unsigned int reserved3:2;
  unsigned int noDA:1;
  unsigned int encryptedDuplication:1;
  unsigned int reserved4:4;
  unsigned int restricted:1;
  unsigned int decrypt:1;
  unsigned int sign:1;
  unsigned int reserved5:13;
};
typedef struct TPMA_OBJECT TPMA_OBJECT;

/* TPMS_SCHEME_HASH Structure */
struct TPMS_SCHEME_HASH
{
  TPMI_ALG_HASH hashAlg;
};
typedef struct TPMS_SCHEME_HASH TPMS_SCHEME_HASH;

/* TPMS_SCHEME_HASH Types */
typedef TPMS_SCHEME_HASH TPMS_KEY_SCHEME_ECDH;
typedef TPMS_SCHEME_HASH TPMS_KEY_SCHEME_ECMQV;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_RSASSA;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_RSAPSS;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_ECDSA;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_ECDAA;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_SM2;
typedef TPMS_SCHEME_HASH TPMS_SIG_SCHEME_ECSCHNORR;
typedef TPMS_SCHEME_HASH TPMS_ENC_SCHEME_RSAES;
typedef TPMS_SCHEME_HASH TPMS_ENC_SCHEME_OAEP;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF2;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_MGF1;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF1_SP800_56A;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF2;
typedef TPMS_SCHEME_HASH TPMS_SCHEME_KDF1_SP800_108;

/* TPMS_SCHEME_HMAC Type */
typedef TPMS_SCHEME_HASH TPMS_SCHEME_HMAC;

/* TPMS_SCHEME_XOR Structure */
struct TPMS_SCHEME_XOR
{
  TPMI_ALG_HASH hashAlg;
  TPMI_ALG_KDF kdf;
};
typedef struct TPMS_SCHEME_XOR TPMS_SCHEME_XOR;

/* TPMU_SCHEME_KEYEDHASH Union */
union TPMU_SCHEME_KEYEDHASH
{
  TPMS_SCHEME_HMAC hmac;
  TPMS_SCHEME_XOR exclusiveOr;
};
typedef union TPMU_SCHEME_KEYEDHASH TPMU_SCHEME_KEYEDHASH;

/* TPMT_KEYEDHASH_SCHEME Structure */
struct TPMT_KEYEDHASH_SCHEME
{
  TPMI_ALG_KEYEDHASH_SCHEME scheme;
  TPMU_SCHEME_KEYEDHASH details;
};
typedef struct TPMT_KEYEDHASH_SCHEME TPMT_KEYEDHASH_SCHEME;

/* TPMS_KEYEDHASH_PARMS Structure */
struct TPMS_KEYEDHASH_PARMS
{
  TPMT_KEYEDHASH_SCHEME scheme;
};
typedef struct TPMS_KEYEDHASH_PARMS TPMS_KEYEDHASH_PARMS;

/* TPMU_SYM_KEY_BITS Union */
union TPMU_SYM_KEY_BITS
{
  TPM_KEY_BITS aes;
  TPM_KEY_BITS exclusiveOr;
  TPM_KEY_BITS sm4;
  TPM_KEY_BITS camellia;
};
typedef union TPMU_SYM_KEY_BITS TPMU_SYM_KEY_BITS;

/* TPMU_SYM_MODE Union */
union TPMU_SYM_MODE
{
  TPMI_ALG_SYM_MODE aes;
  TPMI_ALG_SYM_MODE sm4;
  TPMI_ALG_SYM_MODE camellia;
  TPMI_ALG_SYM_MODE sym;
};
typedef union TPMU_SYM_MODE TPMU_SYM_MODE;

/* TPMT_SYM_DEF_OBJECT Structure */
struct TPMT_SYM_DEF_OBJECT
{
  TPMI_ALG_SYM_OBJECT algorithm;
  TPMU_SYM_KEY_BITS keyBits;
  TPMU_SYM_MODE mode;
};
typedef struct TPMT_SYM_DEF_OBJECT TPMT_SYM_DEF_OBJECT;

/* TPMS_SYMCIPHER_PARMS Structure */
struct TPMS_SYMCIPHER_PARMS
{
  TPMT_SYM_DEF_OBJECT sym;
};
typedef struct TPMS_SYMCIPHER_PARMS TPMS_SYMCIPHER_PARMS;

/* TPMU_ASYM_SCHEME Union */
union TPMU_ASYM_SCHEME
{
  TPMS_KEY_SCHEME_ECDH ecdh;
  TPMS_KEY_SCHEME_ECMQV ecmqv;
  TPMS_SIG_SCHEME_RSASSA rsassa;
  TPMS_SIG_SCHEME_RSAPSS rsapss;
  TPMS_SIG_SCHEME_ECDSA ecdsa;
  TPMS_SIG_SCHEME_ECDAA ecdaa;
  TPMS_SIG_SCHEME_SM2 sm2;
  TPMS_SIG_SCHEME_ECSCHNORR ecschnorr;
  TPMS_ENC_SCHEME_RSAES rsaes;
  TPMS_ENC_SCHEME_OAEP oaep;
  TPMS_SCHEME_HASH anySig;
  unsigned char padding[4];
};
typedef union TPMU_ASYM_SCHEME TPMU_ASYM_SCHEME;

/* TPMT_RSA_SCHEME Structure */
struct TPMT_RSA_SCHEME
{
  TPMI_ALG_RSA_SCHEME scheme;
  TPMU_ASYM_SCHEME details;
};
typedef struct TPMT_RSA_SCHEME TPMT_RSA_SCHEME;

/* TPMS_RSA_PARMS Structure */
struct TPMS_RSA_PARMS
{
  TPMT_SYM_DEF_OBJECT symmetric;
  TPMT_RSA_SCHEME scheme;
  TPM_KEY_BITS keyBits;
  grub_uint32_t exponent;
};
typedef struct TPMS_RSA_PARMS TPMS_RSA_PARMS;

/* TPMT_ECC_SCHEME Structure */
struct TPMT_ECC_SCHEME
{
  TPMI_ALG_ECC_SCHEME scheme;
  TPMU_ASYM_SCHEME details;
};
typedef struct TPMT_ECC_SCHEME TPMT_ECC_SCHEME;

/* TPMU_KDF_SCHEME Union */
union TPMU_KDF_SCHEME
{
  TPMS_SCHEME_MGF1 mgf1;
  TPMS_SCHEME_KDF1_SP800_56A kdf1_sp800_56a;
  TPMS_SCHEME_KDF2 kdf2;
  TPMS_SCHEME_KDF1_SP800_108 kdf1_sp800_108;
};
typedef union TPMU_KDF_SCHEME TPMU_KDF_SCHEME;

/* TPMT_KDF_SCHEME Structure */
struct TPMT_KDF_SCHEME
{
  TPMI_ALG_KDF scheme;
  TPMU_KDF_SCHEME details;
};
typedef struct TPMT_KDF_SCHEME TPMT_KDF_SCHEME;

/* TPMS_ECC_PARMS Structure */
struct TPMS_ECC_PARMS
{
  TPMT_SYM_DEF_OBJECT symmetric;
  TPMT_ECC_SCHEME scheme;
  TPMI_ECC_CURVE curveID;
  TPMT_KDF_SCHEME kdf;
};
typedef struct TPMS_ECC_PARMS TPMS_ECC_PARMS;

/* TPMT_ASYM_SCHEME Structure */
struct TPMT_ASYM_SCHEME
{
  TPMI_ALG_ASYM_SCHEME scheme;
  TPMU_ASYM_SCHEME details;
};
typedef struct TPMT_ASYM_SCHEME TPMT_ASYM_SCHEME;

/* TPMS_ASYM_PARMS Structure */
struct TPMS_ASYM_PARMS
{
  TPMT_SYM_DEF_OBJECT symmetric;
  TPMT_ASYM_SCHEME scheme;
};
typedef struct TPMS_ASYM_PARMS TPMS_ASYM_PARMS;

/* TPMU_PUBLIC_PARMS Union */
union TPMU_PUBLIC_PARMS
{
  TPMS_KEYEDHASH_PARMS keyedHashDetail;
  TPMS_SYMCIPHER_PARMS symDetail;
  TPMS_RSA_PARMS rsaDetail;
  TPMS_ECC_PARMS eccDetail;
  TPMS_ASYM_PARMS asymDetail;
};
typedef union TPMU_PUBLIC_PARMS TPMU_PUBLIC_PARMS;

/* TPM2B_PUBLIC_KEY_RSA Structure */
struct TPM2B_PUBLIC_KEY_RSA
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_RSA_KEY_BYTES];
};
typedef struct TPM2B_PUBLIC_KEY_RSA TPM2B_PUBLIC_KEY_RSA;

/* TPM2B_ECC_PARAMETER Structure */
struct TPM2B_ECC_PARAMETER
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_ECC_KEY_BYTES];
};
typedef struct TPM2B_ECC_PARAMETER TPM2B_ECC_PARAMETER;

/* TPMS_ECC_POINT Structure */
struct TPMS_ECC_POINT
{
  TPM2B_ECC_PARAMETER x;
  TPM2B_ECC_PARAMETER y;
};
typedef struct TPMS_ECC_POINT TPMS_ECC_POINT;

/* TPMU_ENCRYPTED_SECRET Union */
union TPMU_ENCRYPTED_SECRET
{
  grub_uint8_t ecc[sizeof(TPMS_ECC_POINT)];
  grub_uint8_t rsa[TPM_MAX_RSA_KEY_BYTES];
  grub_uint8_t symmetric[sizeof(TPM2B_DIGEST)];
  grub_uint8_t keyedHash[sizeof(TPM2B_DIGEST)];
};
typedef union TPMU_ENCRYPTED_SECRET TPMU_ENCRYPTED_SECRET;

/* TPM2B_ENCRYPTED_SECRET Structure */
struct TPM2B_ENCRYPTED_SECRET
{
  grub_uint16_t size;
  grub_uint8_t secret[sizeof(TPMU_ENCRYPTED_SECRET)];
};
typedef struct TPM2B_ENCRYPTED_SECRET TPM2B_ENCRYPTED_SECRET;

/* TPMU_PUBLIC_ID Union */
union TPMU_PUBLIC_ID
{
  TPM2B_DIGEST keyedHash;
  TPM2B_DIGEST sym;
  TPM2B_PUBLIC_KEY_RSA rsa;
  TPMS_ECC_POINT ecc;
};
typedef union TPMU_PUBLIC_ID TPMU_PUBLIC_ID;

/* TPMT_PUBLIC Structure */
struct TPMT_PUBLIC
{
  TPMI_ALG_PUBLIC type;
  TPMI_ALG_HASH nameAlg;
  TPMA_OBJECT objectAttributes;
  TPM2B_DIGEST authPolicy;
  TPMU_PUBLIC_PARMS parameters;
  TPMU_PUBLIC_ID unique;
};
typedef struct TPMT_PUBLIC TPMT_PUBLIC;

/* TPM2B_PUBLIC Structure */
struct TPM2B_PUBLIC
{
  grub_uint16_t size;
  TPMT_PUBLIC publicArea;
};
typedef struct TPM2B_PUBLIC TPM2B_PUBLIC;

/* TPMT_HA Structure */
struct TPMT_HA
{
  TPMI_ALG_HASH hashAlg;
  TPMU_HA digest;
};
typedef struct TPMT_HA TPMT_HA;

/* TPM2B_DATA Structure */
struct TPM2B_DATA
{
  grub_uint16_t size;
  grub_uint8_t buffer[sizeof(TPMT_HA)];
};
typedef struct TPM2B_DATA TPM2B_DATA;

/* TPMA_LOCALITY Structure */
struct TPMA_LOCALITY
{
  unsigned char TPM_LOC_ZERO:1;
  unsigned char TPM_LOC_ONE:1;
  unsigned char TPM_LOC_TWO:1;
  unsigned char TPM_LOC_THREE:1;
  unsigned char TPM_LOC_FOUR:1;
  unsigned char Extended:3;
};
typedef struct TPMA_LOCALITY TPMA_LOCALITY;

/* TPMU_NAME Union */
union TPMU_NAME
{
  TPMT_HA digest;
  TPM_HANDLE handle;
};
typedef union TPMU_NAME TPMU_NAME;

/* TPM2B_NAME Structure */
struct TPM2B_NAME
{
  grub_uint16_t size;
  grub_uint8_t name[sizeof(TPMU_NAME)];
};
typedef struct TPM2B_NAME TPM2B_NAME;

/* TPMS_CREATION_DATA Structure */
struct TPMS_CREATION_DATA
{
  TPML_PCR_SELECTION pcrSelect;
  TPM2B_DIGEST pcrDigest;
  TPMA_LOCALITY locality;
  TPM_ALG_ID parentNameAlg;
  TPM2B_NAME parentName;
  TPM2B_NAME parentQualifiedName;
  TPM2B_DATA outsideInfo;
};
typedef struct TPMS_CREATION_DATA TPMS_CREATION_DATA;

/* TPM2B_CREATION_DATA Structure */
struct TPM2B_CREATION_DATA
{
  grub_uint16_t size;
  TPMS_CREATION_DATA creationData;
};
typedef struct TPM2B_CREATION_DATA TPM2B_CREATION_DATA;

/* TPMT_SYM_DEF Structure */
struct TPMT_SYM_DEF
{
  TPMI_ALG_SYM algorithm;
  TPMU_SYM_KEY_BITS keyBits;
  TPMU_SYM_MODE mode;
};
typedef struct TPMT_SYM_DEF TPMT_SYM_DEF;

/* TPM2B_MAX_BUFFER Structure */
struct TPM2B_MAX_BUFFER
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_DIGEST_BUFFER];
};
typedef struct TPM2B_MAX_BUFFER TPM2B_MAX_BUFFER;

/* TPMT_TK_HASHCHECK Structure */
struct TPMT_TK_HASHCHECK
{
  TPM_ST tag;
  TPMI_RH_HIERARCHY hierarchy;
  TPM2B_DIGEST digest;
};
typedef struct TPMT_TK_HASHCHECK TPMT_TK_HASHCHECK;

/* TPM2B_SYM_KEY Structure */
struct TPM2B_SYM_KEY
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_SYM_KEY_BYTES];
};
typedef struct TPM2B_SYM_KEY TPM2B_SYM_KEY;

/* TPM2B_PRIVATE_KEY_RSA Structure */
struct TPM2B_PRIVATE_KEY_RSA
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_RSA_KEY_BYTES/2];
};
typedef struct TPM2B_PRIVATE_KEY_RSA TPM2B_PRIVATE_KEY_RSA;

/* TPM2B_PRIVATE_VENDOR_SPECIFIC Structure */
struct TPM2B_PRIVATE_VENDOR_SPECIFIC
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_PRIVATE_VENDOR_SPECIFIC_BYTES];
};
typedef struct TPM2B_PRIVATE_VENDOR_SPECIFIC TPM2B_PRIVATE_VENDOR_SPECIFIC;

/* TPM2B_PRIVATE_VENDOR_SPECIFIC Union */
union TPMU_SENSITIVE_COMPOSITE
{
  TPM2B_PRIVATE_KEY_RSA rsa;
  TPM2B_ECC_PARAMETER ecc;
  TPM2B_SENSITIVE_DATA bits;
  TPM2B_SYM_KEY sym;
  TPM2B_PRIVATE_VENDOR_SPECIFIC any;
};
typedef union TPMU_SENSITIVE_COMPOSITE TPMU_SENSITIVE_COMPOSITE;

/* TPMT_SENSITIVE Structure */
struct TPMT_SENSITIVE
{
  TPMI_ALG_PUBLIC sensitiveType;
  TPM2B_AUTH authValue;
  TPM2B_DIGEST seedValue;
  TPMU_SENSITIVE_COMPOSITE sensitive;
};
typedef struct TPMT_SENSITIVE TPMT_SENSITIVE;

/* TPM2B_SENSITIVE Structure */
struct TPM2B_SENSITIVE
{
  grub_uint16_t size;
  TPMT_SENSITIVE sensitiveArea;
};
typedef struct TPM2B_SENSITIVE TPM2B_SENSITIVE;

/* _PRIVATE Structure */
struct _PRIVATE
{
  TPM2B_DIGEST integrityOuter;
  TPM2B_DIGEST integrityInner;
  TPM2B_SENSITIVE sensitive;
};
typedef struct _PRIVATE _PRIVATE;

/* TPM2B_PRIVATE Structure */
struct TPM2B_PRIVATE
{
  grub_uint16_t size;
  grub_uint8_t buffer[sizeof(_PRIVATE)];
};
typedef struct TPM2B_PRIVATE TPM2B_PRIVATE;

/* TPML_DIGEST_VALUES Structure */
struct TPML_DIGEST_VALUES
{
  grub_uint16_t count;
  TPMT_HA digests[TPM_NUM_PCR_BANKS];
};
typedef struct TPML_DIGEST_VALUES TPML_DIGEST_VALUES;

/* TPM2B_MAX_NV_BUFFER Structure */
struct TPM2B_MAX_NV_BUFFER
{
  grub_uint16_t size;
  grub_uint8_t buffer[TPM_MAX_NV_BUFFER_SIZE];
};
typedef struct TPM2B_MAX_NV_BUFFER TPM2B_MAX_NV_BUFFER;

/* TPMS_NV_PUBLIC Structure */
struct TPMS_NV_PUBLIC
{
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    TPMA_NV attributes;
    TPM2B_DIGEST authPolicy;
    grub_uint16_t dataSize;
};
typedef struct TPMS_NV_PUBLIC TPMS_NV_PUBLIC;

/* TPM2B_NV_PUBLIC Structure */
struct TPM2B_NV_PUBLIC
{
    grub_uint16_t size;
    TPMS_NV_PUBLIC nvPublic;
};
typedef struct TPM2B_NV_PUBLIC TPM2B_NV_PUBLIC;

/* TPMT_TK_CREATION Structure */
struct TPMT_TK_CREATION
{
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST digest;
};
typedef struct TPMT_TK_CREATION TPMT_TK_CREATION;

/* TPMS_EMPTY Structure */
struct TPMS_EMPTY {
  grub_uint8_t empty[1]; /* a structure with no member */
};
typedef struct TPMS_EMPTY TPMS_EMPTY;

/* TPMS_SIGNATURE_RSA Structure */
struct TPMS_SIGNATURE_RSA {
  TPMI_ALG_HASH hash;
  TPM2B_PUBLIC_KEY_RSA sig;
};
typedef struct TPMS_SIGNATURE_RSA TPMS_SIGNATURE_RSA;

/* Definition of Types for RSA Signature */
typedef TPMS_SIGNATURE_RSA TPMS_SIGNATURE_RSASSA;
typedef TPMS_SIGNATURE_RSA TPMS_SIGNATURE_RSAPSS;

/* TPMS_SIGNATURE_ECC Structure */
struct TPMS_SIGNATURE_ECC {
  TPMI_ALG_HASH hash;
  TPM2B_ECC_PARAMETER signatureR;
  TPM2B_ECC_PARAMETER signatureS;
};
typedef struct TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECC;

/* Definition of Types for ECC TPMS_SIGNATURE_ECC */
typedef TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECDSA;
typedef TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECDAA;
typedef TPMS_SIGNATURE_ECC TPMS_SIGNATURE_SM2;
typedef TPMS_SIGNATURE_ECC TPMS_SIGNATURE_ECSCHNORR;

/* TPMU_SIGNATURE Structure */
union TPMU_SIGNATURE {
  TPMS_SIGNATURE_RSASSA rsassa;
  TPMS_SIGNATURE_RSAPSS rsapss;
  TPMS_SIGNATURE_ECDSA ecdsa;
  TPMS_SIGNATURE_ECDAA ecdaa;
  TPMS_SIGNATURE_SM2 sm2;
  TPMS_SIGNATURE_ECSCHNORR ecschnorr;
  TPMT_HA hmac;
  TPMS_SCHEME_HASH any;
  TPMS_EMPTY null;
};
typedef union TPMU_SIGNATURE TPMU_SIGNATURE;

/* TPMT_SIGNATURE Structure */
struct TPMT_SIGNATURE {
  TPMI_ALG_SIG_SCHEME sigAlg;
  TPMU_SIGNATURE signature;
};
typedef struct TPMT_SIGNATURE TPMT_SIGNATURE;

static inline TPMI_ALG_HASH
TPMT_SIGNATURE_get_hash_alg (TPMT_SIGNATURE *sig)
{
  switch (sig->sigAlg)
    {
    case TPM_ALG_RSASSA:
      return sig->signature.rsassa.hash;
    case TPM_ALG_RSAPSS:
      return sig->signature.rsapss.hash;
    case TPM_ALG_ECDSA:
      return sig->signature.ecdsa.hash;
    case TPM_ALG_ECDAA:
      return sig->signature.ecdaa.hash;
    case TPM_ALG_SM2:
      return sig->signature.sm2.hash;
    case TPM_ALG_ECSCHNORR:
      return sig->signature.ecschnorr.hash;
    case TPM_ALG_HMAC:
      return sig->signature.hmac.hashAlg;
    default:
      break;
    }

  return TPM_ALG_NULL;
}

/* TPMT_TK_VERIFIED Structure */
struct TPMT_TK_VERIFIED {
  TPM_ST tag;
  TPMI_RH_HIERARCHY hierarchy;
  TPM2B_DIGEST digest;
};
typedef struct TPMT_TK_VERIFIED TPMT_TK_VERIFIED;

#endif /* ! GRUB_TPM2_INTERNAL_STRUCTS_HEADER */
