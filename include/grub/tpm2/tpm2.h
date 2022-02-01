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

#ifndef GRUB_TPM2_TPM2_HEADER
#define GRUB_TPM2_TPM2_HEADER 1

#include <grub/tpm2/internal/types.h>
#include <grub/tpm2/internal/structs.h>
#include <grub/tpm2/internal/functions.h>

/* Defined in: TCG TPM Specification, v1.59, Part 2, Section 10.6.1. */
#define TPM2_PCR_TO_SELECT(x)  ((x) / 8)
#define TPM2_PCR_TO_BIT(x)     (1 << ((x) % 8))

/* Well-Known Windows SRK handle */
#define TPM2_SRK_HANDLE 0x81000001

typedef struct TPM2_SEALED_KEY {
  TPM2B_PUBLIC  public;
  TPM2B_PRIVATE private;
} TPM2_SEALED_KEY;

#endif /* ! GRUB_TPM2_TPM2_HEADER */
