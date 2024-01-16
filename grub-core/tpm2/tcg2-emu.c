/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024 SUSE LLC
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

#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/mm.h>
#include <grub/tpm2/buffer.h>
#include <grub/tpm2/tcg2.h>
#include <grub/emu/misc.h>

grub_err_t
grub_tcg2_get_max_output_size (grub_size_t *size)
{
  if (size == NULL)
    return GRUB_ERR_BAD_ARGUMENT;

  *size = GRUB_TPM2_BUFFER_CAPACITY;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tcg2_submit_command (grub_size_t input_size, grub_uint8_t *input,
			  grub_size_t output_size, grub_uint8_t *output)
{
  static const grub_size_t header_size = sizeof (grub_uint16_t) +
					 (2 * sizeof(grub_uint32_t));

  if (grub_util_tpm_write (input, input_size) != input_size)
    return GRUB_ERR_BAD_DEVICE;

  if (grub_util_tpm_read (output, output_size) < header_size)
    return GRUB_ERR_BAD_DEVICE;

  return GRUB_ERR_NONE;
}
