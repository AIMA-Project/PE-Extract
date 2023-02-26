/**
 * @author Drew Wheeler
 * @date 2023-02-26
 */

#ifndef BINMANIP_HPP
#define BINMANIP_HPP

#include <cstdint>

void swap_endian (uint8_t*, unsigned int);

void bitstring_to_word (uint16_t*, uint8_t*);
void bitstring_to_dword (uint32_t*, uint8_t*);

#endif