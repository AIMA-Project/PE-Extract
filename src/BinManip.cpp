/**
 * @author Drew Wheeler
 * @date 2023-02-26
 */


#include "BinManip.hpp"

void swap_endian (uint8_t* array, unsigned int array_size)
{
    uint8_t temp = 0x00;
    for (unsigned int i = 0; i < array_size / 2; i++)
    {
        temp = array[i];
        array[i] = array[array_size - (i + 1)];
        array[array_size - (i + 1)] = temp;
    }
}

void bitstring_to_word (uint16_t* word, uint8_t* bitstring)
{
    *word = 0x0000;

    *word += bitstring[0];
    *word = *word << 8;
    *word += bitstring[1];
}

void bitstring_to_dword (uint32_t* dword, uint8_t* bitstring)
{
    *dword = 0x00000000;

    for (unsigned int i = 0; i < 4; i++)
    {
        *dword += bitstring[i];
        if (i != 3)
            *dword = *dword << 8;
    }
}