// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


// --- public functions ---

void error_and_exit(const char* message) {
  fprintf(stderr, "%s", message);
  exit(1);
}

void* malloc_and_check(size_t size) {
  void* pointer = malloc(size);
  if (pointer == NULL) {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config) {

  // TODO
  // Validate the header and set configurations based on it
  // Look at unpack-utilities.h to see what the fields of config are
  // Set the is_valid field of config to false if the header is invalid
  // or input_len (length of the input_data) is shorter than expected

  //checks input_len
  size_t curr_len = 4;
  if (input_len < curr_len) {
    config->is_valid = false;
    return;
  }
  
  //checks magic numbers and version
  if (input_data[0] == 0x02 && input_data[1] == 0x13 && input_data[2] == 0x01) {
    config->is_valid = true;
  }
  else {
    config->is_valid = false;
    return;
  }

  //check flags
  uint8_t flags = input_data[3];
  config->is_checksummed = (flags & 0x20) == 0x20;
  config->is_encrypted = (flags & 0x40) == 0x40;
  config->is_compressed = (flags & 0x80) == 0x80;

  //update dict
  if (config->is_compressed) {
    curr_len += 16;
    for (size_t i = 4; i < curr_len; i++) {
        config->dictionary_data[i-4] = input_data[i];
    }
  }

  //update checksum value
  if (config->is_checksummed) {
      curr_len += 2;
      uint16_t cv = input_data[curr_len - 2];
      cv = cv << 8;
      cv += input_data[curr_len - 1];
      config->checksum_value = cv;
  }

  config->header_len = curr_len;
  
}

uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {

  // TODO
  // Calculate a checksum over input_data
  // Return the checksum value
  uint16_t cv = 0;
  for (size_t i = 0; i < input_len; i++) {
    cv += input_data[i];
  }

  return cv;
}

uint16_t lfsr_step(uint16_t oldstate) {

  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state
  //0x6801
  uint16_t bit0 = oldstate;
  uint16_t bit11 = oldstate >> 11;
  uint16_t bit13 = oldstate >> 13;
  uint16_t bit14 = oldstate >> 14;
  uint16_t new_bit = bit0 ^ bit11 ^ bit13 ^ bit14;
  new_bit = new_bit << 15;
  return new_bit + (oldstate >> 1);
  
}

void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {

  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in big-endian order
  // Beware: input_data may be an odd number of bytes
  uint16_t state = lfsr_step(encryption_key);
  for (size_t i = 0; i+1 < input_len; i += 2) {
    uint8_t byte1 = state;
    uint8_t byte2 = state >> 8;
    output_data[i] = byte1 ^ input_data[i];
    output_data[i+1] = byte2 ^ input_data[i+1];
    state = lfsr_step(state);
  }
  if (input_len % 2 != 0) {
    output_data[input_len - 1] = state ^ input_data[input_len - 1];
  }
  
}

size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data) {

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data
  size_t output_idx = 0;
  for (size_t i = 0; i < input_len; i++) {
    if (input_data[i] == 0x07 && i != input_len - 1) {
        i++;
        if (input_data[i] == 0x00) {
            output_data[output_idx] = 0x07;
            output_idx++;
        }
        else {
            uint8_t count = input_data[i] >> 4;
            uint8_t byte = input_data[i] & 0x0F;
            for (size_t j = 0; j < count; j++) {
                output_data[output_idx+j] = dictionary_data[byte];
            }
            output_idx += count;
        }
    }
    else {
        output_data[output_idx] = input_data[i];
        output_idx++;
    }
  }

  return output_idx;
}

