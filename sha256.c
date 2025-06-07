#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
static const uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Bitwise right rotation function
uint32_t right_rotate(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// Sigma functions for message schedule and hash computation
uint32_t sigma0(uint32_t x) {
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3);
}

uint32_t sigma1(uint32_t x) {
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10);
}

uint32_t big_sigma0(uint32_t x) {
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22);
}

uint32_t big_sigma1(uint32_t x) {
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25);
}

// Choice and Majority functions for compression
uint32_t choice(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// Prepare message schedule
void prepare_message_schedule(uint32_t* W, uint8_t* chunk) {
    // First 16 words are the chunk itself
    for (int t = 0; t < 16; t++) {
        W[t] = (chunk[t*4] << 24) | (chunk[t*4 + 1] << 16) | 
               (chunk[t*4 + 2] << 8) | (chunk[t*4 + 3]);
    }
    
    // Extend to 64 words
    for (int t = 16; t < 64; t++) {
        W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    }
}

// Compression function
void compress_block(uint32_t* hash, uint32_t* W) {
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];

    // Main compression loop
    for (int t = 0; t < 64; t++) {
        uint32_t temp1 = h + big_sigma1(e) + choice(e, f, g) + K[t] + W[t];
        uint32_t temp2 = big_sigma0(a) + majority(a, b, c);
        
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Update hash values
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

// Padding function
void pad_message(uint8_t* message, uint64_t message_len, uint8_t* padded_message, uint64_t* padded_len) {
    // Calculate needed padding
    uint64_t k = (448 - (message_len * 8 + 1)) % 512;
    if (k < 0) k += 512;

    // Copy original message
    memcpy(padded_message, message, message_len);
    
    // Append 1 bit
    padded_message[message_len] = 0x80;
    
    // Append 0 bits
    memset(padded_message + message_len + 1, 0, (k / 8));
    
    // Append original message length as 64-bit big-endian integer
    uint64_t total_bits = message_len * 8;
    for (int i = 0; i < 8; i++) {
        padded_message[message_len + 1 + (k / 8) + i] = (total_bits >> (56 - i * 8)) & 0xFF;
    }

    *padded_len = message_len + 1 + (k / 8) + 8;
}

// Main SHA-256 hash computation
void sha256(uint8_t* message, uint64_t message_len, uint8_t* hash) {
    // Padded message and its length
    uint8_t padded_message[1024];
    uint64_t padded_len;
    
    // Pad the message
    pad_message(message, message_len, padded_message, &padded_len);

    // Initialize hash values
    uint32_t hash_values[8];
    for (int i = 0; i < 8; i++) {
        hash_values[i] = H[i];
    }

    // Process each 512-bit chunk
    for (uint64_t i = 0; i < padded_len; i += 64) {
        // Message schedule
        uint32_t W[64];
        
        // Prepare message schedule
        prepare_message_schedule(W, padded_message + i);
        
        // Compress the block
        compress_block(hash_values, W);
    }

    // Convert hash values to byte array
    for (int i = 0; i < 8; i++) {
        hash[i*4]     = (hash_values[i] >> 24) & 0xFF;
        hash[i*4 + 1] = (hash_values[i] >> 16) & 0xFF;
        hash[i*4 + 2] = (hash_values[i] >> 8)  & 0xFF;
        hash[i*4 + 3] = hash_values[i] & 0xFF;
    }
}

// Function to print hash
void print_hash(uint8_t* hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    // Test the SHA-256 implementation
    char* test_string = "Hello, SHA-256!";
    uint8_t hash[32];
    
    // Compute SHA-256 hash
    sha256((uint8_t*)test_string, strlen(test_string), hash);
    
    // Print the hash
    printf("SHA-256 hash of '%s':\n", test_string);
    print_hash(hash);

    return 0;
}
