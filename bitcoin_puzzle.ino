/**
 * ESP32 Bitcoin Puzzle Solver (Optimized for Speed)
 * Target: Puzzle 71 (Range: 2^70 to 2^71-1)
 * * Logic:
 * 1. Generate a random starting point within the defined range.
 * 2. Use ECC Point Addition (Q = Q + G) instead of Multiplication for speed.
 * 3. Batch process keys to reduce overhead.
 * 4. Run on both ESP32 cores in parallel.
 */

#include <Arduino.h>
#include <Preferences.h>
#include "mbedtls/ecp.h"      
#include "mbedtls/sha256.h"   

// --- CONFIGURATION ---
const int LED_PIN = 2; 
const int BATCH_SIZE = 100;         // Number of keys per loop before resetting start point
static unsigned long globalTotalKeys = 0;
portMUX_TYPE timerMux = portMUX_INITIALIZER_UNLOCKED;

// The RIPEMD160 hash of the public key we are looking for
const uint8_t TARGET_HASH[20] = {
  0x73, 0x95, 0x42, 0x61, 0x17, 0x36, 0x73, 0x32, 0x76, 0x85, 
  0x65, 0x26, 0x11, 0x86, 0x71, 0x68, 0x61, 0x22, 0x88, 0x33
};

volatile bool found = false;

// --- RIPEMD160 IMPLEMENTATION ---
// Manual implementation as some mbedTLS builds for ESP32 omit RIPEMD160
typedef struct { uint64_t length; uint32_t state[5]; uint32_t curlen; uint8_t buf[64]; } local_ripemd160_ctx;
static const uint32_t R160_K[5] = {0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
static const uint32_t R160_KK[5] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000};
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void local_ripemd160_compress(local_ripemd160_ctx *ctx, const uint8_t *buf) {
    uint32_t aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee, X[16];
    for (int i = 0; i < 16; i++) { X[i] = (uint32_t)buf[i * 4] | ((uint32_t)buf[i * 4 + 1] << 8) | ((uint32_t)buf[i * 4 + 2] << 16) | ((uint32_t)buf[i * 4 + 3] << 24); }
    aa = aaa = ctx->state[0]; bb = bbb = ctx->state[1]; cc = ccc = ctx->state[2]; dd = ddd = ctx->state[3]; ee = eee = ctx->state[4];
    
    // Round Logic: Left side and Right side parallel processing
    int s[16] = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8}; 
    for(int i=0;i<16;i++) { uint32_t T = aa + (bb ^ cc ^ dd) + X[i] + R160_K[0]; T = ROL(T, s[i]) + ee; aa=ee; ee=dd; dd=ROL(cc,10); cc=bb; bb=T; }
    int s2[16] = {7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12}; int idx2[16] = {7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8};
    for(int i=0;i<16;i++) { uint32_t T = aa + (((bb & cc) | (~bb & dd))) + X[idx2[i]] + R160_K[1]; T = ROL(T, s2[i]) + ee; aa=ee; ee=dd; dd=ROL(cc,10); cc=bb; bb=T; }
    int s3[16] = {11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5}; int idx3[16] = {3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12};
    for(int i=0;i<16;i++) { uint32_t T = aa + ((bb | ~cc) ^ dd) + X[idx3[i]] + R160_K[2]; T = ROL(T, s3[i]) + ee; aa=ee; ee=dd; dd=ROL(cc,10); cc=bb; bb=T; }
    int s4[16] = {11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12}; int idx4[16] = {1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2};
    for(int i=0;i<16;i++) { uint32_t T = aa + ((bb & dd) | (cc & ~dd)) + X[idx4[i]] + R160_K[3]; T = ROL(T, s4[i]) + ee; aa=ee; ee=dd; dd=ROL(cc,10); cc=bb; bb=T; }
    int s5[16] = {9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6}; int idx5[16] = {4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    for(int i=0;i<16;i++) { uint32_t T = aa + (bb ^ (cc | ~dd)) + X[idx5[i]] + R160_K[4]; T = ROL(T, s5[i]) + ee; aa=ee; ee=dd; dd=ROL(cc,10); cc=bb; bb=T; }
    
    int sp[16] = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6}; int idxp[16] = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12};
    for(int i=0;i<16;i++) { uint32_t T = aaa + (bbb ^ (ccc | ~ddd)) + X[idxp[i]] + R160_KK[0]; T = ROL(T, sp[i]) + eee; aaa=eee; eee=ddd; ddd=ROL(ccc,10); ccc=bbb; bbb=T; }
    int sp2[16] = {9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11}; int idxp2[16] = {6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2};
    for(int i=0;i<16;i++) { uint32_t T = aaa + ((bbb & ddd) | (ccc & ~ddd)) + X[idxp2[i]] + R160_KK[1]; T = ROL(T, sp2[i]) + eee; aaa=eee; eee=ddd; ddd=ROL(ccc,10); ccc=bbb; bbb=T; }
    int sp3[16] = {9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5}; int idxp3[16] = {15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13};
    for(int i=0;i<16;i++) { uint32_t T = aaa + ((bbb | ~ccc) ^ ddd) + X[idxp3[i]] + R160_KK[2]; T = ROL(T, sp3[i]) + eee; aaa=eee; eee=ddd; ddd=ROL(ccc,10); ccc=bbb; bbb=T; }
    int sp4[16] = {15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8}; int idxp4[16] = {8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14};
    for(int i=0;i<16;i++) { uint32_t T = aaa + ((bbb & ccc) | (~bbb & ddd)) + X[idxp4[i]] + R160_KK[3]; T = ROL(T, sp4[i]) + eee; aaa=eee; eee=ddd; ddd=ROL(ccc,10); ccc=bbb; bbb=T; }
    int sp5[16] = {8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11}; int idxp5[16] = {12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    for(int i=0;i<16;i++) { uint32_t T = aaa + (bbb ^ ccc ^ ddd) + X[idxp5[i]] + R160_KK[4]; T = ROL(T, sp5[i]) + eee; aaa=eee; eee=ddd; ddd=ROL(ccc,10); ccc=bbb; bbb=T; }

    uint32_t tmp = ctx->state[1] + cc + ddd; ctx->state[1] = ctx->state[2] + dd + eee; ctx->state[2] = ctx->state[3] + ee + aaa;
    ctx->state[3] = ctx->state[4] + aa + bbb; ctx->state[4] = ctx->state[0] + bb + ccc; ctx->state[0] = tmp;
}

void local_ripemd160_init(local_ripemd160_ctx *ctx) { ctx->length = 0; ctx->curlen = 0; ctx->state[0] = 0x67452301; ctx->state[1] = 0xefcdab89; ctx->state[2] = 0x98badcfe; ctx->state[3] = 0x10325476; ctx->state[4] = 0xc3d2e1f0; }
void local_ripemd160_update(local_ripemd160_ctx *ctx, const uint8_t *in, size_t inlen) {
    size_t n; if (ctx->curlen > 0) { n = 64 - ctx->curlen; if (inlen < n) { memcpy(ctx->buf + ctx->curlen, in, inlen); ctx->curlen += inlen; return; } memcpy(ctx->buf + ctx->curlen, in, n); local_ripemd160_compress(ctx, ctx->buf); in += n; inlen -= n; ctx->length += 512; ctx->curlen = 0; }
    while (inlen >= 64) { local_ripemd160_compress(ctx, in); in += 64; inlen -= 64; ctx->length += 512; } if (inlen > 0) { memcpy(ctx->buf, in, inlen); ctx->curlen = inlen; }
}
void local_ripemd160_final(local_ripemd160_ctx *ctx, uint8_t *out) {
    ctx->length += ctx->curlen * 8; ctx->buf[ctx->curlen++] = 0x80;
    if (ctx->curlen > 56) { while (ctx->curlen < 64) ctx->buf[ctx->curlen++] = 0; local_ripemd160_compress(ctx, ctx->buf); ctx->curlen = 0; }
    while (ctx->curlen < 56) ctx->buf[ctx->curlen++] = 0;
    for(int i=0; i<8; i++) ctx->buf[56+i] = (uint8_t)(ctx->length >> (i*8));
    local_ripemd160_compress(ctx, ctx->buf);
    for (int i = 0; i < 5; i++) { out[i * 4] = (uint8_t)(ctx->state[i]); out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8); out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16); out[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24); }
}

// --- SOLVER TASK (Runs on each core) ---
void solverTask(void * parameter) {
  int coreId = (int)parameter;
  
  // mbedTLS structures for Elliptic Curve Cryptography
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d, one;

  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&one);

  // Load SECP256K1 curve (Bitcoin standard)
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_mpi_lset(&one, 1);

  uint8_t privKeyBytes[32], pubKeyCompressed[33], shaResult[32], ripeResult[20];
  size_t olen;
  local_ripemd160_ctx ripeCtx;

  while(!found) {
    // 1. Pick a random starting point within the Puzzle 71 range
    // Range 71 starts at 0x400000000000000000
    memset(privKeyBytes, 0, 32);
    uint32_t r1 = esp_random(), r2 = esp_random();
    privKeyBytes[23] = (esp_random() & 0x3F) | 0x40; // Ensure it stays in Puzzle 71 bit range
    memcpy(&privKeyBytes[24], &r1, 4); 
    memcpy(&privKeyBytes[28], &r2, 4);
    
    // Convert bytes to BigInt
    mbedtls_mpi_read_binary(&d, privKeyBytes, 32);
    
    // Initial Point Calculation: Q = d * G (Expensive operation)
    if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL) != 0) continue;

    for (int i = 0; i < BATCH_SIZE; i++) {
        // Step A: Serialize Public Key to Compressed Format (33 bytes)
        mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, pubKeyCompressed, 33);
        
        // Step B: SHA256 Hash (Hardware accelerated on ESP32)
        mbedtls_sha256(pubKeyCompressed, 33, shaResult, 0);
        
        // Step C: RIPEMD160 Hash
        local_ripemd160_init(&ripeCtx);
        local_ripemd160_update(&ripeCtx, shaResult, 32);
        local_ripemd160_final(&ripeCtx, ripeResult);

        // Step D: Compare with Target
        if (memcmp(ripeResult, TARGET_HASH, 20) == 0) {
             found = true;
             char hex[67];
             mbedtls_mpi_write_string(&d, 16, hex, 67, &olen);
             Serial.printf("\n\n!!! WINNER !!! CORE %d FOUND THE KEY: %s\n", coreId, hex);
             break;
        }

        // Step E: Point Addition (Q = Q + G)
        // Instead of doing full multiplication, we just add the Generator point G
        // to move to the next private key. This is much faster.
        if (mbedtls_ecp_muladd(&grp, &Q, &one, &Q, &one, &grp.G) != 0) break;
        mbedtls_mpi_add_mpi(&d, &d, &one);
        
        // Update statistics periodically (every 10 keys)
        if (i % 10 == 0) {
            portENTER_CRITICAL(&timerMux);
            globalTotalKeys += 10;
            portEXIT_CRITICAL(&timerMux);
            vTaskDelay(1); // Small delay to prevent Watchdog Reset (WDT)
        }
        if (found) break;
    }
  }
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  setCpuFrequencyMhz(240); // Set ESP32 to max clock speed
  Serial.println("\n--- ESP32 BITCOIN PUZZLE SOLVER INITIALIZED ---");

  // Create two tasks, one for each core of the ESP32
  xTaskCreatePinnedToCore(solverTask, "SolverCore0", 16384, (void*)0, 2, NULL, 0);
  xTaskCreatePinnedToCore(solverTask, "SolverCore1", 16384, (void*)1, 2, NULL, 1);
}

void loop() {
  static unsigned long lastMillis = 0;
  static unsigned long lastKeys = 0;

  unsigned long now = millis();
  unsigned long timeDiff = now - lastMillis;

  // Print Speed Status every 2 seconds
  if (timeDiff >= 2000) { 
    portENTER_CRITICAL(&timerMux);
    unsigned long currentTotal = globalTotalKeys;
    portEXIT_CRITICAL(&timerMux);

    // Calculate Keys Per Second (K/s)
    float speed = ((float)(currentTotal - lastKeys) / timeDiff) * 1000.0;
    Serial.printf("Status: %.2f Keys/s | Total Keys: %lu | Uptime: %lu s\n", 
                  speed, currentTotal, now / 1000);
    
    lastKeys = currentTotal;
    lastMillis = now;
  }
  delay(100); // Main loop is low priority, solver tasks do the work
}
