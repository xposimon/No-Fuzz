/*
 * @Date: 2021-12-03 21:03:52
 * @LastEditors: zx Zhou
 * @LastEditTime: 2022-03-21 00:49:47
 * @FilePath: /libdft64/tools/hashtest.cpp
 */

#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "sha256.h"

extern "C" {
void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int v) {
  printf("set: %p, %d\n", p, v);
}

void __attribute__((noinline)) __libdft_get_taint(void *p) {
  printf("get: %p\n", p);
}

void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) {
  printf("getval: %lu\n", v);
}
}

// "hello"
unsigned char hello_hashed[] = {
  0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a,
  0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
  0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
};

// ""
unsigned char empty_hashed[] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
  0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

int secret = 0x12345678;

int main (int argc, char *argv[]) {

  unsigned char buf[32] = {0};
  if (argc < 1){
    printf("not enough paras\n");
    return -1;
  }
  
  FILE *f = fopen(argv[1], "rb");
  char input[20];
  fread(input, 1, 20, f);
  fclose(f);
  // printf("%s\n", input);
  sha256_hash(buf, (unsigned char*)input, 15);
  // printf("%s", buf);
  // __libdft_get_taint(&buf);
  // __libdft_getval_taint(buf[0]);
  
  if (input[0] == 'h' && input[1] == 'e' && input[2] == 'l')
      printf("magic check\n");

  if (!strcmp(input, "hello world"))
      printf("strcmp test\n");

  if (memcmp(buf, hello_hashed, 32) == 0)
      printf("memcmp test: hash correctly\n");
  else {
      printf("memcmp test: hash error!\n");
  }
  if (input[0] == 'a'){
    // another bbl
    if (!strcmp(input, "another strcmp!"))
        printf("bbl test: second strcmp!\n");
  }

  if (!strncmp(input, (input+5), 3)){
      printf("strncmp test!\n");
    }

  if (strrchr("hello world", input[0])){
      printf("strrchr test\n");
  }

  if (strrchr(input, 'h')){
      printf("strrchr test2\n");
  }

  if (!strcoll(input, "hello world"))
      printf("strcoll test\n");

  if (*((int*)input) == secret){
      printf("direct int cmp\n");
  } 

  if (*((long long*)input) == 0x1234567890abcdef){
      printf("direct long long cmp\n");

  }
  return 0;
}
