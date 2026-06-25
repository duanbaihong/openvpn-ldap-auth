#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "la_tc.h"

int main(void) {
  /* "10Mbps" → 1,250,000 bytes/s (10,000,000 bits / 8) */
  assert(parse_bandwidth("10Mbps") == 1250000);
  /* "2Mbps" → 250,000 bytes/s */
  assert(parse_bandwidth("2Mbps") == 250000);
  /* "512Kbps" → 64,000 bytes/s */
  assert(parse_bandwidth("512Kbps") == 64000);
  /* "100Mbps" → 12,500,000 bytes/s */
  assert(parse_bandwidth("100Mbps") == 12500000);
  /* "1Gbps" → 125,000,000 bytes/s */
  assert(parse_bandwidth("1Gbps") == 125000000);
  /* 纯数字无单位 → 假设为 bps */
  assert(parse_bandwidth("1000000") == 125000);
  /* NULL → 0 */
  assert(parse_bandwidth(NULL) == 0);
  /* 空字符串 → 0 */
  assert(parse_bandwidth("") == 0);
  /* 无法解析 → 0 */
  assert(parse_bandwidth("invalid") == 0);

  printf("All parse_bandwidth tests passed.\n");
  return 0;
}
