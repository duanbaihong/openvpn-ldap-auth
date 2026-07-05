#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "la_tc.h"

int main(void) {
  assert(parse_bandwidth("10Mbps") == 1250000);
  assert(parse_bandwidth("2Mbps") == 250000);
  assert(parse_bandwidth("512Kbps") == 64000);
  assert(parse_bandwidth("100Mbps") == 12500000);
  assert(parse_bandwidth("1Gbps") == 125000000);
  assert(parse_bandwidth("1000bps") == 125);
  assert(parse_bandwidth("10mbps") == 1250000);
  assert(parse_bandwidth(NULL) == 0);
  assert(parse_bandwidth("") == 0);
  assert(parse_bandwidth("1000000") == 0);
  assert(parse_bandwidth("10m") == 0);
  assert(parse_bandwidth("invalid") == 0);
  printf("All parse_bandwidth tests passed.\n");
  return 0;
}
