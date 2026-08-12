#ifndef SDP_H
#define SDP_H

#include "bt_defs.h"

/* Returns 0 and writes channel (1..30) on success. */
int sdp_find_hfp_hf_rfcomm_channel(const bt_addr_t *remote, uint8_t *channel);

#endif
