#ifndef MBT_NET_PEER_H
#define MBT_NET_PEER_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtnet
#include "context.h"

struct mbt_peer;

void mbt_peer_addr(struct mbt_peer *peer, struct sockaddr_in *addr)
    MBT_NONNULL(1, 2);

#endif // !MBT_NET_PEER_H
