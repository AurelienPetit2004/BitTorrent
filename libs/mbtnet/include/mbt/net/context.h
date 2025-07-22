#ifndef MBT_NET_CONTEXT_H
#define MBT_NET_CONTEXT_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtbe
#include <mbt/be/torrent.h>

// libc
#include <arpa/inet.h>

// Forward declaration
struct mbt_net_context;
struct mbt_peer;

struct mbt_net_context *mbt_net_context_init(struct mbt_torrent *t,
                                             struct in_addr ip, uint16_t port)
    MBT_NONNULL(1);

void mbt_net_context_free(struct mbt_net_context *ctx);

// getter

struct mbt_peer **mbt_net_context_peers(struct mbt_net_context *ctx)
    MBT_NONNULL(1);

#endif /* !MBT_NET_CONTEXT_H */
