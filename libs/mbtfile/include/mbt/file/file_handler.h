#ifndef MBT_FILE_FILE_HANDLER_H
#define MBT_FILE_FILE_HANDLER_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtutils
#include <mbt/utils/str.h>

// mbtbe
#include <mbt/be/torrent.h>

// mbtfile
#include <mbt/file/piece.h>

#define MBT_BLOCK_SIZE (1 << 14)

// Forward declaration
struct mbt_file_handler;

// Forward declaration
struct mbt_file;

struct mbt_file_handler *mbt_file_handler_init(struct mbt_torrent *torrent)
    MBT_NONNULL(1);

void mbt_file_handler_free(struct mbt_file_handler *fh);

// getters
size_t mbt_file_handler_get_nb_pieces(struct mbt_file_handler *fh)
    MBT_NONNULL(1);
struct mbt_cview mbt_file_handler_get_name(struct mbt_file_handler *fh)
    MBT_NONNULL(1);
size_t mbt_file_handler_get_nb_files(struct mbt_file_handler *fh)
    MBT_NONNULL(1);
size_t mbt_file_handler_get_total_size(struct mbt_file_handler *fh)
    MBT_NONNULL(1);
const char *mbt_file_handler_get_pieces_hash(struct mbt_file_handler *fh)
    MBT_NONNULL(1);

#endif /* !MBT_FILE_FILE_HANDLER_H */
