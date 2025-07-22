#ifndef MBT_FILE_PIECE_H
#define MBT_FILE_PIECE_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtutils
#include <mbt/utils/str.h>

// libc
#include <stdbool.h>
#include <stddef.h>

struct mbt_file_handler;

struct mbt_piece;

// Enum for pieces status
enum mbt_piece_status
{
    MBT_PIECE_VALID,
    MBT_PIECE_DOWNLOADING,
    MBT_PIECE_INVALID,
};

void mbt_piece_dtor(struct mbt_piece *p);

size_t mbt_piece_get_nb_blocks(struct mbt_file_handler *fh, size_t piece_index)
    MBT_NONNULL(1);

const char *mbt_piece_get_data(struct mbt_file_handler *fh, size_t piece_index)
    MBT_NONNULL(1);

void mbt_piece_set_data(struct mbt_file_handler *fh, size_t piece_index,
                        const char *data, size_t size) MBT_NONNULL(1, 3);

bool mbt_piece_block_is_received(struct mbt_file_handler *fh,
                                 size_t piece_index, size_t block_index)
    MBT_NONNULL(1);

void mbt_piece_block_set_received(struct mbt_file_handler *fh,
                                  size_t piece_index, size_t block_index,
                                  bool received) MBT_NONNULL(1);

bool mbt_compare_hashes(struct mbt_file_handler *fh, size_t piece_index,
                        const char *received_data) MBT_NONNULL(1);

enum mbt_piece_status mbt_piece_check(struct mbt_file_handler *fh,
                                      size_t piece_index) MBT_NONNULL(1);

bool mbt_piece_write(struct mbt_file_handler *fh, size_t piece_index)
    MBT_NONNULL(1);

#endif /* ! MBT_FILE_PIECE_H */
