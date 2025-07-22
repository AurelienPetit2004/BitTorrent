#ifndef STRUCT_H
#define STRUCT_H

#include <mbt/be/torrent.h>
#include <mbt/file/piece.h>
#include <mbt/utils/str.h>

#include "file_handler.h"
#include "piece.h"

struct mbt_file_handler
{
    char *name;
    unsigned char *piece;
    bool *is_dir;
    size_t nbr_files;
    struct mbt_file **files;
    size_t nbr_pieces;
    struct mbt_piece **pieces;
    size_t total_size;
};

struct mbt_piece
{
    size_t nb_blk;
    enum mbt_piece_status st;
    bool *blk_pres;
    char *piece_data;
    char *piece_hash;
};

struct mbt_file
{
    char *name;
    size_t len;
};

#endif /* ! STRUCT_H */
