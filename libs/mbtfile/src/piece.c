#include <mbt/be/bencode.h>
#include <mbt/be/torrent.h>
#include <mbt/be/torrent_file.h>
#include <mbt/be/torrent_files.h>
#include <mbt/be/torrent_getters.h>
#include <mbt/file/file_handler.h>
#include <mbt/file/piece.h>
#include <mbt/file/struct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void mbt_piece_dtor(struct mbt_piece *p)
{
    p->nb_blk = 0;
    free(p->blk_pres);
    free(p->piece_hash);
    free(p->piece_data);
}
