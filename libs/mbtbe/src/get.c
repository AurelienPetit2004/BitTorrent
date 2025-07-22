#include <mbt/be/bencode.h>
#include <mbt/be/torrent.h>
#include <mbt/be/torrent_file.h>
#include <mbt/be/torrent_getters.h>
#include <mbt/utils/str.h>
#include <mbt/utils/utils.h>
#include <mbt/utils/view.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mbt_cview mbt_torrent_created_by(const struct mbt_torrent *torrent)
{
    struct mbt_cview c1;
    c1.data = torrent->creator;
    c1.size = strlen(torrent->creator);
    return c1;
}

size_t mbt_torrent_creation_date(const struct mbt_torrent *torrent)
{
    size_t res = torrent->date;
    return res;
}

size_t mbt_torrent_piece_length(const struct mbt_torrent *torrent)
{
    size_t res = torrent->piece_length;
    return res;
}

struct mbt_cview mbt_torrent_name(const struct mbt_torrent *torrent)
{
    struct mbt_cview c1;
    c1.data = torrent->name;
    c1.size = strlen(torrent->name);
    return c1;
}

struct mbt_cview mbt_torrent_pieces(const struct mbt_torrent *torrent)
{
    struct mbt_cview c1;
    void *p = torrent->pieces;
    c1.data = p;
    c1.size = torrent->size;
    return c1;
}

size_t mbt_torrent_length(const struct mbt_torrent *torrent)
{
    if (torrent->file[0]->path == NULL)
        return torrent->file[0]->length;
    size_t res = 0;
    size_t i = 0;
    while (torrent->file[i] != NULL)
    {
        res += torrent->file[i]->length;
        i = i + 1;
    }
    return res;
}

const struct mbt_torrent_file *
mbt_torrent_files_get(const struct mbt_torrent *torrent, size_t idx)
{
    size_t i = 0;
    while (torrent->file[i] != NULL)
    {
        if (i == idx)
            return torrent->file[i];
        i = i + 1;
    }
    return NULL;
}

size_t mbt_torrent_files_size(const struct mbt_torrent *torrent)
{
    size_t i = 0;
    while (torrent->file[i] != NULL)
        i = i + 1;
    return i;
}

bool mbt_torrent_is_dir(const struct mbt_torrent *torrent)
{
    if (torrent->file[0]->path == NULL)
        return false;
    return true;
}

const struct mbt_be_node *mbt_torrent_node(const struct mbt_torrent *torrent)
{
    return torrent->main_node;
}
