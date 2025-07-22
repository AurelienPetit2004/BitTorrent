#include <mbt/be/bencode.h>
#include <mbt/be/torrent.h>
#include <mbt/be/torrent_file.h>
#include <mbt/be/torrent_files.h>
#include <mbt/be/torrent_getters.h>
#include <mbt/file/file_handler.h>
#include <mbt/file/struct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct mbt_file **init_dir(size_t nbr_f, struct mbt_torrent *torrent)
{
    struct mbt_file **res = calloc(nbr_f, sizeof(struct mbt_file *));
    if (!res)
        return NULL;
    for (size_t i = 0; i < nbr_f; ++i)
    {
        struct mbt_torrent_file *src_file = torrent->file[i];
        res[i] = calloc(1, sizeof(struct mbt_file));
        if (!res[i])
        {
            for (size_t j = 0; j < i; ++j)
            {
                free(res[j]->name);
                free(res[j]);
            }
            free(res);
            return NULL;
        }
        int ind = 0;
        while (src_file->path[ind] != NULL)
        {
            ind++;
        }
        void *tr = src_file->path[ind - 1];
        char *cpy = tr;
        res[i]->name = calloc(strlen(cpy) + 1, sizeof(char));
        res[i]->name = strcpy(res[i]->name, cpy);
        res[i]->len = src_file->length;
    }
    return res;
}

static struct mbt_file **init_file(struct mbt_torrent *torrent)
{
    struct mbt_file **res = calloc(1, sizeof(struct mbt_file *));
    if (!res)
        return NULL;
    res[0] = calloc(1, sizeof(struct mbt_file));
    res[0]->name = calloc(strlen(torrent->name) + 1, sizeof(char));
    res[0]->name = strcpy(res[0]->name, torrent->name);
    res[0]->len = torrent->file[0]->length;
    return res;
}

static size_t calculate_piece_count(const struct mbt_torrent *torrent)
{
    return torrent->size / 20;
}

static struct mbt_piece **init_pieces(const struct mbt_torrent *torrent,
                                      size_t piece_count)
{
    struct mbt_piece **pieces = calloc(piece_count, sizeof(struct mbt_piece *));
    if (!pieces)
        return NULL;

    for (size_t i = 0; i < piece_count; ++i)
    {
        pieces[i] = calloc(1, sizeof(struct mbt_piece));
        if (!pieces[i])
        {
            for (size_t j = 0; j < i; ++j)
            {
                free(pieces[j]);
            }
            free(pieces);
            return NULL;
        }
        size_t rest = 0;
        if (torrent->piece_length % MBT_BLOCK_SIZE != 0)
        {
            rest = torrent->piece_length % MBT_BLOCK_SIZE;
        }
        pieces[i]->nb_blk = (torrent->piece_length / MBT_BLOCK_SIZE) + rest;
        pieces[i]->st = MBT_PIECE_INVALID;
        pieces[i]->blk_pres = calloc(pieces[i]->nb_blk, sizeof(bool));
        pieces[i]->piece_hash = calloc(20, sizeof(char));
        memcpy(pieces[i]->piece_hash, &torrent->pieces[i * 20], 20);
    }
    return pieces;
}

static struct mbt_file **initialize_files(struct mbt_torrent *torrent,
                                          size_t nbr_file)
{
    if (nbr_file == 1 && !mbt_torrent_is_dir(torrent))
        return init_file(torrent);
    else
        return init_dir(nbr_file, torrent);
}

static unsigned char *init_s_piece(struct mbt_torrent *torrent)
{
    void *tr = torrent->pieces;
    char *cpy_piece = tr;
    char *res = calloc(strlen(cpy_piece) + 1, sizeof(char));
    res = strcpy(res, cpy_piece);

    tr = res;
    unsigned char *fres = tr;
    return fres;
}

static bool *init_isdir(struct mbt_torrent *torrent)
{
    bool *res = calloc(1, sizeof(bool));
    if (mbt_torrent_is_dir(torrent))
        *res = true;
    else
        *res = false;
    return res;
}

struct mbt_file_handler *mbt_file_handler_init(struct mbt_torrent *torrent)
{
    if (!torrent->pieces)
        return NULL;

    struct mbt_file_handler *handler =
        calloc(1, sizeof(struct mbt_file_handler));

    handler->name = calloc(strlen(torrent->name) + 1, sizeof(char));
    handler->name = strcpy(handler->name, torrent->name);
    handler->piece = init_s_piece(torrent);
    handler->is_dir = init_isdir(torrent);

    size_t nbr_file = 0;
    while (torrent->file && torrent->file[nbr_file])
    {
        nbr_file++;
    }

    handler->nbr_files = nbr_file;
    handler->files = initialize_files(torrent, nbr_file);
    if (!handler->files)
    {
        free(handler);
        return NULL;
    }

    size_t piece_count = calculate_piece_count(torrent);
    handler->nbr_pieces = piece_count;
    handler->pieces = init_pieces(torrent, piece_count);
    if (!handler->pieces)
    {
        for (size_t i = 0; i < handler->nbr_files; ++i)
        {
            free(handler->files[i]->name);
            free(handler->files[i]);
        }
        free(handler->files);
        free(handler);
        return NULL;
    }

    for (size_t i = 0; i < handler->nbr_files; ++i)
    {
        handler->total_size += handler->files[i]->len;
    }

    return handler;
}

void mbt_file_handler_free(struct mbt_file_handler *fh)
{
    if (!fh)
    {
        return;
    }
    for (size_t i = 0; i < fh->nbr_pieces; ++i)
    {
        free(fh->pieces[i]->blk_pres);
        free(fh->pieces[i]->piece_data);
        free(fh->pieces[i]->piece_hash);
        free(fh->pieces[i]);
    }
    free(fh->pieces);
    for (size_t i = 0; i < fh->nbr_files; ++i)
    {
        free(fh->files[i]->name);
        free(fh->files[i]);
    }
    free(fh->files);
    free(fh->name);
    free(fh->is_dir);
    free(fh->piece);
    free(fh);
}

size_t mbt_file_handler_get_nb_pieces(struct mbt_file_handler *fh)
{
    return fh->nbr_pieces;
}

size_t mbt_file_handler_get_nb_files(struct mbt_file_handler *fh)
{
    return fh->nbr_files;
}

size_t mbt_file_handler_get_total_size(struct mbt_file_handler *fh)
{
    return fh->total_size;
}

const char *mbt_file_handler_get_pieces_hash(struct mbt_file_handler *fh)
{
    void *p = fh->piece;
    char *res = p;
    return res;
}

struct mbt_cview mbt_file_handler_get_name(struct mbt_file_handler *fh)
{
    struct mbt_cview name = { 0 };
    if (fh->name)
    {
        name.data = fh->name;
        name.size = strlen(fh->name);
    }
    return name;
}
