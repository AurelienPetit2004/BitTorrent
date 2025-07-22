#ifndef TORRENT_FILE_H
#define TORRENT_FILE_H

struct mbt_torrent_file
{
    int64_t length;
    char **path;
};

struct mbt_torrent
{
    char *announce;
    int64_t date;
    char *creator;
    char *name;
    int64_t piece_length;
    unsigned char *pieces;
    size_t size;
    unsigned char *buffer;
    size_t size_fill;
    struct mbt_torrent_file **file;
    struct mbt_be_node *main_node;
};

#endif /* !TORRENT_FILE_H */
