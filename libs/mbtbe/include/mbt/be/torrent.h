#ifndef MBT_BE_TORRENT_H
#define MBT_BE_TORRENT_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtbe
#include <mbt/be/bencode.h>
// mbtutils
#include <mbt/utils/view.h>
// libc
#include <stdbool.h>

/**
** @brief Forward declaration of the struct that will contain all the
** information of the torrent
**/
struct mbt_torrent;

/**
** @brief Parse the file at `path` and put all the information inside `torrent`
**
** @param path is the location of the .torrent
** @param torrent is the output of the function, MUST BE allocated before
**
** @return true if success else false
**/
bool mbt_be_parse_torrent_file(const char *path, struct mbt_torrent *torrent)
    MBT_NONNULL(1, 2);

/**
** @brief Create a .torrent file thanks to a file or a dir
**
** @param path is the path to the dir/file
**
** @return true if success else false
**/
bool mbt_be_make_torrent_file(const char *path) MBT_NONNULL(1);

/**
** @brief Initialise a mbt_torrent struct
**
** @return The newly allocated struct, NULL if any error occured
**/
struct mbt_torrent *mbt_torrent_init(void);

/**
** @brief Free the mbt_torrent struct
**/
void mbt_torrent_free(struct mbt_torrent *torrent);

#endif /* !MBT_BE_TORRENT_H */
