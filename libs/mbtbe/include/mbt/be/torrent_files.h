#ifndef MBT_BE_TORRENT_FILES_H
#define MBT_BE_TORRENT_FILES_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtutils
#include <mbt/utils/str.h>

/**
** @brief Forward declaration of the struct that will contain all the
** information of a file inside the field info.files
**/
struct mbt_torrent_file;

/**
** @brief Get the file.path[`idx`] of `file`
**/
struct mbt_cview mbt_torrent_file_path_get(const struct mbt_torrent_file *file,
                                           size_t idx) MBT_NONNULL(1);

/**
** @brief Get the size of the path list in `file`
**/
size_t mbt_torrent_file_path_size(const struct mbt_torrent_file *file)
    MBT_NONNULL(1);

/**
** @brief Get the length of the file
**/
size_t mbt_torrent_file_length(const struct mbt_torrent_file *file)
    MBT_NONNULL(1);

#endif // !MBT_BE_TORRENT_FILES_H
