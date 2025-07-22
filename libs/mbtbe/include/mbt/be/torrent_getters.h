#ifndef MBT_BE_TORRENT_GETTERS_H
#define MBT_BE_TORRENT_GETTERS_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtutils
#include <mbt/utils/str.h>
// libc
#include <stdbool.h>

// Forward decleration
struct mbt_torrent;

///////////////////////////////////////////////////////////////////////////
/// This file has all the getters for the mbt_torrent struct
///////////////////////////////////////////////////////////////////////////

/**
** @brief Get the announce field of the `torrent`
**/
struct mbt_cview mbt_torrent_announce(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

/**
** @brief Get the created_by field of the `torrent`
**/
struct mbt_cview mbt_torrent_created_by(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

/**
** @brief Get the creation_date field of the `torrent`
**/
size_t mbt_torrent_creation_date(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

/**
** @brief Get the info.piece_length field of the `torrent`
**/
size_t mbt_torrent_piece_length(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

/**
** @brief Get the info.name field of the `torrent`
**/
struct mbt_cview mbt_torrent_name(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

/**
** @brief Get the info.pieces field of the `torrent`
**/
struct mbt_cview mbt_torrent_pieces(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

/**
** @brief Get the info.length field of the `torrent`
**/
size_t mbt_torrent_length(const struct mbt_torrent *torrent) MBT_NONNULL(1);

/**
** @brief Get the info.files[`idx`] of the `torrent`
**
** @return NULL if idx is out of bound else the pointer to mbt_torrent_file
**/
const struct mbt_torrent_file *
mbt_torrent_files_get(const struct mbt_torrent *torrent, size_t idx)
    MBT_NONNULL(1);

/**
** @brief Get the numbers of files inside info.files field of the `torrent`
**/
size_t mbt_torrent_files_size(const struct mbt_torrent *torrent) MBT_NONNULL(1);

/**
** @brief Get the type of the `torrent`
**
** @return true if the torrent download a directory else false
**/
bool mbt_torrent_is_dir(const struct mbt_torrent *torrent) MBT_NONNULL(1);

/**
** @brief Get the main mbt_be_node of the `torrent`
**/
const struct mbt_be_node *mbt_torrent_node(const struct mbt_torrent *torrent)
    MBT_NONNULL(1);

#endif // !MBT_BE_TORRENT_GETTERS_H
