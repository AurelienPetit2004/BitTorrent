#ifndef MBT_BE_BENCODE_H
#define MBT_BE_BENCODE_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtstr
#include <mbt/utils/str.h>
// libc
#include <stddef.h>
#include <stdint.h>

enum mbt_be_type
{
    MBT_BE_NUM,
    MBT_BE_STR,
    MBT_BE_LIST,
    MBT_BE_DICT,
};

struct mbt_be_pair
{
    struct mbt_str key;
    struct mbt_be_node *val;
};

struct mbt_be_node
{
    enum mbt_be_type type;
    union mbt_be_value
    {
        int64_t nb;
        struct mbt_str str;
        /* A `NULL` terminated array of `mbt_be_node`. */
        struct mbt_be_node **list;
        /* A `NULL` terminated array of `mbt_be_pair`. */
        struct mbt_be_pair **dict;
    } v;
};

/**
** @brief Decode a buffer and return it as a `be_node`.
**
** @param buf The buffer to decode.
**
** @return On success, the `be_node` corresponding to `buf`, `NULL` on failure.
**         A failure can occur if the size is not correct or if the input is
**         ill-formed, in which case `errno` is set to `EINVAL`, or if an
**         allocation error occurs, in which case `errno` is set to `ENOMEM`.
*/
struct mbt_be_node *mbt_be_decode(struct mbt_cview *buf) MBT_NONNULL(1);

/**
** @brief Encode the content of `node` and return it in the allocated buffer.
**
** @param node The `mbt_be_node` to encode.
**
** @result The allocated buffer filled with the encoded node.
**         Return `NULL` and set `errno` to `ENOMEM` on allocation error.
*/
struct mbt_str mbt_be_encode(struct mbt_be_node *node) MBT_NONNULL(1);

/**
** @brief Allocate and initialize a `mbt_be_node` of type MBT_BE_DICT and set
*the field.
**
** @param d The pairs of the node.
**
** @return the initialized `mbt_be_node`, or NULL in case of error.
*/
struct mbt_be_node *mbt_be_dict_init(struct mbt_be_pair **d);

/**
** @brief Allocate and initialize a `mbt_be_node` of type MBT_BE_STR and set the
*field.
**
** @param v The value of the node.
**
** @return the initialized `mbt_be_node`, or NULL in case of error.
*/
struct mbt_be_node *mbt_be_str_init(struct mbt_cview v);

/**
** @brief Allocate and initialize a `mbt_be_node` of type MBT_BE_LIST and set
*the field.
**
** @param l The value of the node.
**
** @return the initialized `mbt_be_node`, or NULL in case of error.
*/
struct mbt_be_node *mbt_be_list_init(struct mbt_be_node **l);

/**
** @brief Allocate and initialize a `mbt_be_node` of type MBT_BE_NUM and set the
*field.
**
** @param n The value of the node.
**
** @return the initialized `mbt_be_node`, or NULL in case of error.
*/
struct mbt_be_node *mbt_be_num_init(int64_t n);

/**
** @brief Allocate and initialize a `mbt_be_pair` set the fields.
**
** @param key The key of the pair.
** @param node The node of the pair.
**
** @return the initialized `mbt_be_pair`, or NULL in case of error.
*/
struct mbt_be_pair *mbt_be_pair_init(struct mbt_cview key,
                                     struct mbt_be_node *node);

/**
** @brief Free a `mbt_be_node`.
**
** @param node The `mbt_be_node` to free.
*/
void mbt_be_free(struct mbt_be_node *node);

#endif /* !MBT_BE_BENCODE_H */
