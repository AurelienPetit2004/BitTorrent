#include <mbt/be/bencode.h>

// libc
#include <stdlib.h>

static inline struct mbt_be_node *mbt_be_init(enum mbt_be_type type);

struct mbt_be_node *mbt_be_dict_init(struct mbt_be_pair **d)
{
    struct mbt_be_node *bn = mbt_be_init(MBT_BE_DICT);
    if (bn)
        bn->v.dict = d;
    return bn;
}

struct mbt_be_node *mbt_be_str_init(struct mbt_cview v)
{
    struct mbt_be_node *bn = mbt_be_init(MBT_BE_STR);
    if (bn)
    {
        mbt_str_ctor(&bn->v.str, v.size);
        mbt_str_pushcv(&bn->v.str, v);
    }
    return bn;
}

struct mbt_be_node *mbt_be_list_init(struct mbt_be_node **l)
{
    struct mbt_be_node *bn = mbt_be_init(MBT_BE_LIST);
    if (bn)
        bn->v.list = l;
    return bn;
}

struct mbt_be_node *mbt_be_num_init(int64_t n)
{
    struct mbt_be_node *bn = mbt_be_init(MBT_BE_NUM);
    if (bn)
        bn->v.nb = n;
    return bn;
}

struct mbt_be_pair *mbt_be_pair_init(struct mbt_cview key,
                                     struct mbt_be_node *node)
{
    struct mbt_be_pair *pair = malloc(sizeof(*pair));
    if (!pair)
        return NULL;
    mbt_str_ctor(&pair->key, key.size);
    mbt_str_pushcv(&pair->key, key);
    pair->val = node;
    return pair;
}

void mbt_be_free(struct mbt_be_node *bn)
{
    if (!bn)
        return;
    switch (bn->type)
    {
    case MBT_BE_NUM:
        break;
    case MBT_BE_STR:
        mbt_str_dtor(&bn->v.str);
        break;
    case MBT_BE_LIST:
        for (size_t i = 0; bn->v.list[i]; ++i)
            mbt_be_free(bn->v.list[i]);
        free(bn->v.list);
        break;
    case MBT_BE_DICT:
        for (size_t i = 0; bn->v.dict[i]; ++i)
        {
            mbt_str_dtor(&bn->v.dict[i]->key);
            mbt_be_free(bn->v.dict[i]->val);
            free(bn->v.dict[i]);
        }
        free(bn->v.dict);
        break;
    }
    free(bn);
}

static inline struct mbt_be_node *mbt_be_init(enum mbt_be_type type)
{
    struct mbt_be_node *bn = calloc(1, sizeof(*bn));
    if (!bn)
        return NULL;
    bn->type = type;
    return bn;
}
