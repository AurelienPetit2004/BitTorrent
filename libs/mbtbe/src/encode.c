#include <mbt/be/bencode.h>

// libc
#include <inttypes.h>
#include <stdio.h>

static inline bool mbt_be_encode_rec(struct mbt_be_node *bn,
                                     struct mbt_str *str);

struct mbt_str mbt_be_encode(struct mbt_be_node *node)
{
    struct mbt_str str;
    mbt_str_ctor(&str, 0);
    if (!mbt_be_encode_rec(node, &str))
        mbt_str_dtor(&str);
    return str;
}

static inline bool mbt_be_encode_rec(struct mbt_be_node *bn,
                                     struct mbt_str *str)
{
    static char buf[16] = "i";
    switch (bn->type)
    {
    case MBT_BE_NUM:
        snprintf(buf + 1, sizeof(buf) - 1, "%" PRIi64, bn->v.nb);
        return mbt_str_pushcstr(str, buf) && mbt_str_pushc(str, 'e');
    case MBT_BE_STR:
        snprintf(buf + 1, sizeof(buf) - 1, "%zu", bn->v.str.size);
        return mbt_str_pushcstr(str, buf + 1) && mbt_str_pushc(str, ':')
            && mbt_str_pushcv(str, MBT_CVIEW_OF(bn->v.str));
    case MBT_BE_LIST:
        if (!mbt_str_pushc(str, 'l'))
            return false;
        for (size_t i = 0; bn->v.list[i]; ++i)
            if (!mbt_be_encode_rec(bn->v.list[i], str))
                return false;
        return mbt_str_pushc(str, 'e');
    case MBT_BE_DICT:
        if (!mbt_str_pushc(str, 'd'))
            return false;
        for (size_t i = 0; bn->v.list[i]; ++i)
        {
            struct mbt_be_pair *p = bn->v.dict[i];
            snprintf(buf + 1, sizeof(buf) - 1, "%zu", p->key.size);
            if (!mbt_str_pushcstr(str, buf + 1) || !mbt_str_pushc(str, ':')
                || !mbt_str_pushcv(str, MBT_CVIEW_OF(p->key))
                || !mbt_be_encode_rec(p->val, str))
                return false;
        }
        return mbt_str_pushc(str, 'e');
    };
    __builtin_unreachable();
}
