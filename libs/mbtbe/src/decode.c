#include <mbt/be/bencode.h>

// libc
#include <ctype.h>
#include <stdlib.h>

#define MBT_INT64_MAX_ULL 9223372036854775807LLU

static inline bool mbt_be_consume(struct mbt_cview *buf, char expected);
static inline bool mbt_be_parse_u64(struct mbt_cview *buf, uint64_t *val,
                                    char end);
static inline bool mbt_be_parse_i64(struct mbt_cview *buf, int64_t *val);
static inline bool mbt_be_parse_str(struct mbt_cview *buf, struct mbt_str *str);
static inline struct mbt_be_node *mbt_be_decode_rec(struct mbt_cview *buf);
static inline struct mbt_be_node *mbt_be_decode_num(struct mbt_cview *buf);
static inline struct mbt_be_node *mbt_be_decode_str(struct mbt_cview *buf);
static inline struct mbt_be_node *mbt_be_decode_list(struct mbt_cview *buf);
static inline struct mbt_be_node *mbt_be_decode_dict(struct mbt_cview *buf);

struct mbt_be_node *mbt_be_decode(struct mbt_cview *buf)
{
    struct mbt_cview copy = *buf;
    struct mbt_be_node *res = mbt_be_decode_rec(&copy);
    if (!res)
        return NULL;
    *buf = copy;
    return res;
}

static inline bool mbt_be_consume(struct mbt_cview *buf, char expected)
{
    if (!buf->size || *buf->data != expected)
        return false;
    *buf = MBT_CVIEW_SUB(*buf, 1);
    return true;
}

static inline bool mbt_be_parse_u64(struct mbt_cview *buf, uint64_t *val,
                                    char end)
{
    uint64_t v = 0;
    if (!buf->size || *buf->data == end
        || (*buf->data == '0' && (buf->size == 1 || buf->data[1] != end)))
        return false;
    for (; !mbt_be_consume(buf, end); *buf = MBT_CVIEW_SUB(*buf, 1))
    {
        if (!buf->size || !isdigit(*buf->data))
            return false;
        if (__builtin_mul_overflow(v, 10, &v))
            return false;
        unsigned char c = *buf->data - '0';
        if (__builtin_add_overflow(v, c, &v))
            return false;
    }
    *val = v;
    return true;
}

static inline bool mbt_be_parse_i64(struct mbt_cview *buf, int64_t *val)
{
    bool neg = mbt_be_consume(buf, '-');
    uint64_t v;
    if (!mbt_be_parse_u64(buf, &v, 'e'))
        return false;
    if ((v == 0 && neg) || v > MBT_INT64_MAX_ULL + (neg ? 1ull : 0ull))
        return false;
    if (v == MBT_INT64_MAX_ULL + 1ull)
        *val = INT64_MIN;
    else if (neg)
        *val = -v;
    else
        *val = v;
    return true;
}

static inline bool mbt_be_parse_str(struct mbt_cview *buf, struct mbt_str *str)
{
    uint64_t len;
    if (!mbt_be_parse_u64(buf, &len, ':'))
        return false;

    if (!mbt_str_pushcv(str, MBT_CVIEW(buf->data, len)))
        return false;

    *buf = MBT_CVIEW_SUB(*buf, len);
    return true;
}

static inline struct mbt_be_node *mbt_be_decode_rec(struct mbt_cview *buf)
{
    if (!buf->size)
        return NULL;
    switch (*buf->data)
    {
    case 'i':
        *buf = MBT_CVIEW_SUB(*buf, 1);
        return mbt_be_decode_num(buf);
    case 'd':
        *buf = MBT_CVIEW_SUB(*buf, 1);
        return mbt_be_decode_dict(buf);
    case 'l':
        *buf = MBT_CVIEW_SUB(*buf, 1);
        return mbt_be_decode_list(buf);
    default:
        return mbt_be_decode_str(buf);
    }
}

static inline struct mbt_be_node *mbt_be_decode_num(struct mbt_cview *buf)
{
    int64_t val;
    if (!mbt_be_parse_i64(buf, &val))
        return NULL;

    return mbt_be_num_init(val);
}

static inline struct mbt_be_node *mbt_be_decode_str(struct mbt_cview *buf)
{
    struct mbt_be_node *bn = mbt_be_str_init(MBT_CVIEW(NULL, 0));
    if (!bn)
        return NULL;

    if (!mbt_be_parse_str(buf, &bn->v.str))
    {
        mbt_be_free(bn);
        return NULL;
    }

    return bn;
}

static inline struct mbt_be_node *mbt_be_decode_list(struct mbt_cview *buf)
{
    struct mbt_be_node *bn = mbt_be_list_init(NULL);
    if (!bn)
        return NULL;
    size_t nb_elements = 0;
    bn->v.list = calloc(1, sizeof(struct mbt_be_node *));
    if (!bn->v.list)
    {
        free(bn);
        return NULL;
    }

    for (; !mbt_be_consume(buf, 'e'); ++nb_elements)
    {
        struct mbt_be_node **ptr = realloc(
            bn->v.list, (nb_elements + 2) * sizeof(struct mbt_be_node *));
        if (!bn->v.list)
        {
            mbt_be_free(bn);
            return NULL;
        }
        bn->v.list = ptr;
        bn->v.list[nb_elements + 1] = NULL;

        bn->v.list[nb_elements] = mbt_be_decode_rec(buf);
        if (!bn->v.list[nb_elements])
        {
            mbt_be_free(bn);
            return NULL;
        }
    }

    bn->v.list[nb_elements] = NULL;
    return bn;
}

static inline struct mbt_be_node *mbt_be_decode_dict(struct mbt_cview *buf)
{
    struct mbt_be_node *bn = mbt_be_dict_init(NULL);
    if (!bn)
        return NULL;

    size_t nb_elements = 0;
    bn->v.dict = calloc(1, sizeof(struct mbt_be_pair *));
    if (!bn->v.dict)
    {
        free(bn);
        return NULL;
    }

    for (; !mbt_be_consume(buf, 'e'); ++nb_elements)
    {
        struct mbt_be_pair **ptr = realloc(
            bn->v.dict, (nb_elements + 2) * sizeof(struct mbt_be_pair *));
        if (!ptr)
        {
            mbt_be_free(bn);
            return NULL;
        }
        bn->v.dict = ptr;
        bn->v.dict[nb_elements + 1] = NULL;

        bn->v.dict[nb_elements] = calloc(1, sizeof(**ptr));
        if (!bn->v.dict[nb_elements])
        {
            mbt_be_free(bn);
            return NULL;
        }

        if (!mbt_be_parse_str(buf, &bn->v.dict[nb_elements]->key))
        {
            mbt_be_free(bn);
            return NULL;
        }

        bn->v.dict[nb_elements]->val = mbt_be_decode_rec(buf);
        if (!bn->v.dict[nb_elements]->val)
        {
            mbt_be_free(bn);
            return NULL;
        }
    }

    return bn;
}
