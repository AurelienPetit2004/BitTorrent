#include <ctype.h>
#include <mbt/utils/str.h>
#include <mbt/utils/utils.h>
#include <mbt/utils/view.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool mbt_str_ctor(struct mbt_str *str, size_t capacity)
{
    if (capacity == 0)
    {
        str->data = NULL;
        str->capacity = 0;
        str->size = 0;
        return true;
    }
    str->data = calloc(1, capacity + 1);
    str->capacity = capacity;
    str->size = 0;
    if (str->data == NULL)
        return false;
    return true;
}

struct mbt_str *mbt_str_init(size_t capacity)
{
    struct mbt_str *res = calloc(1, sizeof(struct mbt_str));
    bool c = mbt_str_ctor(res, capacity);
    if (c == false)
    {
        free(res);
        return NULL;
    }
    return res;
}

void mbt_str_dtor(struct mbt_str *str)
{
    free(str->data);
    str->data = NULL;
    str->capacity = 0;
    str->size = 0;
}

void mbt_str_free(struct mbt_str *str)
{
    mbt_str_dtor(str);
    free(str);
}

bool mbt_str_pushc(struct mbt_str *str, char c)
{
    if (str->size >= str->capacity)
    {
        str->data = realloc(str->data, str->capacity + 2);
        if (str->data == NULL)
            return false;
        str->data[str->size] = c;
        str->data[str->size + 1] = '\0';
        str->capacity += 1;
        str->size += 1;
        return true;
    }
    str->data[str->size] = c;
    str->size += 1;
    return true;
}

bool mbt_str_pushcv(struct mbt_str *str, struct mbt_cview view)
{
    if (str->size == str->capacity)
    {
        str->data = realloc(str->data, str->capacity + view.size + 1);
        str->capacity += view.size;
        str->data[str->capacity] = '\0';
        if (str->data == NULL)
            return false;
    }
    else if (view.size > (str->capacity - str->size))
    {
        str->data = realloc(str->data, str->size + view.size + 1);
        str->capacity = str->size + view.size;
        str->data[str->capacity] = '\0';
        if (str->data == NULL)
            return false;
    }
    int i = str->size;
    size_t j = 0;
    while (j < view.size)
    {
        str->data[i] = view.data[j];
        i++;
        j++;
    }
    str->size += view.size;
    return true;
}

bool mbt_str_pushcstr(struct mbt_str *str, const char *cstr)
{
    if (cstr == NULL)
        return false;
    struct mbt_cview res;
    res.data = cstr;
    res.size = strlen(cstr);
    return mbt_str_pushcv(str, res);
}

int mbt_cview_cmp(struct mbt_cview lhs, struct mbt_cview rhs)
{
    size_t i = 0;
    while (i < lhs.size && i < rhs.size)
    {
        if (lhs.data[i] < rhs.data[i])
            return -1;
        if (lhs.data[i] > rhs.data[i])
            return 1;
        i++;
    }
    if (i == lhs.size && i == rhs.size)
        return 0;
    if (i == lhs.size)
        return -1;
    return 1;
}

bool mbt_cview_contains(struct mbt_cview view, char c)
{
    size_t i = 0;
    while (i < view.size)
    {
        if (view.data[i] == c)
            return true;
        i++;
    }
    return false;
}

void mbt_cview_fprint(struct mbt_cview view, FILE *stream)
{
    size_t i = 0;
    while (i < view.size)
    {
        if (isprint(view.data[i]) != 0)
        {
            fprintf(stream, "%c", view.data[i]);
        }
        else
        {
            unsigned char c = view.data[i];
            fprintf(stream, "U+00%02X", c);
        }
        i++;
    }
}

/*int main(void)
{
    struct mbt_str str1;
    // str is an uninitialized mbt_str
    // you can only call the ctor on this
    mbt_str_ctor(&str1, 0);
    // str is empty
    mbt_str_pushcstr(&str1, "abc");
    // str contains "abc"
    mbt_str_pushcstr(&str1, "def");
    str1.data[2] = -5;
    // str contains "abcdef"
    mbt_cview_fprint(MBT_CVIEW_OF(str1), stdout);
    // prints "abcdef" to stdout
    mbt_str_dtor(&str1);
    // str is empty

    return 0;
}*/
