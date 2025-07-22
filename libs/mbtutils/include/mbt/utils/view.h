#ifndef MBT_UTILS_VIEW_H
#define MBT_UTILS_VIEW_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// mbtutils
#include <mbt/utils/utils.h>
// libc
#include <stdbool.h>
#include <stdio.h>

struct mbt_cview
{
    const char *data;
    size_t size;
};

struct mbt_view
{
    char *data;
    size_t size;
};

#define MBT_VIEW(Data, Size)                                                   \
    ((struct mbt_view){                                                        \
        .data = (Data),                                                        \
        .size = (Size),                                                        \
    })

// a "View" here is just any struct with a .data and a .size
#define MBT_VIEW_OF(View)                                                      \
    ((struct mbt_view){                                                        \
        .data = (View).data,                                                   \
        .size = (View).size,                                                   \
    })

#define MBT_VIEW_ARR(Array)                                                    \
    ((struct mbt_view){                                                        \
        .data = (Array),                                                       \
        .size = sizeof((Array)),                                               \
    })

// a "View" here is just any struct with a .data and a .size
#define MBT_VIEW_SUB(View, Offset)                                             \
    ((struct mbt_view){                                                        \
        .data = (View).data + (Offset),                                        \
        .size = (View).size - (Offset),                                        \
    })

#define MBT_CVIEW(Data, Size)                                                  \
    ((struct mbt_cview){                                                       \
        .data = (Data),                                                        \
        .size = (Size),                                                        \
    })

// a "View" here is just any struct with a .data and a .size
#define MBT_CVIEW_OF(View)                                                     \
    ((struct mbt_cview){                                                       \
        .data = (View).data,                                                   \
        .size = (View).size,                                                   \
    })

#define MBT_CVIEW_LIT(Lit)                                                     \
    ((struct mbt_cview){                                                       \
        .data = (Lit),                                                         \
        .size = sizeof((Lit)) - 1,                                             \
    })

#define MBT_CVIEW_ARR(Array)                                                   \
    ((struct mbt_cview){                                                       \
        .data = (Array),                                                       \
        .size = sizeof((Array)),                                               \
    })

// a "View" here is just any struct with a .data and a .size
#define MBT_CVIEW_SUB(View, Offset)                                            \
    ((struct mbt_cview){                                                       \
        .data = (View).data + (Offset),                                        \
        .size = (View).size - (Offset),                                        \
    })

int mbt_cview_cmp(struct mbt_cview lhs, struct mbt_cview rhs);
bool mbt_cview_contains(struct mbt_cview view, char c);
void mbt_cview_fprint(struct mbt_cview view, FILE *stream) MBT_NONNULL(2);

#endif /* !MBT_UTILS_VIEW_H */
