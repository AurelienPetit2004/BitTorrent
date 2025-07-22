#include <dirent.h>
#include <inttypes.h>
#include <mbt/be/bencode.h>
#include <mbt/be/torrent.h>
#include <mbt/be/torrent_file.h>
#include <mbt/be/torrent_files.h>
#include <mbt/be/torrent_getters.h>
#include <mbt/utils/str.h>
#include <mbt/utils/utils.h>
#include <mbt/utils/view.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static void ustrcat_bis(unsigned char *dest, unsigned char *src, size_t len,
                        size_t s)
{
    size_t i = 0;
    while (i < len)
        i = i + 1;
    size_t j = 0;
    while (j < s)
    {
        dest[i] = src[j];
        j = j + 1;
        i = i + 1;
    }
}

struct mbt_cview mbt_torrent_announce(const struct mbt_torrent *torrent)
{
    struct mbt_cview c1;
    c1.data = torrent->announce;
    c1.size = strlen(torrent->announce);
    return c1;
}

struct mbt_cview mbt_torrent_file_path_get(const struct mbt_torrent_file *file,
                                           size_t idx)
{
    struct mbt_cview res;
    res.data = NULL;
    res.size = 0;
    size_t i = 0;
    if (file->path != NULL)
    {
        while (file->path[i] != NULL)
        {
            if (i == idx)
            {
                res.data = file->path[i];
                res.size = strlen(file->path[i]);
                return res;
            }
            i = i + 1;
        }
    }
    return res;
}

size_t mbt_torrent_file_path_size(const struct mbt_torrent_file *file)
{
    size_t res = 0;
    if (file->path != NULL)
    {
        while (file->path[res] != NULL)
            res = res + 1;
    }
    return res;
}

size_t mbt_torrent_file_length(const struct mbt_torrent_file *file)
{
    return file->length;
}

static bool aux_fill_dir(struct mbt_be_node *node, struct mbt_torrent *torrent)
{
    size_t i = 0;
    while (node->v.list[i] != NULL)
    {
        torrent->file =
            realloc(torrent->file, sizeof(struct mbt_torrent_file *) * (i + 2));
        if (torrent->file == NULL)
            return false;
        torrent->file[i + 1] = NULL;
        torrent->file[i] = calloc(1, sizeof(struct mbt_torrent_file));
        if (torrent->file[i] == NULL)
            return false;
        struct mbt_be_node *sub = node->v.list[i];
        torrent->file[i]->length = sub->v.dict[0]->val->v.nb;
        size_t j = 0;
        struct mbt_be_node *l = sub->v.dict[1]->val;
        while (l->v.list[j] != NULL)
        {
            torrent->file[i]->path =
                realloc(torrent->file[i]->path, sizeof(char *) * (j + 2));
            if (torrent->file[i]->path == NULL)
                return false;
            torrent->file[i]->path[j + 1] = NULL;
            torrent->file[i]->path[j] = l->v.list[j]->v.str.data;
            j = j + 1;
        }
        i = i + 1;
    }
    return true;
}

static bool aux_fill_str(struct mbt_be_node *node, struct mbt_torrent *torrent)
{
    torrent->file = calloc(1, sizeof(struct mbt_torrent_file *) * 2);
    if (torrent->file == NULL)
        return false;
    torrent->file[0] = calloc(1, sizeof(struct mbt_torrent_file));
    if (torrent->file[0] == NULL)
        return false;
    torrent->file[1] = NULL;
    size_t i = 0;
    while (node->v.dict[i] != NULL)
    {
        if (strcmp(node->v.dict[i]->key.data, "piece length") == 0)
            torrent->piece_length = node->v.dict[i]->val->v.nb;
        else if (strcmp(node->v.dict[i]->key.data, "name") == 0)
            torrent->name = node->v.dict[i]->val->v.str.data;
        else if (strcmp(node->v.dict[i]->key.data, "pieces") == 0)
        {
            void *p = node->v.dict[i]->val->v.str.data;
            torrent->pieces = p;
        }
        else if (strcmp(node->v.dict[i]->key.data, "length") == 0)
            torrent->file[0]->length = node->v.dict[i]->val->v.nb;
        i = i + 1;
    }
    return true;
}

static bool aux_fill(struct mbt_be_node *node, struct mbt_torrent *torrent)
{
    size_t i = 0;
    while (node->v.dict[i] != NULL)
    {
        if (strcmp(node->v.dict[i]->key.data, "announce") == 0)
            torrent->announce = node->v.dict[i]->val->v.str.data;
        else if (strcmp(node->v.dict[i]->key.data, "created by") == 0)
            torrent->creator = node->v.dict[i]->val->v.str.data;
        else if (strcmp(node->v.dict[i]->key.data, "creation date") == 0)
            torrent->date = node->v.dict[i]->val->v.nb;
        else if (strcmp(node->v.dict[i]->key.data, "info") == 0)
        {
            struct mbt_be_node *t = node->v.dict[i]->val;
            if (strcmp(t->v.dict[0]->key.data, "length") == 0)
                return aux_fill_str(node->v.dict[i]->val, torrent);
            aux_fill_dir(t->v.dict[0]->val, torrent);
            size_t l = 1;
            while (t->v.dict[l] != NULL)
            {
                if (strcmp(t->v.dict[l]->key.data, "piece length") == 0)
                    torrent->piece_length = t->v.dict[l]->val->v.nb;
                else if (strcmp(t->v.dict[l]->key.data, "name") == 0)
                    torrent->name = t->v.dict[l]->val->v.str.data;
                else if (strcmp(t->v.dict[l]->key.data, "pieces") == 0)
                {
                    void *p = t->v.dict[l]->val->v.str.data;
                    torrent->pieces = p;
                }
                l = l + 1;
            }
        }
        i = i + 1;
    }
    return true;
}

/*static void print_torrent(struct mbt_torrent *torrent)
{
    if (torrent != NULL)
    {
        bool file = false;
        printf("announce: %s\n", torrent->announce);
        printf("date: %" PRId64 "\n", torrent->date);
        printf("creator: %s\n", torrent->creator);
        printf("name: %s\n", torrent->name);
        printf("piece length: %" PRId64 "\n", torrent->piece_length);
        printf("pieces: %s\n", torrent->pieces);
        printf("size: %zu\n", torrent->size);
        if (torrent->file[0]->path == NULL)
        {
            file = true;
            printf("info:\n");
        }
        else
            printf("files:\n");
        size_t i = 0;
        while (torrent->file[i] != NULL)
        {
            printf("\tlength: %" PRId64 "\n", torrent->file[i]->length);
            size_t j = 0;
            if (file == false)
            {
                printf("\tpath:\n");
                while (torrent->file[i]->path[j] != NULL)
                {
                    printf("\t\t%s\n", torrent->file[i]->path[j]);
                    j = j + 1;
                }
            }
            i = i + 1;
        }
    }
}*/

static bool aux_fill_size(char *b, int s)
{
    if (b[s] != 'e')
        return false;
    if (b[s - 1] != 'c')
        return false;
    if (b[s - 2] != 'e')
        return false;
    if (b[s - 3] != 'i')
        return false;
    if (b[s - 4] != 'p')
        return false;
    return true;
}

static void fill_size(char *b, int s, struct mbt_torrent *torrent)
{
    while (s >= 0)
    {
        if (b[s] == 's')
        {
            if (aux_fill_size(b, s - 1) == true)
            {
                char bu[262144] = { 0 };
                size_t i = 0;
                s = s + 1;
                while (b[s] != ':')
                {
                    bu[i] = b[s];
                    i = i + 1;
                    s = s + 1;
                }
                torrent->size = atoi(bu);
                return;
            }
        }
        s = s - 1;
    }
}

bool mbt_be_parse_torrent_file(const char *path, struct mbt_torrent *torrent)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return false;
    char buf[1] = { 0 };
    char *b = calloc(1, 1);
    if (b == NULL)
        return false;
    b[0] = '\0';
    size_t s = 1;
    while (fread(buf, 1, 1, f) != 0)
    {
        b[s - 1] = buf[0];
        b = realloc(b, s + 1);
        if (b == NULL)
            return false;
        b[s] = '\0';
        s = s + 1;
    }
    if (fclose(f) == EOF)
        return false;
    struct mbt_cview para;
    fill_size(b, s - 1, torrent);
    para.data = b;
    para.size = s - 1;
    struct mbt_be_node *res = mbt_be_decode(&para);
    if (res == NULL)
    {
        free(b);
        return false;
    }
    torrent->main_node = res;
    bool r = aux_fill(res, torrent);
    free(b);
    return r;
}

static void aux_fill_buf(const char *path, char *buf)
{
    char bu[2048] = { 0 };
    int i = strlen(path) - 1;
    if (path[i] == '/')
        i = i - 1;
    size_t j = 0;
    while (i >= 0)
    {
        if (path[i] == '/')
            break;
        bu[j] = path[i];
        j = j + 1;
        i = i - 1;
    }
    i = strlen(bu) - 1;
    j = 0;
    while (i >= 0)
    {
        buf[j] = bu[i];
        i = i - 1;
        j = j + 1;
    }
}

static void aux_fill_inf(struct mbt_be_pair **inf, struct mbt_torrent *t)
{
    struct mbt_cview v1;
    v1.data = "length";
    v1.size = strlen("length");
    inf[0] = mbt_be_pair_init(v1, mbt_be_num_init(mbt_torrent_length(t)));
    struct mbt_cview v2;
    v2.data = "name";
    v2.size = strlen("name");
    inf[1] = mbt_be_pair_init(v2, mbt_be_str_init(mbt_torrent_name(t)));
    struct mbt_cview v3;
    v3.data = "piece length";
    v3.size = strlen("piece length");
    inf[2] = mbt_be_pair_init(v3, mbt_be_num_init(mbt_torrent_piece_length(t)));
    struct mbt_cview v4;
    v4.data = "pieces";
    v4.size = strlen("pieces");
    inf[3] = mbt_be_pair_init(v4, mbt_be_str_init(mbt_torrent_pieces(t)));
}

static struct mbt_torrent *create_tor(const char *path, char *buf, size_t st)
{
    struct mbt_torrent *t = calloc(1, sizeof(struct mbt_torrent));
    t->announce = "http://localhost:6969/announce";
    t->creator = "Aurelien PETIT, Nabil CHARTOUNI";
    t->name = buf;
    t->piece_length = 262144;
    if (st == 0)
    {
        FILE *f = fopen(path, "r");
        unsigned char bu[262144] = { 0 };
        size_t len = 0;
        size_t s = fread(bu, 1, 262144, f);
        size_t size = 0;
        while (s > 0)
        {
            len = len + s;
            unsigned char *sha = calloc(1, SHA_DIGEST_LENGTH + 1);
            SHA1(bu, s, sha);
            t->pieces = realloc(t->pieces, size + 21);
            t->pieces[size + 20] = '\0';
            ustrcat_bis(t->pieces, sha, size, 20);
            free(sha);
            s = fread(bu, 1, 262144, f);
            size += 20;
            t->size = size;
        }
        t->file = calloc(2, sizeof(struct mbt_torrent_file *));
        t->file[0] = calloc(1, sizeof(struct mbt_torrent_file));
        t->file[0]->length = len;
        fclose(f);
    }
    t->date = difftime(time(NULL), 0);
    return t;
}

static struct mbt_be_node *aux_file(const char *path, char *buf)
{
    struct mbt_torrent *t = create_tor(path, buf, 0);
    struct mbt_be_pair **dict = calloc(1, sizeof(struct mbt_be_pair *) * 5);
    struct mbt_cview v1;
    v1.data = "announce";
    v1.size = strlen("announce");
    struct mbt_cview cv = mbt_torrent_announce(t);
    struct mbt_be_node *no = mbt_be_str_init(cv);
    dict[0] = mbt_be_pair_init(v1, no);
    struct mbt_cview v2;
    v2.data = "created by";
    v2.size = strlen("created by");
    dict[1] = mbt_be_pair_init(v2, mbt_be_str_init(mbt_torrent_created_by(t)));
    struct mbt_cview v3;
    v3.data = "creation date";
    v3.size = strlen("creation date");
    dict[2] =
        mbt_be_pair_init(v3, mbt_be_num_init(mbt_torrent_creation_date(t)));
    struct mbt_be_pair **inf = calloc(1, sizeof(struct mbt_be_pair *) * 5);
    aux_fill_inf(inf, t);
    struct mbt_cview v4;
    v4.data = "info";
    v4.size = strlen("info");
    dict[3] = mbt_be_pair_init(v4, mbt_be_dict_init(inf));
    free(t->pieces);
    mbt_torrent_free(t);
    return mbt_be_dict_init(dict);
}

static struct mbt_be_node **aux_aux_fill_file(char *b)
{
    struct mbt_be_node **li = calloc(1, sizeof(struct mbt_be_node *));
    size_t k = 1;
    size_t j = 0;
    size_t n = 0;
    if (b[j] == '/')
        j = j + 1;
    char bu[8000] = { 0 };
    while (b[j] != '\0')
    {
        if (b[j] == '/')
        {
            li = realloc(li, sizeof(struct mbt_be_node *) * (k + 1));
            li[k] = NULL;
            struct mbt_cview v;
            v.data = bu;
            v.size = 8000;
            li[k - 1] = mbt_be_str_init(v);
            k = k + 1;
            n = 0;
            memset(bu, '\0', 8000);
        }
        else
        {
            bu[n] = b[j];
            n = n + 1;
        }
        j = j + 1;
    }
    li = realloc(li, sizeof(struct mbt_be_node *) * (k + 1));
    li[k] = NULL;
    struct mbt_cview v;
    v.data = bu;
    v.size = 8000;
    li[k - 1] = mbt_be_str_init(v);
    return li;
}

static void aux_fill_file_size(struct mbt_torrent *t, size_t s,
                               unsigned char *buff)
{
    if (t->size_fill + s == 262144)
    {
        ustrcat_bis(t->buffer, buff, t->size_fill, s);
        unsigned char *sha = calloc(1, SHA_DIGEST_LENGTH + 1);
        SHA1(t->buffer, t->size_fill + s, sha);
        t->pieces = realloc(t->pieces, t->size + 20);
        ustrcat_bis(t->pieces, sha, t->size, 20);
        free(sha);
        t->size += 20;
        t->size_fill = 0;
        memset(t->buffer, 0, 262144);
        return;
    }
    size_t size = (t->size_fill + s) % 262144;
    ustrcat_bis(t->buffer, buff, t->size_fill, 262144 - t->size_fill);
    unsigned char *sha = calloc(1, SHA_DIGEST_LENGTH + 1);
    SHA1(t->buffer, 262144, sha);
    t->pieces = realloc(t->pieces, t->size + 20);
    ustrcat_bis(t->pieces, sha, t->size, 20);
    t->size += 20;
    free(sha);
    memset(t->buffer, 0, 262144);
    for (size_t i = 0; i < size; i++)
        t->buffer[i] = buff[(262144 - t->size_fill) + i];
    t->size_fill = size;
}

static void aux_fill_file(char *buf, char *b, struct mbt_be_node ***l,
                          struct mbt_torrent *t)
{
    FILE *f = fopen(buf, "r");
    unsigned char buff[262144] = { 0 };
    size_t s = fread(buff, 1, 262144, f);
    size_t size = 0;
    while (s > 0)
    {
        if (t->size_fill + s >= 262144)
            aux_fill_file_size(t, s, buff);
        else
        {
            ustrcat_bis(t->buffer, buff, t->size_fill, s);
            t->size_fill += s;
        }
        size += s;
        s = fread(buff, 1, 262144, f);
    }
    fclose(f);
    size_t i = 0;
    while ((*l)[i] != NULL)
        i = i + 1;
    *l = realloc(*l, sizeof(struct mbt_be_node *) * (i + 2));
    (*l)[i + 1] = NULL;
    struct mbt_be_pair **dict = calloc(1, sizeof(struct mbt_be_pair *) * 3);
    struct mbt_cview v1;
    v1.data = "length";
    v1.size = strlen("length");
    dict[0] = mbt_be_pair_init(v1, mbt_be_num_init(size));
    struct mbt_be_node **li = aux_aux_fill_file(b);
    v1.data = "path";
    v1.size = strlen("path");
    dict[1] = mbt_be_pair_init(v1, mbt_be_list_init(li));
    (*l)[i] = mbt_be_dict_init(dict);
}

static void aux_aux(char *buf, char *b, size_t k, size_t n1)
{
    while (buf[k] != '\0')
    {
        buf[k] = '\0';
        k = k + 1;
    }
    while (b[n1] != '\0')
    {
        b[n1] = '\0';
        n1 = n1 + 1;
    }
}

static void aux_i(char *buf, size_t *i)
{
    while (buf[*i] != '\0')
        *i = *i + 1;
}

static void aux_n(char *b, size_t *n)
{
    while (b[*n] != '\0')
        *n = *n + 1;
}

static void aux(char *buf, char *b, struct mbt_be_node ***l,
                struct mbt_torrent *t)
{
    DIR *dr = opendir(buf);
    struct dirent *de = readdir(dr);
    size_t i = 0;
    aux_i(buf, &i);
    size_t n = 0;
    aux_n(b, &n);
    while (de != NULL)
    {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
        {
            size_t k = i;
            size_t j = 0;
            size_t n1 = n;
            while (de->d_name[j] != '\0')
            {
                buf[k] = de->d_name[j];
                b[n1] = de->d_name[j];
                k = k + 1;
                j = j + 1;
                n1 = n1 + 1;
            }
            struct stat st;
            lstat(buf, &st);
            if (S_ISDIR(st.st_mode))
            {
                b[n1] = '/';
                buf[k] = '/';
                aux(buf, b, l, t);
            }
            else
                aux_fill_file(buf, b, l, t);
            k = i;
            n1 = n;
            aux_aux(buf, b, k, n1);
        }
        de = readdir(dr);
    }
    closedir(dr);
}

static size_t aux_aux_rec(const char *path, char *buf)
{
    size_t i = 0;
    while (path[i] != '\0')
    {
        buf[i] = path[i];
        i = i + 1;
    }
    if (buf[i - 1] != '/')
    {
        buf[i] = '/';
        i = i + 1;
    }
    return i;
}

static void aux_aux_rec_view(struct mbt_be_pair **inf, struct mbt_be_node **l)
{
    struct mbt_cview v;
    v.data = "files";
    v.size = strlen("files");
    inf[0] = mbt_be_pair_init(v, mbt_be_list_init(l));
}

static void aux_rec(const char *path, struct mbt_be_pair **inf,
                    struct mbt_torrent *t)
{
    DIR *dr = opendir(path);
    struct dirent *de = readdir(dr);
    struct mbt_be_node **l = calloc(1, sizeof(struct mbt_be_node *));
    char buf[8000] = { 0 };
    size_t i = aux_aux_rec(path, buf);
    char b[8000] = { 0 };
    while (de != NULL)
    {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
        {
            size_t k = i;
            size_t j = 0;
            while (de->d_name[j] != '\0')
            {
                buf[k] = de->d_name[j];
                b[j] = de->d_name[j];
                k = k + 1;
                j = j + 1;
            }
            struct stat st;
            lstat(buf, &st);
            if (S_ISDIR(st.st_mode))
            {
                buf[k] = '/';
                b[j] = '/';
                aux(buf, b, &l, t);
            }
            else
                aux_fill_file(buf, b, &l, t);
            k = i;
            j = 0;
            aux_aux(buf, b, k, j);
        }
        de = readdir(dr);
    }
    closedir(dr);
    aux_aux_rec_view(inf, l);
}

static void sha(struct mbt_torrent *t)
{
    if (t->size_fill > 0)
    {
        unsigned char *sha = calloc(1, SHA_DIGEST_LENGTH + 1);
        SHA1(t->buffer, t->size_fill, sha);
        t->pieces = realloc(t->pieces, t->size + 20);
        ustrcat_bis(t->pieces, sha, t->size, 20);
        free(sha);
        t->size_fill = 0;
        t->size += 20;
    }
}

static struct mbt_be_node *aux_aux_dict(struct mbt_torrent *t,
                                        struct mbt_be_pair **inf,
                                        struct mbt_be_pair **dict)
{
    struct mbt_cview v6;
    v6.data = "pieces";
    v6.size = strlen("pieces");
    inf[3] = mbt_be_pair_init(v6, mbt_be_str_init(mbt_torrent_pieces(t)));
    struct mbt_cview v7;
    v7.data = "info";
    v7.size = strlen("info");
    dict[3] = mbt_be_pair_init(v7, mbt_be_dict_init(inf));
    free(t->pieces);
    free(t->buffer);
    mbt_torrent_free(t);
    return mbt_be_dict_init(dict);
}

static struct mbt_be_node *aux_dict(const char *path, char *buf)
{
    struct mbt_torrent *t = create_tor(path, buf, 1);
    struct mbt_be_pair **dict = calloc(1, sizeof(struct mbt_be_pair *) * 5);
    struct mbt_cview v1;
    v1.data = "announce";
    v1.size = strlen("announce");
    struct mbt_cview cv = mbt_torrent_announce(t);
    struct mbt_be_node *no = mbt_be_str_init(cv);
    dict[0] = mbt_be_pair_init(v1, no);
    struct mbt_cview v2;
    v2.data = "created by";
    v2.size = strlen("created by");
    dict[1] = mbt_be_pair_init(v2, mbt_be_str_init(mbt_torrent_created_by(t)));
    struct mbt_cview v3;
    v3.data = "creation date";
    v3.size = strlen("creation date");
    dict[2] =
        mbt_be_pair_init(v3, mbt_be_num_init(mbt_torrent_creation_date(t)));
    struct mbt_be_pair **inf = calloc(1, sizeof(struct mbt_be_pair *) * 5);
    struct mbt_cview v4;
    v4.data = "piece length";
    v4.size = strlen("piece length");
    inf[2] = mbt_be_pair_init(v4, mbt_be_num_init(mbt_torrent_piece_length(t)));
    struct mbt_cview v5;
    v5.data = "name";
    v5.size = strlen("name");
    inf[1] = mbt_be_pair_init(v5, mbt_be_str_init(mbt_torrent_name(t)));
    t->buffer = calloc(1, 262144);
    aux_rec(path, inf, t);
    sha(t);
    return aux_aux_dict(t, inf, dict);
}

bool mbt_be_make_torrent_file(const char *path)
{
    struct stat st;
    if (lstat(path, &st) == -1)
        return false;
    struct mbt_be_node *res = NULL;
    char buf[2048] = { 0 };
    aux_fill_buf(path, buf);
    if (!S_ISDIR(st.st_mode))
    {
        res = aux_file(path, buf);
        if (res == NULL)
            return false;
    }
    else
    {
        res = aux_dict(path, buf);
        if (res == NULL)
            return false;
    }
    struct mbt_str str = mbt_be_encode(res);
    if (str.data == NULL)
        return false;
    char *b = strcat(buf, ".torrent");
    FILE *f = fopen(b, "w");
    if (fwrite(str.data, 1, str.size, f) == 0)
        return false;
    if (fclose(f) == EOF)
        return false;
    mbt_be_free(res);
    free(str.data);
    return true;
}

struct mbt_torrent *mbt_torrent_init(void)
{
    struct mbt_torrent *res = calloc(1, sizeof(struct mbt_torrent));
    if (res == NULL)
        return NULL;
    return res;
}

void mbt_torrent_free(struct mbt_torrent *torrent)
{
    if (torrent != NULL)
    {
        struct mbt_torrent_file **f = torrent->file;
        size_t i = 0;
        if (f != NULL)
        {
            while (f[i] != NULL)
            {
                if (f[i]->path != NULL)
                    free(f[i]->path);
                free(f[i]);
                i = i + 1;
            }
        }
        free(torrent->file);
        mbt_be_free(torrent->main_node);
        free(torrent);
        torrent = NULL;
    }
}
