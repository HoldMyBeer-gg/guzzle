/*
 * kvstore.c — tiny key/value config record loader
 *
 * Reads a packed binary config format used for embedded device settings.
 * A file is a sequence of records, each:
 *
 *   [u8  key_len]
 *   [key_len bytes  key   ]
 *   [u8  val_len]
 *   [val_len bytes  value ]
 *
 * Keys are treated as C strings (null-terminated on copy); values are
 * stored as raw bytes. The loader walks every record and prints a summary.
 *
 * This is an INTENTIONALLY VULNERABLE fuzzing target for Guzzle. Do not
 * use it for anything real. The bug is documented inline below.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_KEY   32      /* fixed on-stack key buffer size */
#define MAX_RECS  256

typedef struct {
    char     key[MAX_KEY];
    uint8_t *value;
    uint8_t  val_len;
} KvRecord;

/*
 * load_one — decode a single record starting at *p.
 *
 * On success advances *p past the record and fills *rec.
 * Returns 0 on success, -1 when the buffer is exhausted or malformed.
 */
static int load_one(const uint8_t **p, const uint8_t *end, KvRecord *rec)
{
    const uint8_t *cur = *p;

    if (cur + 1 > end) return -1;
    uint8_t key_len = *cur++;

    /* key bytes must actually be present in the buffer */
    if (cur + key_len > end) return -1;

    /* Copy the key into a fixed on-stack buffer and null-terminate.
     *
     * BUG: key_len is attacker-controlled (0..255) but keybuf holds only
     * MAX_KEY (32) bytes. Any record whose key_len > 31 overflows the
     * stack buffer — a classic stack-buffer-overflow that walks toward
     * the saved return address. The bounds check above only proves the
     * bytes exist in the *input*, not that they fit in the destination. */
    char keybuf[MAX_KEY];
    memcpy(keybuf, cur, key_len);
    keybuf[key_len] = '\0';
    cur += key_len;

    if (cur + 1 > end) return -1;
    uint8_t val_len = *cur++;

    if (cur + val_len > end) return -1;

    uint8_t *val = malloc(val_len ? val_len : 1);
    if (!val) return -1;
    memcpy(val, cur, val_len);
    cur += val_len;

    memcpy(rec->key, keybuf, MAX_KEY);
    rec->value   = val;
    rec->val_len = val_len;

    *p = cur;
    return 0;
}

/*
 * LoadRecords — top-level entry. Walks the whole buffer.
 *
 * libFuzzer-friendly signature: point a harness straight at this with
 * (const uint8_t *data, size_t size).
 *
 * Returns the number of records loaded.
 */
int LoadRecords(const uint8_t *data, size_t size)
{
    if (!data || size == 0) return 0;

    const uint8_t *p   = data;
    const uint8_t *end = data + size;

    KvRecord recs[MAX_RECS];
    int n = 0;

    while (n < MAX_RECS) {
        if (load_one(&p, end, &recs[n]) != 0)
            break;
        n++;
    }

    for (int i = 0; i < n; i++)
        free(recs[i].value);

    return n;
}

/* ------------------------------------------------------------------ */
/* Standalone CLI driver                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: kvstore <file>\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return 1; }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); free(buf); return 1;
    }
    fclose(f);

    int n = LoadRecords(buf, (size_t)sz);
    printf("loaded %d record(s)\n", n);

    free(buf);
    return 0;
}
