/*
 * tangd-host: a small POSIX Tang server built from the portable Pocket Tang core.
 *
 * Purpose: interoperability testing with the real clevis/jose tools and cross-checking against
 * upstream tangd on a Linux host, plus local development. It is single-threaded (one request
 * at a time, like the device's crypto worker) and closes the connection after each response.
 *
 * Usage:
 *   tangd-host -p PORT -d KEYDIR        serve keys from an upstream tang key directory
 *                                       (*.jwk; files starting with '.' are rotated keys)
 *   tangd-host -p PORT -s STATEFILE     serve keys from a Pocket Tang state blob, creating it
 *                                       (with fresh keys) if it does not exist
 *   tangd-host -s STATEFILE --rotate    rotate keys in the state blob and exit
 *   tangd-host ... --thp                print the S256 thumbprint of the active signing key, exit
 *   options: -l ADDR (default 127.0.0.1), --no-tang-pub, --lock
 */
#include "pt/pt_http.h"
#include "pt/pt_tang.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static pt_tang_t g_tang;
static volatile sig_atomic_t g_stop;

static int host_rng(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    while (len > 0) {
        ssize_t n = getrandom(buf, len, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void on_event(void *ctx, pt_tang_event_t ev, int status, const char *kid)
{
    (void)ctx;
    const char *name = ev == PT_EV_REC_OK ? "rec-ok" : ev == PT_EV_REC_DENIED ? "rec-denied" : "adv";
    fprintf(stderr, "tangd-host: %s status=%d kid=%s\n", name, status, kid);
}

static int read_file(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(buf, 1, cap, f);
    int more = fgetc(f);
    fclose(f);
    if (more != EOF) {
        return -1;
    }
    *len = n;
    return 0;
}

static int write_file_atomic(const char *path, const uint8_t *buf, size_t len)
{
    char tmp[4096];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
        return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    ssize_t w = write(fd, buf, len);
    int rc = (w == (ssize_t)len && fsync(fd) == 0) ? 0 : -1;
    close(fd);
    if (rc == 0) {
        rc = rename(tmp, path);
    }
    return rc;
}

static int load_keydir(const char *dir)
{
    DIR *d = opendir(dir);
    if (d == NULL) {
        perror(dir);
        return -1;
    }
    struct dirent *e;
    int loaded = 0;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n < 5 || strcmp(e->d_name + n - 4, ".jwk") != 0) {
            continue;
        }
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        static uint8_t buf[8192];
        size_t len = 0;
        if (read_file(path, buf, sizeof(buf), &len) != 0) {
            fprintf(stderr, "tangd-host: cannot read %s\n", path);
            continue;
        }
        pt_json_tok_t toks[64];
        pt_json_doc_t doc;
        pt_jwk_t jwk;
        if (pt_json_parse((const char *)buf, len, toks, 64, &doc) != PT_OK ||
            pt_jwk_parse(&doc, 0, true, &jwk) != PT_OK || !jwk.has_d) {
            fprintf(stderr, "tangd-host: skipping invalid key %s\n", path);
            pt_zeroize(buf, len);
            continue;
        }
        pt_zeroize(buf, len);
        bool rotated = e->d_name[0] == '.';
        /* Import rotated keys as rotated so they never become active. */
        pt_err_t err = pt_keystore_import(pt_tang_keystore(&g_tang), &jwk, rotated);
        pt_jwk_wipe(&jwk);
        if (err != PT_OK) {
            fprintf(stderr, "tangd-host: cannot import %s: %s\n", path, pt_err_str(err));
            continue;
        }
        loaded++;
    }
    closedir(d);
    return loaded > 0 ? 0 : -1;
}

static int save_state(const char *path)
{
    static uint8_t blob[PT_KEYSTORE_BLOB_MAX];
    size_t len = 0;
    if (pt_keystore_save(pt_tang_keystore(&g_tang), blob, sizeof(blob), &len) != PT_OK) {
        return -1;
    }
    int rc = write_file_atomic(path, blob, len);
    pt_zeroize(blob, sizeof(blob));
    return rc;
}

static int load_state(const char *path)
{
    static uint8_t blob[PT_KEYSTORE_BLOB_MAX + 1];
    size_t len = 0;
    if (read_file(path, blob, sizeof(blob), &len) != 0) {
        if (errno != ENOENT) {
            return -1;
        }
        fprintf(stderr, "tangd-host: creating new keys in %s\n", path);
        if (pt_keystore_ensure(pt_tang_keystore(&g_tang)) != PT_OK) {
            return -1;
        }
        return save_state(path);
    }
    pt_err_t err = pt_keystore_load(pt_tang_keystore(&g_tang), blob, len);
    pt_zeroize(blob, sizeof(blob));
    if (err != PT_OK) {
        fprintf(stderr, "tangd-host: invalid state file %s: %s\n", path, pt_err_str(err));
        return -1;
    }
    return 0;
}

static bool send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return false;
        }
        buf += n;
        len -= (size_t)n;
    }
    return true;
}

static void reply_status(int fd, int status)
{
    char head[256];
    size_t n = pt_http_write_head(head, sizeof(head), status, NULL, 0, false);
    (void)send_all(fd, head, n);
}

static void serve_client(int fd)
{
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    static char buf[PT_HTTP_MAX_HEAD + PT_TANG_MAX_BODY];
    size_t have = 0;
    pt_http_req_t hreq;
    int rc = PT_HTTP_NEED_MORE;
    while (rc == PT_HTTP_NEED_MORE) {
        if (have >= PT_HTTP_MAX_HEAD) {
            reply_status(fd, 431);
            return;
        }
        ssize_t n = recv(fd, buf + have, PT_HTTP_MAX_HEAD - have, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                reply_status(fd, 408);
            }
            return;
        }
        have += (size_t)n;
        rc = pt_http_parse_head(buf, have, PT_TANG_MAX_BODY, &hreq);
    }
    if (rc < 0) {
        reply_status(fd, -rc);
        return;
    }
    size_t need = hreq.head_len + hreq.content_length;
    while (have < need) {
        ssize_t n = recv(fd, buf + have, need - have, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            reply_status(fd, 408);
            return;
        }
        have += (size_t)n;
    }

    pt_tang_req_t treq;
    pt_tang_route(hreq.method, hreq.target, hreq.target_len, &treq);
    static char body[PT_TANG_RESP_MAX];
    pt_tang_resp_t resp;
    pt_tang_handle(&g_tang, &treq, (const uint8_t *)buf + hreq.head_len, hreq.content_length, body,
                   sizeof(body), &resp);
    char head[256];
    size_t hn = pt_http_write_head(head, sizeof(head), resp.status, resp.content_type,
                                   resp.body_len, false);
    if (send_all(fd, head, hn)) {
        (void)send_all(fd, body, resp.body_len);
    }
    fprintf(stderr, "tangd-host: %s %.*s => %d\n", hreq.method, (int)hreq.target_len, hreq.target,
            resp.status);
    pt_zeroize(buf, have);
}

static void usage(void)
{
    fprintf(stderr, "usage: tangd-host [-l ADDR] [-p PORT] (-d KEYDIR | -s STATEFILE) "
                    "[--rotate] [--thp] [--no-tang-pub] [--lock]\n");
}

int main(int argc, char **argv)
{
    const char *addr = "127.0.0.1";
    int port = 8888;
    const char *keydir = NULL;
    const char *state = NULL;
    bool rotate = false;
    bool thp = false;
    bool tang_pub = true;
    bool lock = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            addr = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            char *endp = NULL;
            long v = strtol(argv[++i], &endp, 10);
            port = (endp != NULL && *endp == '\0' && v > 0 && v <= 65535) ? (int)v : -1;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            keydir = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            state = argv[++i];
        } else if (strcmp(argv[i], "--rotate") == 0) {
            rotate = true;
        } else if (strcmp(argv[i], "--thp") == 0) {
            thp = true;
        } else if (strcmp(argv[i], "--no-tang-pub") == 0) {
            tang_pub = false;
        } else if (strcmp(argv[i], "--lock") == 0) {
            lock = true;
        } else {
            usage();
            return 2;
        }
    }
    if ((keydir == NULL) == (state == NULL) || port <= 0 || port > 65535) {
        usage();
        return 2;
    }
    pt_crypto_set_rng(host_rng, NULL);
    pt_tang_init(&g_tang);
    g_tang.include_tang_pub = tang_pub;
    pt_tang_set_locked(&g_tang, lock);
    pt_tang_set_event_cb(&g_tang, on_event, NULL);
    if (keydir != NULL ? load_keydir(keydir) != 0 : load_state(state) != 0) {
        fprintf(stderr, "tangd-host: no usable keys\n");
        return 1;
    }
    if (rotate) {
        if (state == NULL) {
            fprintf(stderr, "tangd-host: --rotate needs -s\n");
            return 2;
        }
        pt_err_t err = pt_keystore_rotate(pt_tang_keystore(&g_tang));
        if (err != PT_OK || save_state(state) != 0) {
            fprintf(stderr, "tangd-host: rotation failed: %s\n", pt_err_str(err));
            return 1;
        }
        fprintf(stderr, "tangd-host: rotated, %u keys\n", pt_keystore_count(pt_tang_keystore(&g_tang)));
        return 0;
    }
    if (thp) {
        const pt_key_t *k = pt_keystore_active(pt_tang_keystore(&g_tang), PT_ALG_ES512);
        char out[PT_THP_MAX];
        if (k == NULL || pt_jwk_thumbprint_b64(&k->pub, PT_HASH_SHA256, out, sizeof(out)) != PT_OK) {
            return 1;
        }
        printf("%s\n", out);
        return 0;
    }
    if (pt_tang_refresh(&g_tang) != PT_OK) {
        fprintf(stderr, "tangd-host: cannot build advertisement\n");
        return 1;
    }

    /* No SA_RESTART: a signal must interrupt accept() so the server can exit. */
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = on_signal;
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1 ||
        bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(s, 16) != 0) {
        perror("tangd-host: listen");
        return 1;
    }
    fprintf(stderr, "tangd-host: listening on %s:%d\n", addr, port);
    while (!g_stop) {
        int c = accept(s, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) {
                continue; /* loop condition re-checks g_stop */
            }
            perror("accept");
            break;
        }
        serve_client(c);
        close(c);
    }
    close(s);
    pt_tang_wipe(&g_tang);
    return 0;
}
