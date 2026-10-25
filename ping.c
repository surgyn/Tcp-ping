#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define RESET "\033[0m"

#ifndef DNS_SERVER
#define DNS_SERVER "1.1.1.1"
#endif
#ifndef DNS_PORT
#define DNS_PORT 53
#endif

#define DNS_TIMEOUT_MS 2000
#define DNS_TRIES 3
#define DNS_QUERY_MAX 512
#define DNS_MSG_MAX 4096
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28

#define TIMEOUT_MS 3000
#define INTERVAL_MS 1000
#define LABEL_LEN 400

struct target {
    struct sockaddr_storage addr;
    socklen_t len;
    int family;
    char ip_text[INET6_ADDRSTRLEN];
};

static volatile sig_atomic_t stop_flag = 0;
static int g_fd = -1;

static void on_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static void cleanup(void)
{
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
    if (isatty(STDOUT_FILENO)) {
        fputs(RESET, stdout);
    }
    fflush(stdout);
}

static int install_handlers(void)
{
    struct sigaction sa;
    const int sigs[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
    size_t i;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) < 0) {
            return -1;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int open_socket(int family, int type)
{
    int fd;
    int flags;

    fd = socket(family, type, 0);
    if (fd < 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    g_fd = fd;
    return fd;
}

static void close_fd(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
    g_fd = -1;
}

static int wait_fd(int fd, short events, double deadline)
{
    for (;;) {
        struct pollfd pfd;
        double remaining;
        int p;

        if (stop_flag) {
            return -2;
        }
        remaining = deadline - now_ms();
        if (remaining <= 0.0) {
            return 0;
        }
        pfd.fd = fd;
        pfd.events = events;
        pfd.revents = 0;
        p = poll(&pfd, 1, (int)remaining + 1);
        if (p < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (p == 0) {
            continue;
        }
        return 1;
    }
}

static int connect_timeout(int fd, const struct sockaddr *sa, socklen_t len, int timeout_ms,
                           int *err)
{
    double deadline = now_ms() + (double)timeout_ms;
    int soerr = 0;
    socklen_t soerr_len = sizeof(soerr);
    int w;

    *err = 0;
    if (connect(fd, sa, len) == 0) {
        return 1;
    }
    if (errno != EINPROGRESS && errno != EINTR) {
        *err = errno;
        return 0;
    }

    w = wait_fd(fd, POLLOUT, deadline);
    if (w == -2) {
        return -1;
    }
    if (w == 0) {
        *err = ETIMEDOUT;
        return 0;
    }
    if (w < 0) {
        *err = errno;
        return 0;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) < 0) {
        *err = errno;
        return 0;
    }
    if (soerr != 0) {
        *err = soerr;
        return 0;
    }
    return 1;
}

static int send_all(int fd, const uint8_t *buf, size_t n, double deadline)
{
    while (n > 0) {
        ssize_t r = send(fd, buf, n, MSG_NOSIGNAL);
        if (r > 0) {
            buf += r;
            n -= (size_t)r;
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            int w = wait_fd(fd, POLLOUT, deadline);
            if (w == 1) {
                continue;
            }
            return w == -2 ? -1 : 0;
        }
        return 0;
    }
    return 1;
}

static int recv_all(int fd, uint8_t *buf, size_t n, double deadline)
{
    while (n > 0) {
        ssize_t r = recv(fd, buf, n, 0);
        if (r > 0) {
            buf += r;
            n -= (size_t)r;
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            int w = wait_fd(fd, POLLIN, deadline);
            if (w == 1) {
                continue;
            }
            return w == -2 ? -1 : 0;
        }
        return 0;
    }
    return 1;
}

static uint16_t random_id(void)
{
    uint8_t b[2];
    ssize_t r = -1;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

    if (fd >= 0) {
        r = read(fd, b, sizeof(b));
        close(fd);
    }
    if (r == (ssize_t)sizeof(b)) {
        return (uint16_t)((b[0] << 8) | b[1]);
    }
    return (uint16_t)((uint64_t)now_ms() ^ (uint64_t)getpid());
}

static int name_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_';
}

static int dns_encode_name(const char *name, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = strlen(name);
    size_t i = 0;
    size_t pos = 0;

    if (n > 0 && name[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n > 253) {
        return -1;
    }

    while (i < n) {
        size_t start = i;
        size_t label_len;

        while (i < n && name[i] != '.') {
            if (!name_char((unsigned char)name[i])) {
                return -1;
            }
            i++;
        }
        label_len = i - start;
        if (label_len == 0 || label_len > 63) {
            return -1;
        }
        if (pos + 1 + label_len + 1 > cap) {
            return -1;
        }
        out[pos++] = (uint8_t)label_len;
        memcpy(out + pos, name + start, label_len);
        pos += label_len;
        if (i < n) {
            i++;
            if (i == n) {
                return -1;
            }
        }
    }

    out[pos++] = 0;
    *out_len = pos;
    return 0;
}

static int dns_build_query(const char *name, uint16_t id, uint16_t qtype, uint8_t *buf, size_t cap)
{
    size_t name_len = 0;
    size_t p;

    if (cap < 32) {
        return -1;
    }
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(id >> 8);
    buf[1] = (uint8_t)(id & 0xff);
    buf[2] = 0x01;
    buf[5] = 1;

    if (dns_encode_name(name, buf + 12, cap - 12 - 4, &name_len) < 0) {
        return -1;
    }
    p = 12 + name_len;
    buf[p++] = (uint8_t)(qtype >> 8);
    buf[p++] = (uint8_t)(qtype & 0xff);
    buf[p++] = 0;
    buf[p++] = 1;
    return (int)p;
}

static int dns_skip_name(const uint8_t *msg, size_t len, size_t *pos)
{
    size_t p = *pos;

    for (;;) {
        uint8_t b;

        if (p >= len) {
            return -1;
        }
        b = msg[p];
        if (b == 0) {
            p++;
            break;
        }
        if ((b & 0xC0) == 0xC0) {
            if (p + 2 > len) {
                return -1;
            }
            p += 2;
            break;
        }
        if ((b & 0xC0) != 0) {
            return -1;
        }
        p += 1 + (size_t)b;
        if (p > len) {
            return -1;
        }
    }

    *pos = p;
    return 0;
}

static int dns_parse(const uint8_t *msg, size_t len, uint16_t id, uint16_t qtype, uint8_t *addr,
                     int *truncated)
{
    uint16_t flags;
    uint16_t qd;
    uint16_t an;
    uint16_t i;
    size_t p = 12;
    size_t want = (qtype == DNS_TYPE_A) ? 4 : 16;

    *truncated = 0;
    if (len < 12) {
        return -1;
    }
    if ((uint16_t)((msg[0] << 8) | msg[1]) != id) {
        return -1;
    }
    flags = (uint16_t)((msg[2] << 8) | msg[3]);
    if (!(flags & 0x8000)) {
        return -1;
    }
    if (flags & 0x0200) {
        *truncated = 1;
        return -1;
    }
    if ((flags & 0x000F) == 3) {
        return 0;
    }
    if ((flags & 0x000F) != 0) {
        return -1;
    }

    qd = (uint16_t)((msg[4] << 8) | msg[5]);
    an = (uint16_t)((msg[6] << 8) | msg[7]);

    for (i = 0; i < qd; i++) {
        if (dns_skip_name(msg, len, &p) < 0 || p + 4 > len) {
            return -1;
        }
        p += 4;
    }

    for (i = 0; i < an; i++) {
        uint16_t type;
        uint16_t cls;
        uint16_t rdlen;

        if (dns_skip_name(msg, len, &p) < 0 || p + 10 > len) {
            return -1;
        }
        type = (uint16_t)((msg[p] << 8) | msg[p + 1]);
        cls = (uint16_t)((msg[p + 2] << 8) | msg[p + 3]);
        rdlen = (uint16_t)((msg[p + 8] << 8) | msg[p + 9]);
        p += 10;
        if (p + rdlen > len) {
            return -1;
        }
        if (type == qtype && cls == 1 && rdlen == want) {
            memcpy(addr, msg + p, want);
            return 1;
        }
        p += rdlen;
    }

    return 0;
}

static int dns_udp(const struct sockaddr_in *srv, const uint8_t *q, size_t qlen, uint8_t *resp,
                   size_t cap, size_t *rlen)
{
    int fd;
    int w;
    ssize_t n;

    fd = open_socket(AF_INET, SOCK_DGRAM);
    if (fd < 0) {
        return 0;
    }
    if (connect(fd, (const struct sockaddr *)srv, sizeof(*srv)) < 0 ||
        send(fd, q, qlen, 0) < 0) {
        close_fd(fd);
        return 0;
    }
    w = wait_fd(fd, POLLIN, now_ms() + DNS_TIMEOUT_MS);
    if (w != 1) {
        close_fd(fd);
        return w == -2 ? -1 : 0;
    }
    n = recv(fd, resp, cap, 0);
    close_fd(fd);
    if (n <= 0) {
        return 0;
    }
    *rlen = (size_t)n;
    return 1;
}

static int dns_tcp(const struct sockaddr_in *srv, const uint8_t *q, size_t qlen, uint8_t *resp,
                   size_t cap, size_t *rlen)
{
    uint8_t frame[2 + DNS_QUERY_MAX];
    uint8_t lenb[2];
    size_t want;
    double deadline;
    int fd;
    int r;
    int cerr;

    if (qlen > DNS_QUERY_MAX) {
        return 0;
    }
    frame[0] = (uint8_t)(qlen >> 8);
    frame[1] = (uint8_t)(qlen & 0xff);
    memcpy(frame + 2, q, qlen);

    fd = open_socket(AF_INET, SOCK_STREAM);
    if (fd < 0) {
        return 0;
    }
    r = connect_timeout(fd, (const struct sockaddr *)srv, sizeof(*srv), DNS_TIMEOUT_MS, &cerr);
    if (r != 1) {
        close_fd(fd);
        return r;
    }

    deadline = now_ms() + DNS_TIMEOUT_MS;
    r = send_all(fd, frame, qlen + 2, deadline);
    if (r == 1) {
        r = recv_all(fd, lenb, sizeof(lenb), deadline);
    }
    if (r == 1) {
        want = (size_t)((lenb[0] << 8) | lenb[1]);
        if (want < 12 || want > cap) {
            r = 0;
        } else {
            r = recv_all(fd, resp, want, deadline);
            if (r == 1) {
                *rlen = want;
            }
        }
    }
    close_fd(fd);
    return r;
}

static int dns_query(const struct sockaddr_in *srv, const char *name, uint16_t qtype,
                     uint8_t *addr)
{
    uint8_t query[DNS_QUERY_MAX];
    uint8_t resp[DNS_MSG_MAX];
    uint16_t id = random_id();
    int qlen;
    int attempt_no;

    qlen = dns_build_query(name, id, qtype, query, sizeof(query));
    if (qlen < 0) {
        return -2;
    }

    for (attempt_no = 0; attempt_no < DNS_TRIES; attempt_no++) {
        size_t rlen = 0;
        int truncated = 0;
        int r;
        int pr;

        r = dns_udp(srv, query, (size_t)qlen, resp, sizeof(resp), &rlen);
        if (r == -1) {
            return -1;
        }
        if (r == 0) {
            continue;
        }

        pr = dns_parse(resp, rlen, id, qtype, addr, &truncated);
        if (truncated) {
            r = dns_tcp(srv, query, (size_t)qlen, resp, sizeof(resp), &rlen);
            if (r == -1) {
                return -1;
            }
            if (r == 0) {
                continue;
            }
            pr = dns_parse(resp, rlen, id, qtype, addr, &truncated);
        }
        if (pr >= 0) {
            return pr;
        }
    }

    return -2;
}

static void target_v4(struct target *t, const uint8_t *ip, uint16_t port)
{
    struct sockaddr_in a;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    memcpy(&a.sin_addr, ip, 4);

    memset(t, 0, sizeof(*t));
    memcpy(&t->addr, &a, sizeof(a));
    t->len = sizeof(a);
    t->family = AF_INET;
    inet_ntop(AF_INET, ip, t->ip_text, sizeof(t->ip_text));
}

static void target_v6(struct target *t, const uint8_t *ip, uint16_t port)
{
    struct sockaddr_in6 a;

    memset(&a, 0, sizeof(a));
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);
    memcpy(&a.sin6_addr, ip, 16);

    memset(t, 0, sizeof(*t));
    memcpy(&t->addr, &a, sizeof(a));
    t->len = sizeof(a);
    t->family = AF_INET6;
    inet_ntop(AF_INET6, ip, t->ip_text, sizeof(t->ip_text));
}

static int parse_literal(const char *s, uint16_t port, struct target *t)
{
    uint8_t buf[16];

    if (inet_pton(AF_INET, s, buf) == 1) {
        target_v4(t, buf, port);
        return 0;
    }
    if (inet_pton(AF_INET6, s, buf) == 1) {
        target_v6(t, buf, port);
        return 0;
    }
    return -1;
}

#define RESOLVE_OK 0
#define RESOLVE_INTERRUPTED -1
#define RESOLVE_INVALID -2
#define RESOLVE_FAILED -3
#define RESOLVE_NONE -4

static const char *resolve_error(int code)
{
    switch (code) {
    case RESOLVE_INVALID:
        return "invalid address or domain name";
    case RESOLVE_FAILED:
        return "DNS lookup via " DNS_SERVER " failed";
    case RESOLVE_NONE:
        return "no A or AAAA records found";
    default:
        return "interrupted";
    }
}

static int resolve_domain(const char *name, uint16_t port, struct target *t)
{
    struct sockaddr_in srv;
    uint8_t addr[16];
    uint8_t probe[DNS_QUERY_MAX];
    int ra;
    int r6;

    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, DNS_SERVER, &srv.sin_addr) != 1) {
        return RESOLVE_FAILED;
    }

    if (dns_build_query(name, 0, DNS_TYPE_A, probe, sizeof(probe)) < 0) {
        return RESOLVE_INVALID;
    }

    ra = dns_query(&srv, name, DNS_TYPE_A, addr);
    if (ra == 1) {
        target_v4(t, addr, port);
        return RESOLVE_OK;
    }
    if (ra == -1) {
        return RESOLVE_INTERRUPTED;
    }

    r6 = dns_query(&srv, name, DNS_TYPE_AAAA, addr);
    if (r6 == 1) {
        target_v6(t, addr, port);
        return RESOLVE_OK;
    }
    if (r6 == -1) {
        return RESOLVE_INTERRUPTED;
    }

    if (ra == -2 && r6 == -2) {
        return RESOLVE_FAILED;
    }
    return RESOLVE_NONE;
}

static void format_label(char *buf, size_t n, const char *host, const struct target *t,
                         uint16_t port)
{
    if (host != NULL) {
        snprintf(buf, n, "%s (%s):%u", host, t->ip_text, (unsigned)port);
    } else if (t->family == AF_INET6) {
        snprintf(buf, n, "[%s]:%u", t->ip_text, (unsigned)port);
    } else {
        snprintf(buf, n, "%s:%u", t->ip_text, (unsigned)port);
    }
}

static int parse_port(const char *s, uint16_t *out)
{
    char *end = NULL;
    long v;

    if (s == NULL || *s == '\0') {
        return -1;
    }
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < 1 || v > 65535) {
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int attempt(const struct target *t, double *elapsed, int *err)
{
    int fd;
    int r;
    double start;

    *elapsed = 0.0;
    *err = 0;

    fd = open_socket(t->family, SOCK_STREAM);
    if (fd < 0) {
        *err = errno;
        return 0;
    }

    start = now_ms();
    r = connect_timeout(fd, (const struct sockaddr *)&t->addr, t->len, TIMEOUT_MS, err);
    if (r == 1) {
        *elapsed = now_ms() - start;
    }
    close_fd(fd);
    return r;
}

static void wait_interval(void)
{
    struct timespec ts;

    ts.tv_sec = INTERVAL_MS / 1000;
    ts.tv_nsec = (long)(INTERVAL_MS % 1000) * 1000000L;
    while (!stop_flag && nanosleep(&ts, &ts) < 0 && errno == EINTR) {
    }
}

int main(int argc, char **argv)
{
    struct target t;
    char label[LABEL_LEN];
    char summary_label[LABEL_LEN];
    uint16_t port = 0;
    unsigned long seq = 0;
    unsigned long ok = 0;
    unsigned long failed = 0;
    double min_ms = 0.0;
    double max_ms = 0.0;
    double sum_ms = 0.0;
    int is_domain;
    int first = 1;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <ip|domain> <port>\n", argv[0]);
        return 2;
    }
    if (parse_port(argv[2], &port) < 0) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }

    atexit(cleanup);
    if (install_handlers() < 0) {
        fprintf(stderr, "failed to install signal handlers\n");
        return 1;
    }

    is_domain = parse_literal(argv[1], port, &t) < 0;
    if (is_domain) {
        rc = resolve_domain(argv[1], port, &t);
        if (rc != RESOLVE_OK) {
            if (rc == RESOLVE_INTERRUPTED) {
                return 130;
            }
            fprintf(stderr, "%s: %s\n", resolve_error(rc), argv[1]);
            return 2;
        }
        printf("Resolved %s -> %s via %s\n", argv[1], t.ip_text, DNS_SERVER);
        snprintf(summary_label, sizeof(summary_label), "%s:%u", argv[1], (unsigned)port);
    } else {
        format_label(summary_label, sizeof(summary_label), NULL, &t, port);
    }

    printf("TCP pinging %s%s\n", summary_label,
           is_domain ? " (re-resolving on every ping)" : "");
    fflush(stdout);

    while (!stop_flag) {
        double elapsed = 0.0;
        int err = 0;
        int r;

        if (is_domain && !first) {
            rc = resolve_domain(argv[1], port, &t);
            if (rc == RESOLVE_INTERRUPTED) {
                break;
            }
            if (rc != RESOLVE_OK) {
                seq++;
                failed++;
                printf(RED "Failed to resolve %s seq=%lu: %s" RESET "\n", summary_label, seq,
                       resolve_error(rc));
                fflush(stdout);
                wait_interval();
                continue;
            }
        }
        first = 0;

        format_label(label, sizeof(label), is_domain ? argv[1] : NULL, &t, port);

        r = attempt(&t, &elapsed, &err);
        if (r < 0) {
            break;
        }

        seq++;
        if (r == 1) {
            if (ok == 0 || elapsed < min_ms) {
                min_ms = elapsed;
            }
            if (elapsed > max_ms) {
                max_ms = elapsed;
            }
            sum_ms += elapsed;
            ok++;
            printf(GREEN "Connected to %s seq=%lu time=%.2f ms" RESET "\n", label, seq,
                   elapsed);
        } else {
            failed++;
            printf(RED "Failed to connect to %s seq=%lu: %s" RESET "\n", label, seq,
                   strerror(err));
        }
        fflush(stdout);

        wait_interval();
    }

    printf("\n--- %s tcp ping statistics ---\n", summary_label);
    printf("%lu attempts, %lu successful, %lu failed", seq, ok, failed);
    if (seq > 0) {
        printf(" (%.1f%% loss)", (double)failed * 100.0 / (double)seq);
    }
    printf("\n");
    if (ok > 0) {
        printf("rtt min/avg/max = %.2f/%.2f/%.2f ms\n", min_ms, sum_ms / (double)ok,
               max_ms);
    }

    return ok > 0 ? 0 : 1;
}
