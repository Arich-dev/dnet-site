/* dnetd — маяк DNet для роутеров (OpenWrt и т.п.).
 * Отвечает на hello/peers по TCP 48556, рассылает UDP-маяк на 48555.
 * Страниц не хранит, таблица соседей живёт только в RAM. Только libc.
 *
 * Сборка (SDK/тулчейн OpenWrt):  $CC -Os -s -o dnetd dnetd.c
 * Запуск: dnetd [-l файл_лога] [-n]. Лог по умолчанию лежит рядом с бинарником (dnetd.log),
 * не больше 4 КБ, сбрасывается при каждом запуске.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 /* SIGPIPE и так игнорируется */
#endif
/* у BSD адрес широковещания лежит в ifa_dstaddr */
#ifdef __linux__
#define BCAST(a) ((a)->ifa_broadaddr)
#else
#define BCAST(a) ((a)->ifa_dstaddr)
#endif

#define TCP_PORT 48556
#define UDP_PORT 48555
#define MAX_PEERS 64
#define PER_IP 8
#define TTL 300
#define BEACON_EVERY 15
#define CONN_PER_SEC 40

struct peer {
    char id[65];
    struct in_addr ip;
    unsigned short port;
    time_t seen;
};

static struct peer tab[MAX_PEERS];
static char my_id[65];

/* Лог: файл не больше LOG_MAX байт (при переполнении начинается заново),
 * не больше LOG_LINES строк в минуту, чтобы не убивать флеш. */
#define LOG_MAX 4096
#define LOG_LINES 30
static int logfd = -1;
static size_t logged;

static long mono(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

static void logput(const char *line, int n)
{
    if ((size_t)n + logged > LOG_MAX) {
        if (ftruncate(logfd, 0))
            return;
        logged = 0;
    }
    if (write(logfd, line, n) > 0)
        logged += n;
}

static void dlog(const char *fmt, ...)
{
    static long win, t0, lines;
    char line[160];
    long now = mono();
    if (logfd < 0)
        return;
    if (!t0)
        t0 = now;
    if (now - win >= 60) {
        win = now;
        lines = 0;
    }
    if (++lines > LOG_LINES + 1)
        return;
    int n;
    if (lines == LOG_LINES + 1) {
        n = snprintf(line, sizeof line, "(too many messages, skipping until next minute)\n");
    } else {
        va_list ap;
        n = snprintf(line, sizeof line, "+%lds ", now - t0);
        va_start(ap, fmt);
        n += vsnprintf(line + n, sizeof line - n, fmt, ap);
        va_end(ap);
        if (n > (int)sizeof line - 2)
            n = sizeof line - 2;
        line[n++] = '\n';
    }
    logput(line, n);
}

/* Лог рядом с исполняемым файлом: dnetd.log */
static void default_log(char *out, size_t n, const char *argv0)
{
    char exe[256];
    const char *src = argv0 ? argv0 : "";
    ssize_t r = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (r > 0) {
        exe[r] = 0;
        src = exe;
    }
    const char *slash = strrchr(src, '/');
    if (slash)
        snprintf(out, n, "%.*s/dnetd.log", (int)(slash - src), src);
    else
        snprintf(out, n, "/tmp/dnetd.log");
}

/* Минимальный разбор JSON: достаём "key":"строка" и "key":число. */
static const char *field(const char *s, const char *key)
{
    char pat[24];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    s = strstr(s, pat);
    if (!s)
        return NULL;
    s += strlen(pat);
    while (*s == ' ')
        s++;
    if (*s++ != ':')
        return NULL;
    while (*s == ' ')
        s++;
    return s;
}

static int jstr(const char *s, const char *key, char *out, size_t n)
{
    const char *p = field(s, key);
    size_t i = 0;
    if (!p || *p++ != '"')
        return 0;
    while (*p && *p != '"') {
        if (*p == '\\' || i + 1 >= n)
            return 0;
        out[i++] = *p++;
    }
    out[i] = 0;
    return *p == '"';
}

static long jint(const char *s, const char *key)
{
    const char *p = field(s, key);
    return p ? strtol(p, NULL, 10) : -1;
}

static int valid_id(const char *id)
{
    size_t n = strlen(id);
    if (n < 8 || n > 64)
        return 0;
    for (; *id; id++)
        if (!isxdigit((unsigned char)*id) || isupper((unsigned char)*id))
            return 0;
    return 1;
}

static int alive(const struct peer *p, time_t now)
{
    return p->id[0] && now - p->seen < TTL;
}

static void touch(const char *id, struct in_addr ip, unsigned short port)
{
    time_t now = time(NULL);
    struct peer *slot = NULL, *oldest = NULL, *oldest_ip = NULL;
    int same_ip = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        struct peer *p = &tab[i];
        if (alive(p, now) && !strcmp(p->id, id)) {
            slot = p;
            break;
        }
        if (alive(p, now) && p->ip.s_addr == ip.s_addr) {
            same_ip++;
            if (!oldest_ip || p->seen < oldest_ip->seen)
                oldest_ip = p;
        }
        if (!alive(p, now)) {
            if (!slot)
                slot = p;
        } else if (!oldest || p->seen < oldest->seen) {
            oldest = p;
        }
    }
    /* один адрес не может занять всю таблицу */
    if (same_ip >= PER_IP && !(slot && alive(slot, now)))
        slot = oldest_ip;
    if (!slot)
        slot = oldest;
    if (!(slot && alive(slot, now) && !strcmp(slot->id, id)))
        dlog("peer+ %s %s:%u%s", id, inet_ntoa(ip), port, slot && alive(slot, now) ? " (evicted old)" : "");
    snprintf(slot->id, sizeof slot->id, "%s", id);
    slot->ip = ip;
    slot->port = port;
    slot->seen = now;
}

static void handle(int c, struct in_addr from)
{
    char buf[1024], op[16], id[65], out[1536];
    size_t n = 0;
    struct timeval tv = {0, 300000};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    while (n < sizeof buf - 1) {
        ssize_t r = recv(c, buf + n, sizeof buf - 1 - n, 0);
        if (r <= 0)
            break;
        n += r;
        if (memchr(buf, '\n', n))
            break;
    }
    buf[n] = 0;
    if (!jstr(buf, "op", op, sizeof op)) {
        dlog("%s: %s", inet_ntoa(from), n ? "bad request" : "no data");
        return;
    }

    int len;
    if (!strcmp(op, "hello")) {
        long port = jint(buf, "port");
        if (jstr(buf, "id", id, sizeof id) && valid_id(id) && strcmp(id, my_id) && port > 0 && port < 65536)
            touch(id, from, (unsigned short)port);
        else
            dlog("%s: bad hello", inet_ntoa(from));
        len = snprintf(out, sizeof out,
                       "{\"op\": \"hello\", \"id\": \"%s\", \"nick\": \"router\", \"sup\": false, "
                       "\"port\": %d, \"v\": 1, \"kind\": \"router\"}\n", my_id, TCP_PORT);
    } else if (!strcmp(op, "peers")) {
        time_t now = time(NULL);
        len = snprintf(out, sizeof out, "{\"peers\": [");
        int first = 1, cnt = 0;
        for (int i = 0; i < MAX_PEERS && cnt < 20; i++) {
            if (!alive(&tab[i], now) || tab[i].ip.s_addr == from.s_addr)
                continue;
            len += snprintf(out + len, sizeof out - len, "%s[\"%s\", %u]", first ? "" : ", ",
                            inet_ntoa(tab[i].ip), tab[i].port);
            first = 0;
            cnt++;
        }
        len += snprintf(out + len, sizeof out - len, "]}\n");
    } else if (!strcmp(op, "index")) {
        len = snprintf(out, sizeof out, "{\"items\": []}\n");
    } else if (!strcmp(op, "get")) {
        len = snprintf(out, sizeof out, "{\"ok\": false}\n");
    } else if (!strcmp(op, "want")) {
        len = snprintf(out, sizeof out, "{\"ok\": true}\n");
    } else {
        for (char *p = op; *p; p++)
            if (!isprint((unsigned char)*p))
                *p = '?';
        dlog("%s: unknown op '%s'", inet_ntoa(from), op);
        len = snprintf(out, sizeof out, "{\"error\": \"bad op\"}\n");
    }
    if (len > 0 && (size_t)len < sizeof out)
        send(c, out, len, MSG_NOSIGNAL);
}

static void beacon(int u)
{
    char pkt[128];
    int n = snprintf(pkt, sizeof pkt, "{\"dnet\": 1, \"id\": \"%s\"}", my_id);
    struct ifaddrs *ifs, *a;
    static int warned;
    int sent = 0;
    if (getifaddrs(&ifs))
        return;
    for (a = ifs; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET || !(a->ifa_flags & IFF_UP) ||
            !(a->ifa_flags & IFF_BROADCAST) || (a->ifa_flags & IFF_LOOPBACK) || !BCAST(a))
            continue;
        struct sockaddr_in to = *(struct sockaddr_in *)BCAST(a);
        to.sin_port = htons(UDP_PORT);
        if (sendto(u, pkt, n, 0, (struct sockaddr *)&to, sizeof to) > 0)
            sent++;
    }
    freeifaddrs(ifs);
    if (!sent && !warned) {
        warned = 1;
        dlog("beacon: no interface to send broadcast from");
    }
}

/* Стабильный id из MAC моста/интерфейса, чтобы после перезапуска не плодить дубли. */
static void make_id(void)
{
    static const char *ifs[] = {"br-lan", "eth0", "lan", "wlan0"};
    char path[64], mac[32];
    for (unsigned i = 0; i < sizeof ifs / sizeof *ifs; i++) {
        snprintf(path, sizeof path, "/sys/class/net/%s/address", ifs[i]);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        int ok = fgets(mac, sizeof mac, f) != NULL;
        fclose(f);
        if (!ok)
            continue;
        size_t k = 0;
        for (char *p = mac; *p && k < 12; p++)
            if (isxdigit((unsigned char)*p))
                my_id[k++] = tolower((unsigned char)*p);
        my_id[k] = 0;
        if (k == 12)
            return;
    }
    snprintf(my_id, sizeof my_id, "%08lx%08lx", (unsigned long)time(NULL), (unsigned long)getpid());
}

int main(int argc, char **argv)
{
    char logpath[256];
    int nolog = 0;
    default_log(logpath, sizeof logpath, argc ? argv[0] : NULL);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-l") && i + 1 < argc) {
            snprintf(logpath, sizeof logpath, "%s", argv[++i]);
        } else if (!strcmp(argv[i], "-n")) {
            nolog = 1;
        } else {
            fprintf(stderr, "usage: dnetd [-l logfile] [-n]\n  -l  log path (default: dnetd.log next to the binary)\n"
                            "  -n  no log\n");
            return 2;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    make_id();

    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in me = {.sin_family = AF_INET, .sin_port = htons(TCP_PORT)};
    if (bind(s, (struct sockaddr *)&me, sizeof me) || listen(s, 16)) {
        perror("dnetd: bind");
        return 1;
    }
    if (!nolog) {
        /* чистим лог при каждом успешном запуске */
        logfd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        if (logfd < 0)
            fprintf(stderr, "dnetd: cannot open log %s, running without it\n", logpath);
    }
    dlog("start id=%s tcp=%d log=%s", my_id, TCP_PORT, logpath);
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(u, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);

    time_t next = 0, sec = 0;
    int cnt = 0;
    for (;;) {
        time_t now = time(NULL);
        if (now >= next) {
            beacon(u);
            next = now + BEACON_EVERY;
        }
        struct pollfd pf = {s, POLLIN, 0};
        if (poll(&pf, 1, 1000) <= 0)
            continue;
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        int c = accept(s, (struct sockaddr *)&from, &fl);
        if (c < 0)
            continue;
        now = time(NULL);
        if (now != sec) {
            sec = now;
            cnt = 0;
        }
        if (++cnt <= CONN_PER_SEC)
            handle(c, from.sin_addr);
        else if (cnt == CONN_PER_SEC + 1)
            dlog("%s: over %d conn/s, dropping", inet_ntoa(from.sin_addr), CONN_PER_SEC);
        close(c);
    }
}
