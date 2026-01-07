/*
 * TBMI Sandbox - ELF Tracer Library
 * 
 * LD_PRELOAD shared library for hooking libc functions.
 * Sends events to LogServer via Unix socket.
 * 
 * Compile:
 *   x64: gcc -shared -fPIC -o libtracer_x64.so tracer.c -ldl
 *   x86: gcc -m32 -shared -fPIC -o libtracer_x86.so tracer.c -ldl
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

/* Socket for sending events */
static int g_socket_fd = -1;
static int g_initialized = 0;

/* Original function pointers */
static int (*orig_execve)(const char*, char *const[], char *const[]) = NULL;
static int (*orig_system)(const char*) = NULL;
static FILE* (*orig_popen)(const char*, const char*) = NULL;
static int (*orig_socket)(int, int, int) = NULL;
static int (*orig_connect)(int, const struct sockaddr*, socklen_t) = NULL;
static int (*orig_bind)(int, const struct sockaddr*, socklen_t) = NULL;
static int (*orig_open)(const char*, int, ...) = NULL;
static FILE* (*orig_fopen)(const char*, const char*) = NULL;
static int (*orig_unlink)(const char*) = NULL;
static int (*orig_remove)(const char*) = NULL;
static long (*orig_ptrace)(int, ...) = NULL;
static int (*orig_chmod)(const char*, mode_t) = NULL;
static int (*orig_chown)(const char*, uid_t, gid_t) = NULL;
static int (*orig_setuid)(uid_t) = NULL;
static int (*orig_setgid)(gid_t) = NULL;
static pid_t (*orig_fork)(void) = NULL;

/* Initialize connection to LogServer */
static void init_socket(void) {
    if (g_initialized) return;
    g_initialized = 1;
    
    const char *sock_path = getenv("SANDBOX_SOCKET");
    if (!sock_path) return;
    
    g_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_socket_fd < 0) return;
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    
    if (connect(g_socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
        return;
    }
    
    /* Set non-blocking to avoid hanging */
    int flags = fcntl(g_socket_fd, F_GETFL, 0);
    fcntl(g_socket_fd, F_SETFL, flags | O_NONBLOCK);
}

/* Send event to LogServer */
static void send_event(const char *type, const char *func, const char *details) {
    if (g_socket_fd < 0) {
        init_socket();
        if (g_socket_fd < 0) return;
    }
    
    char buf[1024];
    int len = snprintf(buf, sizeof(buf),
        "{\"type\":\"%s\",\"module\":\"libc\",\"function\":\"%s\",\"cmd\":\"%s\",\"filename\":\"\",\"lineno\":0}\n",
        type, func, details ? details : "");
    
    if (len > 0 && len < (int)sizeof(buf)) {
        /* Best effort send, ignore errors */
        send(g_socket_fd, buf, len, MSG_NOSIGNAL);
    }
}

/* Escape string for JSON */
static void escape_json(char *dest, const char *src, size_t max_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < max_len - 2; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            if (j < max_len - 3) {
                dest[j++] = '\\';
                dest[j++] = c;
            }
        } else if (c == '\n') {
            if (j < max_len - 3) {
                dest[j++] = '\\';
                dest[j++] = 'n';
            }
        } else if (c == '\r') {
            if (j < max_len - 3) {
                dest[j++] = '\\';
                dest[j++] = 'r';
            }
        } else if (c >= 32 && c < 127) {
            dest[j++] = c;
        }
    }
    dest[j] = '\0';
}

/* ==================== HOOKED FUNCTIONS ==================== */

/* execve - execute program */
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (!orig_execve) {
        orig_execve = dlsym(RTLD_NEXT, "execve");
    }
    
    char escaped[256];
    escape_json(escaped, pathname ? pathname : "", sizeof(escaped));
    send_event("exec", "execve", escaped);
    
    return orig_execve(pathname, argv, envp);
}

/* system - execute shell command */
int system(const char *command) {
    if (!orig_system) {
        orig_system = dlsym(RTLD_NEXT, "system");
    }
    
    char escaped[256];
    escape_json(escaped, command ? command : "", sizeof(escaped));
    send_event("exec", "system", escaped);
    
    return orig_system(command);
}

/* popen - open process pipe */
FILE *popen(const char *command, const char *type) {
    if (!orig_popen) {
        orig_popen = dlsym(RTLD_NEXT, "popen");
    }
    
    char escaped[256];
    escape_json(escaped, command ? command : "", sizeof(escaped));
    send_event("exec", "popen", escaped);
    
    return orig_popen(command, type);
}

/* socket - create socket */
int socket(int domain, int type, int protocol) {
    if (!orig_socket) {
        orig_socket = dlsym(RTLD_NEXT, "socket");
    }
    
    /* Don't log our own Unix socket connections */
    if (domain != AF_UNIX) {
        char details[64];
        snprintf(details, sizeof(details), "domain=%d type=%d", domain, type);
        send_event("network", "socket", details);
    }
    
    return orig_socket(domain, type, protocol);
}

/* connect - connect to remote */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) {
        orig_connect = dlsym(RTLD_NEXT, "connect");
    }
    
    /* Don't log Unix socket connections (our own socket) */
    if (addr && addr->sa_family != AF_UNIX) {
        send_event("network", "connect", "");
    }
    
    return orig_connect(sockfd, addr, addrlen);
}

/* bind - bind to address */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_bind) {
        orig_bind = dlsym(RTLD_NEXT, "bind");
    }
    
    if (addr && addr->sa_family != AF_UNIX) {
        send_event("network", "bind", "");
    }
    
    return orig_bind(sockfd, addr, addrlen);
}

/* open - open file */
int open(const char *pathname, int flags, ...) {
    if (!orig_open) {
        orig_open = dlsym(RTLD_NEXT, "open");
    }
    
    /* Only log writes to sensitive paths */
    if (pathname && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))) {
        if (strstr(pathname, "/etc/") || 
            strstr(pathname, "/.ssh/") ||
            strstr(pathname, "/bin/") ||
            strstr(pathname, "/sbin/") ||
            strstr(pathname, "cron") ||
            strstr(pathname, ".bashrc") ||
            strstr(pathname, ".profile")) {
            
            char escaped[256];
            escape_json(escaped, pathname, sizeof(escaped));
            send_event("file", "open", escaped);
        }
    }
    
    /* Handle variadic arguments */
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return orig_open(pathname, flags, mode);
    }
    
    return orig_open(pathname, flags);
}

/* fopen - open file stream */
FILE *fopen(const char *pathname, const char *mode) {
    if (!orig_fopen) {
        orig_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    
    /* Only log writes */
    if (pathname && mode && (strchr(mode, 'w') || strchr(mode, 'a'))) {
        if (strstr(pathname, "/etc/") || 
            strstr(pathname, "/.ssh/") ||
            strstr(pathname, "/bin/") ||
            strstr(pathname, "cron") ||
            strstr(pathname, ".bashrc")) {
            
            char escaped[256];
            escape_json(escaped, pathname, sizeof(escaped));
            send_event("file", "fopen", escaped);
        }
    }
    
    return orig_fopen(pathname, mode);
}

/* unlink - delete file */
int unlink(const char *pathname) {
    if (!orig_unlink) {
        orig_unlink = dlsym(RTLD_NEXT, "unlink");
    }
    
    char escaped[256];
    escape_json(escaped, pathname ? pathname : "", sizeof(escaped));
    send_event("file", "unlink", escaped);
    
    return orig_unlink(pathname);
}

/* remove - delete file */
int remove(const char *pathname) {
    if (!orig_remove) {
        orig_remove = dlsym(RTLD_NEXT, "remove");
    }
    
    char escaped[256];
    escape_json(escaped, pathname ? pathname : "", sizeof(escaped));
    send_event("file", "remove", escaped);
    
    return orig_remove(pathname);
}

/* ptrace - process tracing */
long ptrace(int request, ...) {
    if (!orig_ptrace) {
        orig_ptrace = dlsym(RTLD_NEXT, "ptrace");
    }
    
    char details[64];
    snprintf(details, sizeof(details), "request=%d", request);
    send_event("injection", "ptrace", details);
    
    /* Handle variadic arguments */
    va_list args;
    va_start(args, request);
    pid_t pid = va_arg(args, pid_t);
    void *addr = va_arg(args, void*);
    void *data = va_arg(args, void*);
    va_end(args);
    
    return orig_ptrace(request, pid, addr, data);
}

/* chmod - change file permissions */
int chmod(const char *pathname, mode_t mode) {
    if (!orig_chmod) {
        orig_chmod = dlsym(RTLD_NEXT, "chmod");
    }
    
    char details[256];
    char escaped[200];
    escape_json(escaped, pathname ? pathname : "", sizeof(escaped));
    snprintf(details, sizeof(details), "%s mode=%o", escaped, mode);
    send_event("file", "chmod", details);
    
    return orig_chmod(pathname, mode);
}

/* chown - change file owner */
int chown(const char *pathname, uid_t owner, gid_t group) {
    if (!orig_chown) {
        orig_chown = dlsym(RTLD_NEXT, "chown");
    }
    
    char details[256];
    char escaped[200];
    escape_json(escaped, pathname ? pathname : "", sizeof(escaped));
    snprintf(details, sizeof(details), "%s uid=%d gid=%d", escaped, owner, group);
    send_event("file", "chown", details);
    
    return orig_chown(pathname, owner, group);
}

/* setuid - set user ID */
int setuid(uid_t uid) {
    if (!orig_setuid) {
        orig_setuid = dlsym(RTLD_NEXT, "setuid");
    }
    
    char details[64];
    snprintf(details, sizeof(details), "uid=%d", uid);
    send_event("privilege", "setuid", details);
    
    return orig_setuid(uid);
}

/* setgid - set group ID */
int setgid(gid_t gid) {
    if (!orig_setgid) {
        orig_setgid = dlsym(RTLD_NEXT, "setgid");
    }
    
    char details[64];
    snprintf(details, sizeof(details), "gid=%d", gid);
    send_event("privilege", "setgid", details);
    
    return orig_setgid(gid);
}

/* fork - create child process */
pid_t fork(void) {
    if (!orig_fork) {
        orig_fork = dlsym(RTLD_NEXT, "fork");
    }
    
    send_event("process", "fork", "");
    
    pid_t pid = orig_fork();
    
    /* In child process, reinitialize socket */
    if (pid == 0) {
        g_socket_fd = -1;
        g_initialized = 0;
    }
    
    return pid;
}

/* Constructor - called when library is loaded */
__attribute__((constructor))
static void tracer_init(void) {
    init_socket();
}

/* Destructor - called when library is unloaded */
__attribute__((destructor))
static void tracer_fini(void) {
    if (g_socket_fd >= 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
    }
}

