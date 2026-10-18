//go:build darwin && cgo

#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

// These XNU SPI declarations are exported by libSystem but omitted from the SDK.
#define CS_OPS_STATUS 0
#define CS_OPS_CDHASH 5
#define CS_VALID 0x00000001
#define CS_RUNTIME 0x00010000
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);

int portablefs_capture_socket_peer_witness(
    int fd,
    uint32_t token_out[8],
    int *pid_out,
    int *pid_version_out,
    uint32_t *euid_out,
    char **path_out
) {
    if (fd < 0 || token_out == NULL || pid_out == NULL ||
        pid_version_out == NULL || euid_out == NULL || path_out == NULL) {
        return EINVAL;
    }
    *path_out = NULL;
    audit_token_t token;
    socklen_t token_size = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &token_size) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if (token_size != sizeof(token)) {
        return EPROTO;
    }
    int pid = audit_token_to_pid(token);
    pid_t socket_pid = 0;
    socklen_t pid_size = sizeof(socket_pid);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &socket_pid, &pid_size) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if (pid_size != sizeof(socket_pid) || socket_pid != pid) { return EPROTO; }
    int pid_version = audit_token_to_pidversion(token);
    uid_t euid = audit_token_to_euid(token);
    if (pid <= 0 || pid_version <= 0) {
        return EPROTO;
    }
    char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(path, 0, sizeof(path));
    int path_length = proc_pidpath_audittoken(&token, path, sizeof(path));
    if (path_length <= 0 || path[0] != '/' || memchr(path, '\0', sizeof(path)) == NULL) {
        return errno != 0 ? errno : EPROTO;
    }
    char *copy = strdup(path);
    if (copy == NULL) {
        return ENOMEM;
    }
    memcpy(token_out, token.val, sizeof(token.val));
    *pid_out = pid;
    *pid_version_out = pid_version;
    *euid_out = (uint32_t)euid;
    *path_out = copy;
    return 0;
}

int portablefs_process_witness_matches(
    const uint32_t token_values[8],
    int pid,
    int pid_version,
    const char *expected_path,
    char **observed_path_out
) {
    if (token_values == NULL || pid <= 0 || pid_version <= 0 ||
        expected_path == NULL || expected_path[0] != '/' ||
        observed_path_out == NULL) {
        return -EINVAL;
    }
    *observed_path_out = NULL;
    audit_token_t token;
    memcpy(token.val, token_values, sizeof(token.val));
    if (audit_token_to_pid(token) != pid ||
        audit_token_to_pidversion(token) != pid_version) {
        return -EPROTO;
    }
    char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(path, 0, sizeof(path));
    errno = 0;
    int path_length = proc_pidpath_audittoken(&token, path, sizeof(path));
    if (path_length <= 0) {
        // The captured execution is gone (including pid reuse). This is an
        // ordinary mismatch; every other native inspection failure is fatal.
        if (errno == 0 || errno == ESRCH) {
            return 0;
        }
        return -errno;
    }
    if (path[0] != '/' || memchr(path, '\0', sizeof(path)) == NULL) {
        return -EPROTO;
    }
    char *copy = strdup(path);
    if (copy == NULL) {
        return -ENOMEM;
    }
    *observed_path_out = copy;
    return strcmp(path, expected_path) == 0 ? 1 : 0;
}

// The audit token pins pidversion as well as pid. Both operations inspect the
// running text vnode; reopening the executable pathname cannot establish this.
int portablefs_running_image(
    const uint32_t token_values[8], int pid, int pid_version,
    unsigned char cdhash_out[20]
) {
    if (token_values == NULL || pid <= 0 || pid_version <= 0 || cdhash_out == NULL) {
        return EINVAL;
    }
    audit_token_t token;
    memcpy(token.val, token_values, sizeof(token.val));
    if (audit_token_to_pid(token) != pid || audit_token_to_pidversion(token) != pid_version) {
        return EPROTO;
    }
    uint32_t flags = 0;
    if (csops_audittoken(pid, CS_OPS_STATUS, &flags, sizeof(flags), &token) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if ((flags & (CS_VALID | CS_RUNTIME)) != (CS_VALID | CS_RUNTIME)) {
        return EAUTH;
    }
    if (csops_audittoken(pid, CS_OPS_CDHASH, cdhash_out, 20, &token) != 0) {
        return errno != 0 ? errno : EIO;
    }
    // Recheck validity after reading the hash; every query uses the same token.
    flags = 0;
    if (csops_audittoken(pid, CS_OPS_STATUS, &flags, sizeof(flags), &token) != 0) {
        return errno != 0 ? errno : EIO;
    }
    return (flags & (CS_VALID | CS_RUNTIME)) == (CS_VALID | CS_RUNTIME) ? 0 : EAUTH;
}
