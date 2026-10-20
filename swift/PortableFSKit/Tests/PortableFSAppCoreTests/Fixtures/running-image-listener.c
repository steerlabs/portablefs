// A native, independently signed execution for audit-token authentication.
// Readiness follows listen(2), so no connection races socket publication.
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (argc != 2 || strlen(argv[1]) >= sizeof(address.sun_path)) return 64;
    strcpy(address.sun_path, argv[1]);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0) {
        perror("listener");
        return 65;
    }
    if (write(STDOUT_FILENO, "R", 1) != 1) return 66;
    // Keep the listening socket and accepted peer alive until the test stops
    // this execution; no application protocol is involved in these proofs.
    if (accept(listener, NULL, NULL) < 0) return 67;
    for (;;) pause();
}
