// Signed bundle fixture. All sockets and inventories belong to the test's
// private temporary root; it never registers a service or launches an app.
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef ROUTING_IDENTITY
#error ROUTING_IDENTITY is required
#endif
static int response(FILE *stream, const char *file) {
    FILE *input = fopen(file, "r");
    if (!input) return 70;
    int status;
    if (fscanf(input, "%d\n", &status) != 1) { fclose(input); return 71; }
    char body[8192] = {0};
    size_t size = fread(body, 1, sizeof(body) - 1, input);
    fclose(input);
    return fprintf(stream, "HTTP/1.1 %d Fixture\r\nContent-Length: %zu\r\n\r\n%s", status, size, body) < 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "version")) { puts("portablefs 1.2.3"); return 0; }
    if (argc == 2 && !strcmp(argv[1], "-version")) { puts("1.2.3"); return 0; }
    if ((argc == 2 && !strcmp(argv[1], "-identity-json")) ||
        (argc == 4 && !strcmp(argv[1], "lifecycle") && !strcmp(argv[2], "identity") && !strcmp(argv[3], "--json"))) {
        puts(ROUTING_IDENTITY); return 0;
    }
    if (argc != 4) return 64;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof(address.sun_path)) return 66;
    strcpy(address.sun_path, argv[1]);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 10)) return 67;
    puts("ready");
    for (;;) {
        int peer = accept(listener, NULL, NULL);
        if (peer < 0) return 68;
        FILE *stream = fdopen(peer, "r+");
        if (!stream) return 69;
        setvbuf(stream, NULL, _IONBF, 0);
        char line[4096], path[2048];
        while (fgets(line, sizeof(line), stream)) {
            if (sscanf(line, "%*s %2047s", path) != 1) break;
            while (fgets(line, sizeof(line), stream) && strcmp(line, "\r\n") != 0) {}
            printf("request %s\n", path);
            if (!strcmp(path, "/lifecycle/v1/identity")) { if (response(stream, argv[2])) break; }
            else if (!strcmp(path, "/lifecycle/v1/inventory")) { if (response(stream, argv[3])) break; }
            else if (!strcmp(path, "/v2/attaches")) fprintf(stream, "HTTP/1.1 200 Fixture\r\nContent-Length: 15\r\n\r\n{\"attaches\":[]}");
            else if (!strcmp(path, "/healthz")) fprintf(stream, "HTTP/1.1 200 Fixture\r\nContent-Length: 0\r\n\r\n");
            else fprintf(stream, "HTTP/1.1 404 Fixture\r\nContent-Length: 0\r\n\r\n");
        }
        fclose(stream);
    }
}
