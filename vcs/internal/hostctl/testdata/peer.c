// Native socket fixture: kernel audit tokens and running-image signatures are
// real. This fixture does not stand in for signed shipping-bundle validation.
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef IMAGE
#define IMAGE "A"
#endif
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    setvbuf(stdout, NULL, _IOLBF, 0);
    FILE *identity_file = fopen(argv[2], "r");
    if (!identity_file) return 65;
    char identity[2048] = {0};
    size_t identity_size = fread(identity, 1, sizeof(identity)-1, identity_file);
    fclose(identity_file);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof(address.sun_path)) return 66;
    strcpy(address.sun_path, argv[1]);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 10)) return 67;
    printf("ready " IMAGE "\n");
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
            const char *body = "";
            int status = 200;
            if (!strcmp(path, "/lifecycle/v1/identity")) body = identity;
            else if (!strcmp(path, "/lifecycle/v1/inventory")) body = "{\"attachment_count\":0}";
            else if (!strcmp(path, "/lifecycle/v1/stop-if-idle")) status = 204;
            else if (!strcmp(path, "/v2/attaches")) body = "{\"attaches\":[]}";
            else if (strcmp(path, "/healthz")) status = 404;
            fprintf(stream, "HTTP/1.1 %d Test\r\nContent-Length: %zu\r\n\r\n%s", status, strlen(body), body);
        }
        fclose(stream);
    }
    return identity_size == 0;
}
