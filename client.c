#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <errno.h>

int main(int argc, char** argv) {
    int sock;
    struct sockaddr_in client_addr;
    char* ip_str;
    char* port_str;
    char* image_buffer;
    size_t image_size;
    size_t image_off = 0;
    int64_t port;
    int64_t entry;
    int64_t base;
    FILE* filp;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <ip(:port)>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    filp = fopen("output.bin", "w");
    if (filp == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    ip_str = strtok(argv[1], ":");
    port_str = strtok(NULL, ":");
    port = (port_str != NULL ? strtol(port_str, NULL, 10) : 2137);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }
    if (inet_aton(ip_str, &client_addr.sin_addr) != 1) {
        fprintf(stderr, "err: incorrect ip address\n");
        exit(EXIT_FAILURE);
    }
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons((uint32_t)port);
    if (connect(sock, (struct sockaddr*)&client_addr,
                sizeof(client_addr)) < 0)
    {
        perror("connect() failed");
        exit(EXIT_FAILURE);
    }
    ssize_t len = recv(sock, &image_size, sizeof(size_t), 0);
    if (len <= 0) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    image_buffer = malloc(image_size);
    if (image_buffer == NULL) {
        perror("malloc() failed");
        exit(EXIT_FAILURE);
    }
    len = 0;
    while (len < image_size) {
        size_t remain = image_size - len;
        ssize_t bread = 0;
        bread = recv(sock, image_buffer + len, remain, 0);
        if (bread <= 0) {
            perror("recv() failed");
            exit(EXIT_FAILURE);
        }
        len += bread;
    }
    if (len != image_size) {
        fprintf(stderr, "image size mismatch\n");
        exit(EXIT_FAILURE);
    }
    close(sock);
    printf("read %zu bytes of payload\n", len);
    //printf("raw image size %llx\n", image_size - 24);
    if (image_size < 24) {
        fprintf(stderr, "invalid image\n");
        exit(EXIT_FAILURE);
    }
    if (strncmp(image_buffer, "BEADFACE", 8) != 0) {
        fprintf(stderr, "invalid image magic\n");
        exit(EXIT_FAILURE);
    }
    base = *(((uint64_t*)image_buffer) + 2);
    entry = *(((uint64_t*)image_buffer) + 1);
    uint64_t end_address = base + (image_size - 24);
    uint64_t page_base = (base & ~0xffff);
    uint64_t page_end = ((end_address + 0xffff) & ~0xffff);
    printf("attempting to allocate 0x%llx-0x%llx (%lld bytes) |",
            page_base, page_end, page_end - page_base);
    void* page_ptr = mmap((void*)page_base, page_end - page_base,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANON | MAP_PRIVATE /*| MAP_FIXED */, -1, 0);
    printf(" got %p\n", page_ptr);
    if (page_ptr == MAP_FAILED) {
        perror("mmap() failed");
        exit(EXIT_FAILURE);
    }
    if (base != (uint64_t)page_ptr) {
        printf("rebasing to assigned memory at %p\n", page_ptr);
        base = (uint64_t)page_ptr;
    }
    entry += base;
    memcpy(page_ptr, image_buffer + 24, image_size - 24);
    printf("jumping to entry at 0x%llx + 0x%llx (0x%llx)\n",
           base, entry - base, entry);

    ((void (*)(void))entry)();
    return 0;
}
