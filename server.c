#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define is_le() (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ? 1 : 2)

#define perrexit(str) do { \
                        perror(str); \
                        exit(EXIT_FAILURE); \
                     } while (0);

#define ferrexit(format, ...) do { \
                        fprintf(stderr, "err: " format "\n", ##__VA_ARGS__); \
                        exit(EXIT_FAILURE); \
                     } while (0);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define short_from_le(value) (value)
#define int_from_le(value) (value)
#define long_from_le(value) (value)
#define short_from_be(value) (((value & 0x00ff) << 8) | (value & 0xff00 >> 8))
#define int_from_be(value) (((value & 0x000000ff) << 24) | \
                         ((value & 0x0000ff00) << 8) | \
                         ((value & 0x00ff0000) >> 8) | \
                         ((value & 0xff000000) >> 24))
#define long_from_be(value) (((value & 0x00000000000000ff) << 56) | \
                         ((value & 0x000000000000ff00) << 40) | \
                         ((value & 0x0000000000ff0000) << 24) | \
                         ((value & 0x00000000ff000000) << 8) | \
                         ((value & 0xff00000000000000) >> 56) | \
                         ((value & 0x00ff000000000000) >> 40) | \
                         ((value & 0x0000ff0000000000) >> 24) | \
                         ((value & 0x000000ff00000000) >> 8))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define short_from_le(value) (((value & 0x00ff) << 8) | (value & 0xff00 >> 8))
#define int_from_le(value) (((value & 0x000000ff) << 24) | \
                          ((value & 0x0000ff00) << 8) | \
                          ((value & 0x00ff0000) >> 8) | \
                          ((value & 0xff000000) >> 24))
#define long_from_le(value) (((value & 0x00000000000000ff) << 56) | \
                         ((value & 0x000000000000ff00) << 40) | \
                         ((value & 0x0000000000ff0000) << 24) | \
                         ((value & 0x00000000ff000000) << 8) | \
                         ((value & 0xff00000000000000) >> 56) | \
                         ((value & 0x00ff000000000000) >> 40) | \
                         ((value & 0x0000ff0000000000) >> 24) | \
                         ((value & 0x000000ff00000000) >> 8))
#define short_from_be(value) (value)
#define int_from_be(value) (value)
#define long_from_be(value) (value)
#endif

#define PT_LOAD 1

const char ELF_MAGIC[4] = {0x7f, 'E', 'L', 'F'};
const char SRV_MAGIC[8] = {'B', 'E', 'A', 'D', 'F', 'A', 'C', 'E'};
//const char FELF_MAGIC[8] = {'F', 'E', 'L', 'F', '0', '0', '0', '1'};

struct load_segment {
    u64 vaddr;
    size_t data_size;
    void* data;
};

int addr_compare(const void* p, const void* q) {
    u64 left = (*(struct load_segment*)(p)).vaddr;
    u64 right = (*(struct load_segment*)(q)).vaddr;

    if (left < right)
        return -1;
    else if (left > right)
        return 1;
    else
        return 0;
}

/*
 * Read size bytes from filp with error handling for fread.
 */
void consume(FILE* filp, void* buf, size_t size, char* str) {
    fread(buf, size, 1, filp);
    if (ferror(filp))
        ferrexit("fread() failed: %s", str);
}

/*
 * Read size of endianess-dependant bytes from filp and convert to
 * machine native endianess.
 */
void ordered_consume(FILE* filp, void* buf, size_t size, char* str,
                            u8 endianess)
{
    consume(filp, buf, size, str);
    if (is_le() == endianess) {
        return;
    } else if (is_le() == 1 && endianess == 2) {
        switch (size) {
        case 2:
            *(u64*)buf = short_from_be(*(u64*)buf);
        case 4:
            *(u64*)buf = int_from_be(*(u64*)buf);
        case 8:
            *(u64*)buf = long_from_be(*(u64*)buf);
        }
    } else if (is_le() == 2 && endianess == 1) {
        switch (size) {
        case 2:
            *(u64*)buf = short_from_le(*(u64*)buf);
        case 4:
            *(u64*)buf = int_from_le(*(u64*)buf);
        case 8:
            *(u64*)buf = long_from_le(*(u64*)buf);
        }
    }
}

/*
 * Read a 64 bit value or 32 bit endianess-dependant bytes from filp
 * and convert to machine native endianess.
 */
void native_consume(FILE* filp, void* buf, u8 bitness, char* str, u8 endianess)
{
    ordered_consume(filp, buf, 4 * bitness, str, endianess);
}

/*
 * Read and parse an ELF file from filp and produce a simplified
 * image of LOAD sections to dst. If base == 0, the chosen base is
 * the lowest address of any of load sections.
 */
size_t consume_elf(char** dst, u64 base, FILE* filp) {
    u8 magic[4];
    u8 bitness;
    u8 endianess;
    u8 version;
    u8 abi;
    u8 abi_version;
    u16 file_type;
    u16 target_isa;
    u16 elf_header_size;
    u16 ph_header_size;
    u16 ph_count;
    u32 elf_version;
    u32 flags;
    u64 entry_addr;
    u64 ph_offset;
    u64 sh_offset;
    struct load_segment* ld_segments = NULL;
    size_t ld_count = 0;

    consume(filp, magic, 4, "ELF magic");
    if (strncmp(magic, ELF_MAGIC, 4) != 0)
        ferrexit("Incorrect magic");
    consume(filp, &bitness, 1, "bitness");
    consume(filp, &endianess, 1, "endianess");
    consume(filp, &version, 1, "version");
    if (version != 1)
        ferrexit("Incorrect version");
    consume(filp, &abi, 1, "abi");
    consume(filp, &abi_version, 1, "abi version");
    if (fseek(filp, 7, SEEK_CUR) == -1)
        perrexit("fseek() failed");

    ordered_consume(filp, &file_type, 2, "file type", endianess);
    ordered_consume(filp, &target_isa, 2, "target isa", endianess);
    ordered_consume(filp, &elf_version, 4, "elf version", endianess);
    native_consume(filp, &entry_addr, bitness, "entry address", endianess);
    native_consume(filp, &ph_offset, bitness, "program header offset", 
                   endianess);
    native_consume(filp, &sh_offset, bitness, "section header offset",
                   endianess);
    ordered_consume(filp, &flags, 4, "elf flags", endianess);
    ordered_consume(filp, &elf_header_size, 2, "elf header size", endianess);
    ordered_consume(filp, &ph_header_size, 2, "program header size",
                    endianess);
    ordered_consume(filp, &ph_count, 2, "program header entries", endianess);
    if (fseek(filp, ph_offset, SEEK_SET) == -1)
        perrexit("fseek() failed");

    for (int i = 0; i < ph_count; i++) {
        u32 header_type;
        u32 pt_flags;
        u64 pt_offset;
        u64 pt_vaddr;
        u64 pt_paddr;
        u64 pt_filesz;
        u64 pt_memsz;
        u64 pt_align;
        ordered_consume(filp, &header_type, 4, "program header type",
                        endianess);
        if (bitness == 2)
            ordered_consume(filp, &pt_flags, 4, "program header flags",
                            endianess);
        native_consume(filp, &pt_offset, bitness, "file image offset",
                       endianess);
        native_consume(filp, &pt_vaddr, bitness, "segment virtual address",
                       endianess);
        native_consume(filp, &pt_paddr, bitness, "segment physical addrress",
                       endianess);
        native_consume(filp, &pt_filesz, bitness, "segment file size",
                       endianess);
        native_consume(filp, &pt_memsz, bitness, "segment memory size", 
                       endianess);
        if (bitness == 1)
            ordered_consume(filp, &pt_flags, 4, "program header flags",
                            endianess);
        native_consume(filp, &pt_align, bitness, "segment alignment",
                       endianess);

        if (header_type == PT_LOAD) {
            struct load_segment* current_seg;
            ld_count++;
            ld_segments = realloc(ld_segments,
                                  sizeof(struct load_segment) * ld_count);
            current_seg = (ld_segments + (ld_count - 1));
            if (ld_segments == NULL)
                ferrexit("realloc() failed");
            current_seg->vaddr = pt_vaddr;
            current_seg->data_size = pt_memsz;
            current_seg->data = malloc(pt_memsz);
            if (current_seg->data == NULL)
                ferrexit("malloc() failed");

            memset(current_seg->data, 0, pt_memsz);
            if (pt_memsz < pt_filesz)
                ferrexit("file in memory bigger than file image");
            if (pt_filesz > 0) {
                long prev_pos = ftell(filp);
                if (fseek(filp, pt_offset, SEEK_SET) == -1)
                    perrexit("fseek() failed");
                consume(filp, current_seg->data,
                        pt_filesz, "load section data");
                if (fseek(filp, prev_pos, SEEK_SET) == -1)
                    perrexit("fseek() failed");
            }
        }
    }
    qsort(ld_segments, ld_count, sizeof(struct load_segment), addr_compare);

    u64 target_base = (base == 0 ? ld_segments->vaddr : base);
    u64 current_addr = target_base;
    size_t buf_pos = 0;
    size_t image_size = 0;
    char* new_dst = NULL;

    *dst = malloc(24);
    memcpy(*dst + buf_pos, SRV_MAGIC, 8);
    buf_pos += 8;
    memcpy(*dst + buf_pos, &entry_addr, 8);
    buf_pos += 8;
    memcpy(*dst + buf_pos, &target_base, 8);
    buf_pos += 8;
    image_size = buf_pos;

    for (int i = 0; i < ld_count; i++) {
        struct load_segment current_seg = (*(ld_segments + i));
        if (current_seg.vaddr < current_addr)
            ferrexit("overlapping sections");
        u64 offset = current_seg.vaddr - current_addr;
        if (offset > 0) {
            image_size += offset;
            new_dst = realloc(*dst, image_size);
            if (new_dst == NULL)
                ferrexit("realloc() failed");
            *dst = new_dst;
            memset(*dst + buf_pos, 0, offset);
            buf_pos += offset;
        }
        image_size += current_seg.data_size;
        new_dst = realloc(*dst, image_size);
        if (new_dst == NULL)
            ferrexit("realloc() failed");
        *dst = new_dst;
        memcpy(*dst + buf_pos, current_seg.data, current_seg.data_size);
        buf_pos += current_seg.data_size;
        current_addr = current_seg.vaddr + current_seg.data_size;
    }

    for (int i = 0; i < ld_count; i++) {
        struct load_segment* current_seg = (ld_segments + i);
        free(current_seg->data);
    }
    free(ld_segments);
    return image_size;
}

void serve(const char* image, size_t image_len, char* addr_str) {
    s32 sock;
    s32 client_sock;
    size_t client_len;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    char* ip_str = strtok(addr_str, ":");
    char* port_str = strtok(NULL, ":");
    s64 port = (port_str != NULL ? strtol(port_str, NULL, 10) : 2137 );
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
        perrexit("socket() failed");

    if (inet_aton(ip_str, &server_addr.sin_addr) != 1)
        ferrexit("incorrect ip address");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((u32)port);

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(struct sockaddr)) < 0)
        perrexit("bind() failed");
    if (listen(sock, 1) < 0)
        perrexit("listen() failed");

    printf("listening on %s\n", addr_str);
    for(;;) {
        client_len = sizeof(client_addr);
        if (client_sock = accept(sock, (struct sockaddr*)&client_addr,
                                 ((socklen_t*)&client_len)))
        {
            /*
            ssize_t len = send(client_sock, &image_len, sizeof(size_t), 0);
            if (len != sizeof(size_t)) {
                fprintf(stderr, "sent %d, expected %d\n", len, sizeof(size_t));
                goto size_mismatch;
            }
            len = send(client_sock, image, image_len, 0);
            if (len != image_len) {
                fprintf(stderr, "sent %d, expected %d\n", len, image_len);
                goto size_mismatch;
            }
            printf("sending %d bytes to %s\n", len,
                   inet_ntoa(client_addr.sin_addr));
            close(client_sock);
            */
            
            setpgrp();
            switch (fork()) {
            case -1:
                goto fork_failure;
            case 0:
                ssize_t len = send(client_sock, &image_len, sizeof(size_t), 0);
                if (len != sizeof(size_t)) {
                    fprintf(stderr, "sent %d, expected %d\n",
                            len, sizeof(size_t));
                    goto size_mismatch;
                }
                len = send(client_sock, image, image_len, 0);
                if (len != image_len) {
                    fprintf(stderr, "sent %d, expected %d\n",
                            len, image_len);
                    goto size_mismatch;
                }
                printf("served %d bytes to %s\n", len,
                       inet_ntoa(client_addr.sin_addr));
                close(client_sock);
                exit(EXIT_SUCCESS);
            }
        }
    }
    close(sock);

size_mismatch:
    close(client_sock);
    close(sock);
    ferrexit("sent size mismatch");

fork_failure:
    close(client_sock);
    close(sock);
    perrexit("fork() failed");
}

size_t read_imagefile(FILE* filp, char** buf) {
    size_t file_size = 0;
    fseek(filp, 0, SEEK_END);
    file_size = ftell(filp);
    *buf = malloc(file_size);
    fseek(filp, 0, SEEK_SET);
    fread(*buf, file_size, 1, filp);
    if (strncmp(*buf, SRV_MAGIC, 8) != 0)
        ferrexit("incorrect magic");
    return file_size;
}

size_t write_image_to_file(FILE* filp, char* image, size_t image_sz) {
    size_t written = fwrite(image, 8, image_sz, filp);
    if (written != image_sz)
        ferrexit("written %d, expected %d", written, image_sz);
    fflush(filp);
    return written;
}

void sig_handler(int signo, siginfo_t* info, void* context) {
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    FILE* filp;
    FILE* out;
    char* output_file = NULL;
    char* image = NULL;
    bool image_file = false;
    char* elf_filename;
    char* address_str;
    size_t image_sz = 0;
    u64 base_addr = 0;
    struct sigaction action = { 0 };

    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = &sig_handler;
    // Catch CTRL-C and close sockets
    if (sigaction(SIGINT, &action, NULL) == -1)
        perrexit("sigaction() failed");
    if (argc < 2)
        ferrexit("usage: %s <ip:port> <file>", argv[0]);

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [options] <ip:port> <file> \n\
additional options: \n\
        --output <file> : output created image to a file \n\
        --image: use input file as image\n", argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "--output") == 0 && !(i + 1 >= argc - 2)) {
            output_file = argv[i + 1];
        } else if (strcmp(argv[i], "--image") == 0) {
            image_file = true;
        }
    }
    elf_filename = argv[argc - 1];
    address_str  = argv[argc - 2];

    filp = fopen(elf_filename, "r");
    if (filp == NULL)
        perrexit("fopen() failed");
    if (image_file == true) {
        printf("using %s as ready image\n", elf_filename);
        image_sz = read_imagefile(filp, &image);
    } else {
        image_sz = consume_elf(&image, base_addr, filp);
    }

    if (output_file != NULL) {
        printf("outputting current input to %s\n", output_file);
        out = fopen(output_file, "w");
        if (out == NULL)
            perrexit("fopen() failed");
        write_image_to_file(out, image, image_sz);
    } else {
        serve(image, image_sz, address_str);
    }

    fclose(filp);
    return 0;
}
