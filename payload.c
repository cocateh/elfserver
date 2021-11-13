#define BSD_SYSCALL_MASK 2 << 24

#define SYSCALL_EXIT 1
#define SYSCALL_WRITE 4

#define BSD_SYSCALL(x) BSD_SYSCALL_MASK | (0xFF & x)

void exit(int exit_code) {
    asm volatile ("movabsq %0, %%rax\n\t"
                  "movq %1, %%rdi\n\t"
                  "syscall"
                  :
                  : "g" (BSD_SYSCALL(SYSCALL_EXIT)), "g" (exit_code));
}

long write(int fd, const char* buf, unsigned long count) {
    long ret;
    asm volatile ("movabsq %1, %%rax\n\t"
                  "mov %2, %%rdi\n\t"
                  "movq %3, %%rsi\n\t"
                  "movq %4, %%rdx\n\t"
                  "syscall\n\t"
                  "mov %%rax, %0"
                  : "=r" (ret)
                  : "g" (BSD_SYSCALL(SYSCALL_WRITE)), "g" (fd),
                    "g" (buf), "g" (count));

}

void _start(void) {
    write(0, "Hello, world\n", 13);
    exit(123);
}
