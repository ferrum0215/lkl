#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <libgen.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>

#include <vector>
#include <iostream>
#include <cstdio>
#include <string>
#include <stdexcept>
#include <experimental/filesystem>
#include <errno.h>
#include <signal.h>

#include <zlib.h>
#include <sys/sendfile.h>

#include "executor.hpp"
#include "Program.hpp"

#define PAGE_SIZE 4096
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

#define gettid() syscall(SYS_gettid)

__AFL_FUZZ_INIT();
__AFL_COVERAGE();

namespace fs = std::experimental::filesystem;

static const char doc_executor[] = "File system fuzzing executor";
static const char args_doc_executor[] = "-t fstype -i fsimage_path -e emulator_path -d tmp_prefix -p program_path (-f) (-r) (-v)";

static struct argp_option options[] = {
    {"enable-printk", 'v', 0, 0, "show Linux printks"},
    {"filesystem-type", 't', "string", 0, "select filesystem type - mandatory"},
    {"filesystem-image", 'i', "string", 0, "path to the filesystem image - mandatory"},
    {"no-sigraise", 'n', 0, 0, "Do not raise SIGUSR2"},
    {0},
};

static struct cl_args {
    int printk;
    int emul_verbose;
    int part;
    int no_sigraise;
    const char *fsimg_type;
    const char *fsimg_path;
} cla;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct cl_args *cla = (struct cl_args*)state->input;

    switch (key) {
        case 'v':
            cla->printk = 0;
            cla->emul_verbose = 1;
            break;
        case 't':
            cla->fsimg_type = arg;
            break;
        case 'i':
            cla->fsimg_path = arg;
            break;
        case 'n':
            cla->no_sigraise = 1;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp_executor = {
    .options = options,
    .parser = parse_opt,
    .args_doc = args_doc_executor,
    .doc = doc_executor,
};

static void exec_syscall(Program *prog, Syscall *syscall) {

    long params[6];
    long ret;
    int cnt = 0;

    for (Arg *arg : syscall->args) {
        if (!arg->is_variable)
            params[cnt] = arg->value;
        else {
            Variable *v = prog->variables[arg->index];
            if (v->is_pointer() && v->value == 0)
                v->value = static_cast<uint8_t*>(malloc(v->size));
            params[cnt] = reinterpret_cast<long>(v->value);
        }
        cnt++;
    }

    /* ret = lkl_syscall(lkl_syscall_nr[syscall->nr], params); */
    ret = handle_syscalls(syscall->nr, params);
    if (syscall->ret_index != -1)
        prog->variables[syscall->ret_index]->value = reinterpret_cast<uint8_t*>(ret);

    // show_syscall(prog, syscall);
    // printf("ret: %ld\n", ret);
}

static void close_active_fds(Program *prog) {

    long params[6];

    for (int64_t fd_index : prog->active_fds) {
        params[0] = reinterpret_cast<long>(prog->variables[fd_index]->value);
        lkl_syscall(lkl_syscall_nr[SYS_close], params);
    }

}

struct arg_struct {
    long uffd;
    unsigned long base;
    void *buffer;
};

void *fault_handler_thread(void *arg) {
    struct arg_struct *args = (struct arg_struct *)arg;
    long uffd = args->uffd;
    void *buffer = args->buffer;
    unsigned long base = args->base;
    static struct uffd_msg msg;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    for (;;) {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0 || nread == -1) {
            fprintf(stderr, "error read on userfaultfd!\n");
            _exit(1);
        }

        unsigned long offset = (msg.arg.pagefault.address & ~(PAGE_SIZE - 1)) - base;
        uffdio_copy.src = (unsigned long)(buffer) + offset;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        uffdio_copy.len = PAGE_SIZE;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) _exit(1);
    }
}

void *userfault_init(void *image_buffer, size_t size) {
    long uffd;
    size_t len = size;
    pthread_t thr;
    struct uffdio_register uffdio_register;
    struct uffdio_api uffdio_api;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    void *buffer = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED)
        errExit("mmap");

    uffdio_register.range.start = (unsigned long) buffer;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("register uffd");

    static struct arg_struct args;
    args.buffer = image_buffer;
    args.uffd = uffd;
    args.base = (unsigned long) buffer;
    int s = pthread_create(&thr, NULL, fault_handler_thread, (void *)(&args));
    if (s != 0)
        errExit("pthread_create");

    return buffer;
}

int main(int argc, char **argv)
{
    __AFL_COVERAGE_OFF();

    unsigned char *data = __AFL_FUZZ_TESTCASE_BUF;
    size_t len = __AFL_FUZZ_TESTCASE_LEN;
    struct lkl_disk disk;
    long ret;
    long bug;
    char mpoint[32];
    unsigned int disk_id;

    struct stat st;

    int verbose = 0;

    cla.no_sigraise = 0;
    if (argp_parse(&argp_executor, argc, argv, 0, 0, &cla) < 0) {
        fprintf(stderr, "arg parse failed\n");
        return -1;
    }

    if (!cla.printk)
        lkl_host_ops.print = NULL;

    const char *mount_options = NULL;
    if (!strcmp(cla.fsimg_type, "btrfs"))
        mount_options = "thread_pool=1";
    else if (!strcmp(cla.fsimg_type, "gfs2"))
        mount_options = "acl";
    else if (!strcmp(cla.fsimg_type, "reiserfs"))
        mount_options = "acl,user_xattr";
    else if (!strcmp(cla.fsimg_type, "ext4"))
        mount_options = "errors=remount-ro";

    lstat(cla.fsimg_path, &st);

    disk.fd = open(cla.fsimg_path, O_RDONLY);
    if (disk.fd < 0) {
        fprintf(stderr, "disk open failed\n");
        return -1;
    }

    disk.ops = NULL;
    ret = lkl_init(&lkl_host_ops);
    if (ret < 0) {
        fprintf(stderr, "lkl init failed: %s\n", lkl_strerror(ret));
        close(disk.fd);
        return -1;
    }

    ret = lkl_disk_add(&disk);
    if (ret < 0) {
        fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
        lkl_sys_halt();
        close(disk.fd);
        return -1;
    }
    disk_id = ret;

    lkl_start_kernel("mem=2048M kasan.fault=report loglevel=8");

    __AFL_COVERAGE_DISCARD();
    __AFL_COVERAGE_ON();

    ret = lkl_mount_dev(disk_id, cla.part, cla.fsimg_type, 0,
            mount_options, mpoint, sizeof(mpoint));
    if (ret) {
        fprintf(stderr, "can't mount base img disk: %s\n", lkl_strerror(ret));
        lkl_sys_halt();
        lkl_disk_remove(disk);
        close(disk.fd);
        return -1;
    }

    ret = lkl_sys_chdir(mpoint);
    if (ret) {
        fprintf(stderr, "can't chdir to %s: %s\n", mpoint,
                lkl_strerror(ret));
        lkl_umount_dev(disk_id, cla.part, 0, 1000);
        lkl_disk_remove(disk);
        lkl_sys_halt();
        close(disk.fd);
        return -1;
    }

    Program *prog = Program::deserialize(data);
    int callcnt = 1;
    for (Syscall *syscall : prog->syscalls) {
        if (verbose)
            fprintf(stdout, "#%d", callcnt);
        exec_syscall(prog, syscall);
        callcnt++;
    }

    ret = lkl_sys_chdir("/");

    close_active_fds(prog);
    bug = lkl_umount_dev(disk_id, cla.part, 0, 7000);
    ret = lkl_disk_remove(disk);
    close(disk.fd);
    lkl_sys_halt();

    __AFL_COVERAGE_OFF();

    if (cla.emul_verbose)
        return 0;
    if (bug) {
        puts("bug!");
        // use SIGUSR2 for notifying the fuzzer of an umount bug
        fflush(NULL);
        if (!cla.no_sigraise)
            raise(SIGUSR2);
    }

    return 0;
}

