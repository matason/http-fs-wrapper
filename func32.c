#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>

FILE *fopen64(const char *pathname, const char *mode);

FILE *fopen(const char *pathname, const char *mode) {
    return fopen64(pathname, mode);
}

int open64(const char *pathname, int flag, ...);

int open(const char *pathname, int flag, ...)
{
    va_list ap;
    va_start(ap, flag);
    mode_t mode = 0;

    if (flag & O_CREAT)
        mode = va_arg(ap, mode_t);
    va_end(ap);

    return open64(pathname, flag, mode);
}
