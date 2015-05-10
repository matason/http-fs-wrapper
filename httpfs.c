/*
 * gcc -Wall -nostartfiles -fpic -shared -o httpfs.so httpfs.c func32.c -ldl $(curl-config --libs)
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE

#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <errno.h>
#include <curl/curl.h>
#include <time.h>

#include <stdarg.h>

#define IS_SUPPORTED_URL(path) (!strncmp((path), "http://", sizeof("http://")-1) || !strncmp((path), "https://", sizeof("https://")-1))

/* XXX: do parallel support for open AND open64 by #undef open etc .. */

#define RESOLVE(x)	if (!o_##x && !(o_##x = dlsym(RTLD_NEXT, #x))) { fprintf(stderr, #x"() not found!\n"); exit(-1); }
#define DEBUGF(a...)	if (debug) { fprintf(stderr, "%s: ", __FUNCTION__); fprintf(stderr, ##a); }

#define min(x,y) ( (x)<(y)?(x):(y) )
#define max(x,y) ( (x)>(y)?(x):(y) )

typedef struct {
    void *buf;
    size_t size;
    off_t offset;
    int fd;
} read_buffer_t;

typedef struct {
    int fd;
    char *url;
    CURL *curl;
    size_t size;
    off_t offset;
    time_t mtime;
    off_t ra_fileoffset;
    void *ra_buf;
    off_t ra_offset;
    size_t ra_size;
    int flags;
    int refcount;
} intercept_t;

#define READAHEAD_MAX 128*1024

/* XXX: need to handle this differently .. linked list? */
#define HIGHEST_FD 256
static intercept_t *intercept[HIGHEST_FD];
#define FEAT_RANGE_SUPPORT 1

static int (*o_open64)(const char *, int, ...);
static ssize_t (*o_read)(int, void *, size_t);
static __off64_t (*o_lseek64)(int, __off64_t, int);
static int (*o_close)(int);

static FILE *(*o_fopen64)(const char *, const char *);
static size_t (*o_fread)(void *, size_t, size_t, FILE *);
static int (*o_fseeko64)(FILE *, __off64_t, int);
static int (*o_fclose)(FILE *);
static long int (*o_ftell)(FILE *);
static __off64_t (*o_ftello64)(FILE *stream);
static int (* o_dup2)(int, int);
static ssize_t (* o___getdelim)(char **, size_t *, int, FILE *);

static int (*o___xstat64)(int, const char *, struct stat64 *);
static int (*o___fxstat64)(int, int, struct stat64 *);
static int (*o___lxstat64)(int, const char *, struct stat64 *);

static int debug=0;

void _init(void)
{
    if (getenv("DEBUG"))
	debug=1;
}

#define NUMBUFSIZE 60
static char numbuf[NUMBUFSIZE];
char *str_off_t(__off64_t t)
{
    char *p=numbuf+sizeof(numbuf)-1;
    int isneg=0;

    if (t < 0)
    {
        t= -t;
        isneg=1;
    }

    *p=0;
    do
    {
        *--p= '0' + (t % 10);
        t=t / 10;
    } while(t);

    if (isneg)
        *--p='-';

    return p;
}

size_t _curl_parse_header(void *source, size_t size, size_t nmemb, void *userData)
{
    intercept_t *obj=(intercept_t *)userData;
    size_t len = size * nmemb;
    char *p;

    if (!(p = strchr(source, ':')))
	return len;

    do { p++; } while (*p == ' ');

    if (!strncasecmp(source, "Content-Length", sizeof("Content-Length")-1))
    {
	obj->size = atoll(p);
	DEBUGF("detected obj->size: %zu\n", obj->size);
    }
    else if (!strncasecmp(source, "Accept-Ranges", sizeof("Accept-Ranges")-1) && !strncasecmp(p, "bytes", sizeof("bytes")-1))
    {
	obj->flags |= FEAT_RANGE_SUPPORT;
	DEBUGF("detected byte range sup port\n");
    }
    else if (!strncasecmp(source, "Last-Modified", sizeof("Last-Modified")-1))
    {
	/* stolen from wget source */
	static const char *time_formats[] = {
	    "%a, %d %b %Y %T",          /* RFC1123: Thu, 29 Jan 1998 22:12:57 */
	    "%A, %d-%b-%y %T",          /* RFC850:  Thursday, 29-Jan-98 22:12:57 */
	    "%a, %d-%b-%Y %T",          /* pseudo-RFC850:  Thu, 29-Jan-1998 22:12:57
	                                   (google.com uses this for their cookies.) */
	    "%a %b %d %T %Y"            /* asctime: Thu Jan 29 22:12:57 1998 */
	};

	int i;
	char *leftover;
	struct tm t;

	t.tm_isdst = 0;

#define countof(array) (sizeof (array) / sizeof (*(array)))
	for (i = 0; i < countof(time_formats); i++)
	{
	    DEBUGF("checking %s against %s\n", p, time_formats[i]);

	    if ((leftover = strptime(p, time_formats[i], &t))
		&& !strncmp(leftover, " GMT", sizeof(" GMT")-1)
		&& (obj->mtime = timegm(&t)))
	    {
		DEBUGF("matched: %s\n", asctime(&t));
		break;
	    }
	}
    }

    return len;
}

size_t _curl_output_null(void *source, size_t size, size_t nmemb, void *userData)
{
    return size * nmemb;
}

size_t _curl_output_buf(void *source, size_t size, size_t nmemb, void *userData)
{
    off_t remaining;
    off_t len = size * nmemb;
    read_buffer_t *read_buf = (read_buffer_t *)userData;
    intercept_t *obj = intercept[read_buf->fd];

    if (obj->ra_buf)
    {
	remaining = min(len, obj->ra_size - obj->ra_offset);

	if (remaining > 0)
	{
	    DEBUGF("adding %s bytes to ra buffer %p\n", str_off_t(remaining), read_buf->buf);
	    memcpy(obj->ra_buf + obj->ra_offset, source, remaining);
	    obj->ra_offset += remaining;
	}
    }

    remaining = min(len, read_buf->size - read_buf->offset);

    if (remaining > 0)
    {
	DEBUGF("adding %s bytes to buffer %p\n", str_off_t(remaining), read_buf->buf);
	memcpy(read_buf->buf + read_buf->offset, source, remaining);
	read_buf->offset += remaining;
    }

    return len;
}

int _intercept_open(const char *pathname)
{
    int fd;
    CURLcode ret;
    intercept_t *obj;
    long status;

    RESOLVE(open64);
    RESOLVE(close);

#define ERR_RETURN(err)	do { if (fd >= 0) o_close(fd); errno = err; return -1; } while (0);
#define CURL_SETOPT(option, value) if ((ret = curl_easy_setopt(obj->curl, option, value)) != CURLE_OK) ERR_RETURN(EACCES);

    if ((fd = o_open64("/dev/null", O_RDONLY, 0644)) < 0)
	ERR_RETURN(errno);

    DEBUGF("new fd=%d\n", fd);

    if (fd > HIGHEST_FD)
	ERR_RETURN(EMFILE);

    if (!(obj = calloc(1, sizeof(intercept_t))))
	ERR_RETURN(ENOMEM);

    obj->refcount = 1;
    obj->url = strdup(pathname);

    if (!(obj->curl = curl_easy_init()))
	ERR_RETURN(ENOMEM);

    if (getenv("DEBUG"))
	CURL_SETOPT(CURLOPT_VERBOSE, 0x1);

    CURL_SETOPT(CURLOPT_URL, obj->url);
    CURL_SETOPT(CURLOPT_NOBODY, 0x1);
    CURL_SETOPT(CURLOPT_WRITEHEADER, obj);
    CURL_SETOPT(CURLOPT_HEADERFUNCTION, _curl_parse_header);
    CURL_SETOPT(CURLOPT_WRITEFUNCTION, _curl_output_null);

    if ((ret = curl_easy_perform(obj->curl)) != CURLE_OK)
	ERR_RETURN(EACCES);

    if ((ret = curl_easy_getinfo(obj->curl, CURLINFO_RESPONSE_CODE, &status)) != CURLE_OK || status != 200)
	ERR_RETURN(ENOENT);

    DEBUGF("curl_easy_perform succeeded\n");

    if (!obj->size || !(obj->flags & FEAT_RANGE_SUPPORT))
    {
	DEBUGF("unacceptable resource: size=%zu, flags=%d\n", obj->size, obj->flags);
	ERR_RETURN(ENXIO);
    }

    CURL_SETOPT(CURLOPT_WRITEHEADER, NULL);
    CURL_SETOPT(CURLOPT_HEADERFUNCTION, NULL);

#undef CURL_SETOPT

    intercept[fd] = obj;

    errno = 0;
    return fd;
}

size_t _intercept_read(int fd, void *buf, size_t count)
{
    char range[512];
    char *start, *finish;
    read_buffer_t read_buf;
    CURLcode ret;
    intercept_t *obj = intercept[fd];
    off_t ra_size;
    long status;

    /* no point reading if we're already at the file boundary */
    if (obj->offset >= obj->size)
	return 0;

    /* don't read over file boundary */
    count = min(obj->size - obj->offset, count);

    /* satisfy from existing readahead buffer if possible */
    if (obj->ra_buf
	&& obj->offset >= obj->ra_fileoffset
	&& obj->offset+count <= obj->ra_fileoffset+obj->ra_size)
    {
	off_t bo = obj->offset - obj->ra_fileoffset;
	memcpy(buf, obj->ra_buf+bo, count);
	obj->offset += count;
	return count;
    }

    /* work out how much we'd like to read ahead */
    ra_size = min(obj->size - obj->offset, READAHEAD_MAX);

    /* format string for range request (inclusive) */
    start = strdup(str_off_t(obj->offset));
    finish = strdup(str_off_t(obj->offset+max(ra_size, count)-1));
    snprintf(range, sizeof(range), "%s-%s", start, finish);
    free(start);
    free(finish);

    /* initialize structure used in _curl_output_buf */
    read_buf.fd = fd;
    read_buf.buf = buf;
    read_buf.size = count;
    read_buf.offset = 0;

    /* throw old readahead buffer away, it didn't cut the mustard */
    if (obj->ra_buf)
    {
	free(obj->ra_buf);
	obj->ra_buf = 0;
    }

    /* someone set us up the bomb */
    if (ra_size > count && (obj->ra_buf = calloc(1, ra_size)))
    {
	obj->ra_size = ra_size;
	obj->ra_offset = 0;
	obj->ra_fileoffset = obj->offset;
    }

#define CURL_SETOPT(option, value) if ((ret = curl_easy_setopt(obj->curl, option, value)) != CURLE_OK) return -1;

    /* setup curl and do request */
    CURL_SETOPT(CURLOPT_HTTPGET, 0x1);
    CURL_SETOPT(CURLOPT_NOBODY, 0x0);
    CURL_SETOPT(CURLOPT_RANGE, range);
    CURL_SETOPT(CURLOPT_WRITEDATA, &read_buf);
    CURL_SETOPT(CURLOPT_WRITEFUNCTION, _curl_output_buf);

    if ((ret = curl_easy_perform(obj->curl)) != CURLE_OK)
	return -1;

    if ((ret = curl_easy_getinfo(obj->curl, CURLINFO_RESPONSE_CODE, &status)) != CURLE_OK || status != 206)
	return -1;

#undef CURL_SETOPT

    DEBUGF("read succeeded. length=%s\n", str_off_t(read_buf.offset));

    /* move offset with read */
    obj->offset += read_buf.offset;

    return read_buf.offset;
}

int _intercept_close(fd)
{
    if (!intercept[fd])
	return -1;

    if (--intercept[fd]->refcount)
        return 0;

    DEBUGF("closing %d\n", fd);

    curl_easy_cleanup(intercept[fd]->curl);
    free(intercept[fd]->url);
    free(intercept[fd]);
    intercept[fd] = 0;

    return 0;
}

void _intercept_stat(int fd, struct stat64 *buf)
{
    buf->st_dev = 0;
    buf->st_ino = 0;
    buf->st_mode = S_IFREG|S_IRUSR|S_IRGRP|S_IROTH;
    buf->st_nlink = 1;
    buf->st_uid = buf->st_gid = 0;
    buf->st_rdev = 0;
    buf->st_size = intercept[fd]->size;
    buf->st_blksize = 4096;
    buf->st_blocks = (intercept[fd]->size / buf->st_blksize)+1;
    if (intercept[fd]->mtime)
    {
	buf->st_atime = intercept[fd]->mtime;
	buf->st_mtime = intercept[fd]->mtime;
	buf->st_ctime = intercept[fd]->mtime;
    }
    else
	buf->st_atime = buf->st_mtime = buf->st_ctime = time(NULL);
}

off_t _intercept_seek(int fd, off_t offset, int whence)
{
    switch (whence) {
    case SEEK_SET:
	intercept[fd]->offset = offset;
	break;
    case SEEK_CUR:
	intercept[fd]->offset += offset;
	break;
    case SEEK_END:
	intercept[fd]->offset = intercept[fd]->size + offset;
	break;
    default:
	return (off_t)-1;
    };

    return intercept[fd]->offset;
}

int _intercept_dup2(int oldfd, int newfd)
{
    close(newfd);
    intercept[newfd] = intercept[oldfd];
    intercept[newfd]->refcount++;
    return newfd;
}

ssize_t _intercept_getdelim(int fd, char **lineptr, size_t *n, int delim)
{
    intercept_t *obj = intercept[fd];
    int counter = -1;
    char *c, *newbuf;

    *n = 1;
    *lineptr = malloc(*n);
    while (obj->offset < obj->size)
    {
        ++counter;
        if (counter >= *n)
        {
            if ((newbuf = realloc(*lineptr, *n  << 1)))
            {
                *n = *n << 1;
                *lineptr = newbuf;
            }
            else
            {
              	return -1;
            }

        }
        c = *lineptr + counter;
        _intercept_read(fd, c, nc);
        if (*c == delim)
        {
           break;
        }
    }
    if (counter > -1)
    {
        *(*lineptr + ++counter) = '\0';
    }
    return counter;
}

int open64(const char *pathname, int flag, ...)
{
    va_list ap;
    va_start(ap, flag);
    mode_t mode = 0;

    if (flag & O_CREAT)
        mode = va_arg(ap, mode_t);
    va_end(ap);

    if (IS_SUPPORTED_URL(pathname))
    {
	DEBUGF("pathname=%s, flag=%d\n", pathname, flag);

	if ((flag & O_ACCMODE) != O_RDONLY)
	{
	    errno = EACCES;
	    return -1;
	}

	return _intercept_open(pathname);
    }

    RESOLVE(open64);
    return o_open64(pathname, flag, mode);
}

FILE *fopen64(const char *pathname, const char *mode)
{
    if (IS_SUPPORTED_URL(pathname))
    {
	int fd;
	FILE *ret = 0;

	DEBUGF("pathname=%s, mode=%s\n", pathname, mode);

	if ((fd = _intercept_open(pathname)) > 0)
	     ret = fdopen(fd, mode);

	return ret;
    }

    RESOLVE(fopen64);
    return o_fopen64(pathname, mode);
}

ssize_t read(int fd, void *buf, size_t count)
{
    if (intercept[fd])
    {
	DEBUGF("fd=%d, buf=%p, count=%zu\n", fd, buf, count);

	return _intercept_read(fd, buf, count);
    }

    RESOLVE(read);
    return o_read(fd, buf, count);
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    int fd = fileno(stream);

    if (intercept[fd])
    {
	DEBUGF("ptr=%p, size=%zu, nmemb=%zu, fd=%d", ptr, size, nmemb, fd);

	return _intercept_read(fd, ptr, size * nmemb);
    }

    RESOLVE(fread);
    return o_fread(ptr, size, nmemb, stream);
}

int __xstat64(int version, const char *file_name, struct stat64 *buf)
{
    if (IS_SUPPORTED_URL(file_name))
    {
	int fd;

	DEBUGF("version=%d, file_name=%s\n", version, file_name);

	if ((fd = _intercept_open(file_name)) < 0)
	    return -1;
	_intercept_stat(fd, buf);
	_intercept_close(fd);

	return 0;
    }

    RESOLVE(__xstat64);
    return o___xstat64(version, file_name, buf);
}

int __fxstat64(int version, int fd, struct stat64 *buf)
{
    if (intercept[fd])
    {
	DEBUGF("version=%d, fd=%d\n", version, fd);

	_intercept_stat(fd, buf);

	return 0;
    }

    RESOLVE(__fxstat64);
    return o___fxstat64(version, fd, buf);
}

int __lxstat64(int version, const char *file_name, struct stat64 *buf)
{
    if (IS_SUPPORTED_URL(file_name))
    {
	int fd;

	DEBUGF("version=%d, file_name=%s\n", version, file_name);

	if ((fd = _intercept_open(file_name)) < 0)
	    return -1;
	_intercept_stat(fd, buf);
	_intercept_close(fd);

	return 0;
    }

    RESOLVE(__lxstat64);
    return o___lxstat64(version, file_name, buf);
}

__off64_t lseek64 (int fd, __off64_t offset, int whence)
{
    if (intercept[fd])
    {
	DEBUGF("fd=%d, offset=%s, whence=%d\n", fd, str_off_t(offset), whence);

	return _intercept_seek(fd, offset, whence);
    }

    RESOLVE(lseek64);
    return o_lseek64(fd, offset, whence);
}

int fseeko64 (FILE *stream, __off64_t offset, int whence)
{
    int fd = fileno(stream);

    if (intercept[fd])
    {
	DEBUGF("fd=%d, offset=%s, whence=%d\n", fd, str_off_t(offset), whence);

	if (_intercept_seek(fd, offset, whence) < 0)
	    return EINVAL;

	return 0;
    }

    RESOLVE(fseeko64);
    return o_fseeko64(stream, offset, whence);
}

long int ftell(FILE *stream)
{
    int fd = fileno(stream);

    if (intercept[fd])
    {
	DEBUGF("fd=%d\n", fd);

	return intercept[fd]->offset;
    }

    RESOLVE(ftell);
    return o_ftell(stream);
}

__off64_t ftello64 (FILE *stream)
{
    int fd = fileno(stream);

    if (intercept[fd])
    {
	DEBUGF("fd=%d\n", fd);

	return intercept[fd]->offset;
    }

    RESOLVE(ftello64);
    return o_ftello64(stream);
}

int close(int fd)
{
    if (intercept[fd])
    {
	DEBUGF("fd=%d\n", fd);

	return _intercept_close(fd);
    }

    RESOLVE(close);
    return o_close(fd);
}

int fclose(FILE *stream)
{
    int fd = fileno(stream);

    if (intercept[fd])
    {
	DEBUGF("fd=%d\n", fd);

	return _intercept_close(fd);
    }

    RESOLVE(fclose);
    return o_fclose(stream);
}

int dup2(int oldfd, int newfd) {

    if (intercept[oldfd]) {
        return _intercept_dup2(oldfd, newfd);
    }

    RESOLVE(dup2)
    return o_dup2(oldfd, newfd);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    return getdelim(lineptr, n, '\n', stream);
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    return __getdelim(lineptr, n, delim, stream);
}

ssize_t __getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    int fd = fileno(stream);

    if (intercept[fd]) {
        return _intercept_getdelim(fd, lineptr, n, delim);
    }
    RESOLVE(__getdelim)
    return o___getdelim(lineptr, n, delim, stream);
}

