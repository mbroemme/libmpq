/*
 *  mpq-file.c -- private file and directory operations.
 *
 *  Copyright (c) 2003-2026 Maik Broemme <mbroemme@libmpq.org>
 *
 *  This file is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This file is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this file; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpq-file.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* Both backends require the same 32-character random suffix placeholder. */
static int
valid_template(const char *suffix)
{
    size_t length;

    if (suffix == NULL)
        return 0;
    length = strlen(suffix);
    return length >= 32 && strcmp(suffix + length - 32, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX") == 0;
}

char *
libmpq__string_duplicate(const char *text)
{
    size_t size;

    if (text == NULL)
        return NULL;
    size = strlen(text) + 1;
    char *copy = malloc(size);

    if (copy != NULL)
        memcpy(copy, text, size);
    return copy;
}

int32_t
libmpq__file_seek(FILE *file, uint64_t offset, int origin)
{
    if (file == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (offset > INT64_MAX)
        return LIBMPQ_ERROR_SEEK;
#ifdef _WIN32
    return _fseeki64(file, (int64_t)offset, origin) == 0 ? 0 : LIBMPQ_ERROR_SEEK;
#else

    /* Check before narrowing on platforms with a smaller signed off_t. */
    if (sizeof(off_t) < sizeof(int64_t) &&
        offset > (UINT64_MAX >> (65U - sizeof(off_t) * CHAR_BIT)))
        return LIBMPQ_ERROR_SEEK;
    return fseeko(file, (off_t)offset, origin) == 0 ? 0 : LIBMPQ_ERROR_SEEK;
#endif
}

libmpq__off_t
libmpq__file_tell(FILE *file)
{
    if (file == NULL)
        return LIBMPQ_ERROR_EXIST;
#ifdef _WIN32
    int64_t position = _ftelli64(file);
#else
    off_t position = ftello(file);
#endif

    return position < 0 ? LIBMPQ_ERROR_SEEK : (libmpq__off_t)position;
}

#ifdef _WIN32

struct mpq_directory
{
    HANDLE handle;
};

static wchar_t *
wide_path(const char *path)
{
    int count;
    wchar_t *wide;

    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count == 0) {
        errno = EINVAL;
        return NULL;
    }
    wide = malloc((size_t)count * sizeof(*wide));
    if (wide != NULL)
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, count);
    return wide;
}

static FILE *
handle_stream(HANDLE handle, const char *mode)
{
    int flags = _O_BINARY | _O_NOINHERIT;
    int fd;
    FILE *file;

    if (strchr(mode, '+') != NULL)
        flags |= _O_RDWR;
    else if (mode[0] == 'w' || mode[0] == 'a')
        flags |= _O_WRONLY;
    else
        flags |= _O_RDONLY;
    if (mode[0] == 'a')
        flags |= _O_APPEND;
    fd = _open_osfhandle((intptr_t)handle, flags);

    if (fd < 0) {
        CloseHandle(handle);
        return NULL;
    }
    file = _fdopen(fd, mode);
    if (file == NULL)
        _close(fd);
    return file;
}

FILE *
libmpq__file_open(const char *path, const char *mode)
{
    wchar_t *wide;
    HANDLE handle;
    DWORD error;
    DWORD access;
    DWORD disposition;

    if (path == NULL || path[0] == '\0' || mode == NULL || mode[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    wide = wide_path(path);
    if (wide == NULL)
        return NULL;
    if (strchr(mode, '+') != NULL)
        access = GENERIC_READ | GENERIC_WRITE;
    else if (mode[0] == 'w' || mode[0] == 'a')
        access = GENERIC_WRITE;
    else
        access = GENERIC_READ;
    disposition = mode[0] == 'w' ? CREATE_ALWAYS : mode[0] == 'a' ? OPEN_ALWAYS : OPEN_EXISTING;
    handle = CreateFileW(
        wide, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, disposition,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    error = GetLastError();
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? ENOENT : EACCES;
        return NULL;
    }
    return handle_stream(handle, mode);
}

int32_t
libmpq__file_identity(FILE *file, uint64_t *device, uint64_t *inode)
{
    BY_HANDLE_FILE_INFORMATION info;

    if (device != NULL)
        *device = 0;
    if (inode != NULL)
        *inode = 0;
    if (file == NULL || device == NULL || inode == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (!GetFileInformationByHandle((HANDLE)_get_osfhandle(_fileno(file)), &info))
        return LIBMPQ_ERROR_OPEN;
    *device = info.dwVolumeSerialNumber;
    *inode = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    return 0;
}

/* Resolve against the retained handle, not the process working directory. */
static wchar_t *
directory_path(mpq_directory_s *directory, const char *name)
{
    DWORD size = GetFinalPathNameByHandleW(directory->handle, NULL, 0, FILE_NAME_NORMALIZED);
    wchar_t *suffix = wide_path(name);
    wchar_t *path;
    size_t length;

    if (size == 0 || suffix == NULL) {
        free(suffix);
        return NULL;
    }
    length = wcslen(suffix);
    path = malloc(((size_t)size + length + 2) * sizeof(*path));
    if (path != NULL) {
        DWORD used = GetFinalPathNameByHandleW(directory->handle, path, size, FILE_NAME_NORMALIZED);

        if (used == 0 || used >= size) {
            free(path);
            path = NULL;
        } else {
            if (path[used - 1] != L'\\')
                path[used++] = L'\\';
            memcpy(path + used, suffix, (length + 1) * sizeof(*path));
        }
    }
    free(suffix);
    return path;
}

int32_t
libmpq__directory_open(const char *path, mpq_directory_s **directory, char **name)
{
    wchar_t *wide;
    wchar_t *absolute = NULL;
    wchar_t *basename = NULL;
    DWORD size;
    int bytes;
    HANDLE handle;

    if (directory != NULL)
        *directory = NULL;
    if (name != NULL)
        *name = NULL;
    if (directory == NULL || name == NULL || path == NULL || path[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    wide = wide_path(path);
    if (wide == NULL)
        return LIBMPQ_ERROR_OPEN;
    size = GetFullPathNameW(wide, 0, NULL, NULL);
    if (size == 0) {
        free(wide);
        return LIBMPQ_ERROR_OPEN;
    }
    absolute = malloc((size_t)size * sizeof(*absolute));
    if (absolute == NULL) {
        free(wide);
        return LIBMPQ_ERROR_MALLOC;
    }
    if (GetFullPathNameW(wide, size, absolute, &basename) >= size || basename == NULL ||
        *basename == 0) {
        free(wide);
        free(absolute);
        return LIBMPQ_ERROR_OPEN;
    }
    free(wide);
    bytes = WideCharToMultiByte(CP_UTF8, 0, basename, -1, NULL, 0, NULL, NULL);
    *name = malloc((size_t)bytes);
    if (*name == NULL) {
        free(absolute);
        return LIBMPQ_ERROR_MALLOC;
    }
    WideCharToMultiByte(CP_UTF8, 0, basename, -1, *name, bytes, NULL, NULL);
    *basename = 0;
    handle = CreateFileW(
        absolute, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL
    );
    free(absolute);
    if (handle == INVALID_HANDLE_VALUE) {
        free(*name);
        *name = NULL;
        return LIBMPQ_ERROR_OPEN;
    }
    *directory = malloc(sizeof(**directory));
    if (*directory == NULL) {
        CloseHandle(handle);
        free(*name);
        *name = NULL;
        return LIBMPQ_ERROR_MALLOC;
    }
    (*directory)->handle = handle;
    return 0;
}

int32_t
libmpq__directory_remove(mpq_directory_s *directory, const char *name)
{
    wchar_t *path;
    int32_t result;

    if (directory == NULL || name == NULL || name[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    path = directory_path(directory, name);
    result = path != NULL && DeleteFileW(path) ? 0 : LIBMPQ_ERROR_WRITE;

    free(path);
    return result;
}

int32_t
libmpq__directory_replace(
    mpq_directory_s *directory, const char *temporary, const char *destination
)
{
    wchar_t *source;
    wchar_t *target;
    int32_t result = LIBMPQ_ERROR_WRITE;

    if (directory == NULL || temporary == NULL || destination == NULL || temporary[0] == '\0' ||
        destination[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    source = directory_path(directory, temporary);
    target = directory_path(directory, destination);
    if (source != NULL && target != NULL &&
        MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        result = 0;
    free(source);
    free(target);
    return result;
}

void
libmpq__directory_close(mpq_directory_s *directory)
{
    if (directory != NULL) {
        CloseHandle(directory->handle);
        free(directory);
    }
}

/* Grant only the effective user access; do not inherit directory permissions. */
static int
owner_descriptor(PSECURITY_DESCRIPTOR *descriptor)
{
    static const wchar_t prefix[] = L"D:P(A;;GA;;;";
    HANDLE token;
    DWORD size = 0;
    TOKEN_USER *user = NULL;
    wchar_t *sid = NULL;
    wchar_t *text = NULL;
    int result = 0;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        if (GetLastError() != ERROR_NO_TOKEN ||
            !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            return 0;
    }
    (void)GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (size != 0)
        user = malloc(size);
    if (user != NULL && GetTokenInformation(token, TokenUser, user, size, &size) &&
        ConvertSidToStringSidW(user->User.Sid, &sid)) {
        size_t prefix_length = sizeof(prefix) / sizeof(*prefix) - 1;
        size_t sid_length = wcslen(sid);

        text = malloc((prefix_length + sid_length + 2) * sizeof(*text));
        if (text != NULL) {
            memcpy(text, prefix, prefix_length * sizeof(*text));
            memcpy(text + prefix_length, sid, sid_length * sizeof(*text));
            text[prefix_length + sid_length] = L')';
            text[prefix_length + sid_length + 1] = 0;
            result = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                         text, SDDL_REVISION_1, descriptor, NULL
                     ) != 0;
        }
    }
    free(text);
    if (sid != NULL)
        LocalFree(sid);
    free(user);
    CloseHandle(token);
    return result;
}

int32_t
libmpq__directory_temporary(
    mpq_directory_s *directory, const char *suffix, int private_file, char **name, FILE **file
)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t random[16];
    char *candidate;
    size_t length;
    unsigned attempt;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, FALSE };

    if (name != NULL)
        *name = NULL;
    if (file != NULL)
        *file = NULL;
    if (directory == NULL || name == NULL || file == NULL || !valid_template(suffix))
        return LIBMPQ_ERROR_EXIST;
    length = strlen(suffix);
    candidate = libmpq__string_duplicate(suffix);
    if (candidate == NULL)
        return LIBMPQ_ERROR_MALLOC;

    /* Protected owner-only DACL: plaintext must not inherit directory grants. */
    if (private_file && !owner_descriptor(&descriptor)) {
        free(candidate);
        return LIBMPQ_ERROR_OPEN;
    }
    security.lpSecurityDescriptor = descriptor;
    for (attempt = 0; attempt < 128; ++attempt) {
        wchar_t *path;
        HANDLE handle;
        DWORD error;
        size_t i;

        if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            break;
        for (i = 0; i < 32; ++i)
            candidate[length - 32 + i] = hex[(i & 1) ? random[i / 2] & 15 : random[i / 2] >> 4];
        path = directory_path(directory, candidate);
        if (path == NULL)
            break;
        handle = CreateFileW(
            path, GENERIC_READ | GENERIC_WRITE, 0, private_file ? &security : NULL, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, NULL
        );
        error = GetLastError();
        if (handle != INVALID_HANDLE_VALUE) {
            *file = handle_stream(handle, "w+b");
            if (*file == NULL)
                DeleteFileW(path);
            free(path);
            break;
        }
        free(path);
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            break;
    }
    if (descriptor != NULL)
        LocalFree(descriptor);
    if (*file == NULL) {
        free(candidate);
        return LIBMPQ_ERROR_OPEN;
    }
    *name = candidate;
    return 0;
}

#else

struct mpq_directory
{
    int fd;
};

FILE *
libmpq__file_open(const char *path, const char *mode)
{
    if (path == NULL || path[0] == '\0' || mode == NULL || mode[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    return fopen(path, mode);
}

int32_t
libmpq__file_identity(FILE *file, uint64_t *device, uint64_t *inode)
{
    struct stat status;

    if (device != NULL)
        *device = 0;
    if (inode != NULL)
        *inode = 0;
    if (file == NULL || device == NULL || inode == NULL)
        return LIBMPQ_ERROR_EXIST;
    if (fstat(fileno(file), &status) != 0)
        return LIBMPQ_ERROR_OPEN;
    *device = (uint64_t)status.st_dev;
    *inode = (uint64_t)status.st_ino;
    return 0;
}

int32_t
libmpq__directory_remove(mpq_directory_s *directory, const char *name)
{
    if (directory == NULL || name == NULL || name[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    return unlinkat(directory->fd, name, 0) == 0 ? 0 : LIBMPQ_ERROR_WRITE;
}

void
libmpq__directory_close(mpq_directory_s *directory)
{
    if (directory != NULL) {
        close(directory->fd);
        free(directory);
    }
}

/* Mark a descriptor close-on-exec when atomic creation did not provide it. */
#ifndef O_CLOEXEC
static int
set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);

    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}
#endif

/* Fill a short temporary suffix from the operating system random source. */
static int32_t
random_bytes(uint8_t *buffer, size_t size)
{
    int fd;
    size_t offset = 0;

#ifdef O_CLOEXEC
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
#else
    fd = open("/dev/urandom", O_RDONLY);
#endif
    if (fd < 0)
        return LIBMPQ_ERROR_OPEN;
#ifndef O_CLOEXEC
    if (!set_cloexec(fd)) {
        (void)close(fd);
        return LIBMPQ_ERROR_OPEN;
    }
#endif
    while (offset < size) {
        ssize_t read_size = read(fd, buffer + offset, size - offset);

        if (read_size < 0 && errno == EINTR)
            continue;
        if (read_size <= 0) {
            (void)close(fd);
            return LIBMPQ_ERROR_OPEN;
        }
        offset += (size_t)read_size;
    }
    if (close(fd) != 0)
        return LIBMPQ_ERROR_OPEN;
    return 0;
}

/* Create one temporary file using an unpredictable O_EXCL basename. */
static int32_t
temporary_output_file(
    int directory, char *path, size_t random_offset, size_t random_size, mode_t mode, int *file
)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t random[16] = { 0 };
    size_t i;
    uint32_t attempt;
    int flags = O_RDWR | O_CREAT | O_EXCL;

    if (random_size == 0 || random_size > 2U * sizeof(random))
        return LIBMPQ_ERROR_EXIST;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    for (attempt = 0; attempt < 128U; ++attempt) {
        int32_t result = random_bytes(random, (random_size + 1U) / 2U);

        if (result != 0)
            return result;
        for (i = 0; i < random_size; ++i) {
            uint8_t byte = random[i / 2U];

            path[random_offset + i] = hex[(i & 1U) == 0 ? byte >> 4 : byte & 0x0fU];
        }
        *file = openat(directory, path, flags, mode);
        if (*file >= 0) {
#ifndef O_CLOEXEC
            if (!set_cloexec(*file)) {
                (void)close(*file);
                (void)unlinkat(directory, path, 0);
                return LIBMPQ_ERROR_OPEN;
            }
#endif
            return 0;
        }
        if (errno != EEXIST)
            return LIBMPQ_ERROR_OPEN;
    }
    return LIBMPQ_ERROR_OPEN;
}

/* Split a destination once and retain its directory descriptor for later publication. */
int32_t
libmpq__directory_open(const char *destination, mpq_directory_s **directory, char **name)
{
    const char *slash;
    const char *directory_path;
    char *allocated_directory = NULL;
    char *destination_name;
    size_t directory_size;
    int flags = O_RDONLY;
    int fd;
    struct stat status;

    if (directory != NULL)
        *directory = NULL;
    if (name != NULL)
        *name = NULL;
    if (destination == NULL || destination[0] == '\0' || directory == NULL || name == NULL)
        return LIBMPQ_ERROR_EXIST;
    slash = (strrchr)(destination, '/');
    if (slash == NULL) {
        directory_path = ".";
        destination_name = libmpq__string_duplicate(destination);
    } else {
        directory_size = (size_t)(slash - destination);
        if (slash[1] == '\0')
            return LIBMPQ_ERROR_EXIST;
        if (directory_size == 0) {
            directory_path = "/";
        } else {
            allocated_directory = malloc(directory_size + 1U);
            if (allocated_directory == NULL)
                return LIBMPQ_ERROR_MALLOC;
            memcpy(allocated_directory, destination, directory_size);
            allocated_directory[directory_size] = '\0';
            directory_path = allocated_directory;
        }
        destination_name = libmpq__string_duplicate(slash + 1);
    }
    if (destination_name == NULL) {
        free(allocated_directory);
        return LIBMPQ_ERROR_MALLOC;
    }
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    fd = open(directory_path, flags);
    free(allocated_directory);
    if (fd < 0) {
        free(destination_name);
        return LIBMPQ_ERROR_OPEN;
    }
#ifndef O_CLOEXEC
    if (!set_cloexec(fd)) {
        (void)close(fd);
        free(destination_name);
        return LIBMPQ_ERROR_OPEN;
    }
#endif
    if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode)) {
        (void)close(fd);
        free(destination_name);
        return LIBMPQ_ERROR_OPEN;
    }
    *directory = malloc(sizeof(**directory));
    if (*directory == NULL) {
        close(fd);
        free(destination_name);
        return LIBMPQ_ERROR_MALLOC;
    }
    (*directory)->fd = fd;
    *name = destination_name;
    return 0;
}

/* Securely create one private temporary file below an already-opened directory. */
int32_t
libmpq__directory_temporary(
    mpq_directory_s *directory, const char *suffix, int private_file, char **path, FILE **file
)
{
    char *template_path;
    size_t suffix_size;
    int32_t result;
    int fd;

    if (path != NULL)
        *path = NULL;
    if (file != NULL)
        *file = NULL;
    if (directory == NULL || path == NULL || file == NULL || !valid_template(suffix))
        return LIBMPQ_ERROR_EXIST;
    suffix_size = strlen(suffix);
    template_path = libmpq__string_duplicate(suffix);
    if (template_path == NULL)
        return LIBMPQ_ERROR_MALLOC;
    result = temporary_output_file(
        directory->fd, template_path, suffix_size - 32U, 32U, private_file ? 0600 : 0666, &fd
    );
    if (result != 0) {
        free(template_path);
        return result;
    }
    *file = fdopen(fd, "w+b");
    if (*file == NULL) {
        (void)close(fd);
        (void)unlinkat(directory->fd, template_path, 0);
        free(template_path);
        return LIBMPQ_ERROR_OPEN;
    }
    *path = template_path;
    return 0;
}

/*
 * Publish a complete same-directory encrypted temporary output. On POSIX,
 * renameat is the atomic replacement primitive: observers see either the old
 * destination or the complete encrypted replacement, never a partial file.
 */
int32_t
libmpq__directory_replace(
    mpq_directory_s *directory, const char *temporary, const char *destination
)
{
    if (directory == NULL || temporary == NULL || destination == NULL || temporary[0] == '\0' ||
        destination[0] == '\0')
        return LIBMPQ_ERROR_EXIST;
    return renameat(directory->fd, temporary, directory->fd, destination) == 0 ? 0
                                                                               : LIBMPQ_ERROR_WRITE;
}

#endif
