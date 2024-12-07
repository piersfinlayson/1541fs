#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS 64

#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <pthread.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <opencbm.h>

#define APP_NAME "1541fs-fuse"
#ifndef VERSION
#define VERSION 0.1
#endif

int current_log_level = LOG_DEBUG;

#define ERROR(format, ...) \
    if (current_log_level >= LOG_ERR) syslog(LOG_ERR, format, ##__VA_ARGS__)
#define WARN(format, ...) \
    if (current_log_level >= LOG_WARNING) syslog(LOG_WARNING, format, ##__VA_ARGS__)
#define INFO(format, ...) \
    if (current_log_level >= LOG_INFO) syslog(LOG_INFO, format, ##__VA_ARGS__)
#define DEBUG(format, ...) \
    if (current_log_level >= LOG_DEBUG) syslog(LOG_DEBUG, format, ##__VA_ARGS__)

#define BUF_INC 256
#define DEVICE_NUM 8

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
    const char *filename;
    const char *contents;
    int show_help;
} options;

static char *mountpoint; 

#define BLOCK_SIZE 256
#define TRACK_18_START 17 * 21
#define TRACK_18_END 17 * 21 + 19
#define MAX_BLOCKS (663)
#define CBM_FILE_NAME "RAWDISK,L,"
#define RECORD_LEN BLOCK_SIZE
#define MAX_ERROR_LENGTH 48
#define MAX_NUM_FILES 296 + 1 // 296 on 1571/1581, plus 1 for the disk name (which we expose as a special file)
#define MAX_FILENAME_LEN 16+1+3+1 // 16 chars + 1 for period + 3 for file ending + 1 null terminator

struct cbm_dir_entry {
    unsigned short num_blocks;
    unsigned long filesize;
    char filename[MAX_FILENAME_LEN];
    unsigned char is_header;
};

struct cbm_state {
    struct fuse *fuse;
    int fuse_fh;
    int fuse_loop;
    int fuse_exited;
    pthread_mutex_t mutex;
    CBM_FILE fd;
    unsigned char drive_num;

    unsigned char channel;
    unsigned char error_channel;
    size_t total_size;
    int is_initialized;
    char error_buffer[MAX_ERROR_LENGTH];
    int dir_is_clean;
    int num_dir_entries;
    struct cbm_dir_entry *dir_entries;
};

static void *read_dir_from_disk_thread_func(void *vargp);

static int check_drive_status(struct cbm_state *cbm) {
    int len;

    len = cbm_exec_command(cbm->fd, cbm->drive_num, "I", 1);
    if (len < 0) return -1;

    len = cbm_listen(cbm->fd, cbm->drive_num, 15);
    if (len < 0) return -1;

    len = cbm_raw_read(cbm->fd, cbm->error_buffer, sizeof(cbm->error_buffer));
    cbm_unlisten(cbm->fd);

    if (len < 0) return -1;
    cbm->error_buffer[len] = '\0';

    cbm->error_buffer[MAX_ERROR_LENGTH - 1] = '\0';

    return ((cbm->error_buffer)[0] == '0') ? 0 : -1;
}

static void cbm_cleanup(struct cbm_state *cbm)
{
    cbm_driver_close(cbm->fd);
}

// Updated init function signature for FUSE3
static void *cbm_init(struct fuse_conn_info *conn,
                     struct fuse_config *cfg)
{
    struct cbm_state *cbm = fuse_get_context()->private_data;
    (void)conn;
    (void)cfg;
    int failed = 0;

    if (pthread_mutex_init(&(cbm->mutex), NULL) != 0)
    {
        ERROR("Failed to initialize mutex\n");
        return NULL;
    }

    cbm->drive_num = 8;
    cbm->error_channel = 15;
    cbm->total_size = MAX_BLOCKS * BLOCK_SIZE;
    cbm->is_initialized = 0;
    
    if (cbm_driver_open(&cbm->fd, 0) != 0) {
        WARN("Failed to open OpenCBM driver\n");
        failed = 1;
        goto EXIT;
    }
    
    if (check_drive_status(cbm) != 0) {
        WARN("Drive not responding: %s\n", cbm->error_buffer);
        cbm_cleanup(cbm);
        failed = 1;
        goto EXIT;
    }
    
    cbm->is_initialized = 1;

    // Spawn a thread to read the disk, so it's faster to access this mount
    // later
    pthread_t thread_id;
    pthread_create(&thread_id,
                   NULL,
                   read_dir_from_disk_thread_func,
                   (void *)cbm);

EXIT:

    if (failed)
    {
        pthread_mutex_destroy(&cbm->mutex);
        ERROR("Mount failed - is the XUM1541 plugged in and the drive turned on?\n");
        fuse_exit(fuse_get_context()->fuse);
        cbm->fuse_exited = 1;
        cbm = NULL;
    }

    return cbm;
}

// Clean up when unmounting
static void cbm_destroy(void *private_data)
{
    struct cbm_state *cbm = private_data;
    if (cbm->is_initialized) {
        check_drive_status(cbm); // Clear any pending errors
    }
    cbm_driver_close(cbm->fd);
    pthread_mutex_destroy(&(cbm->mutex));
}

void set_stat(struct cbm_dir_entry *entry, struct stat *stbuf)
{
    memset(&stbuf, 0, sizeof(stbuf));

    // Num blocks is tricky.  It's supposed to represent the number of
    // 512 byte blocks.  But our filesystem has size 256 blocks.  So we
    // must convert into 512 byte blocks
    assert(BLOCK_SIZE == 256);
    stbuf->st_blocks = (int)((entry->filesize + 255) / 256/ 2);
    stbuf->st_blksize = BLOCK_SIZE;
    stbuf->st_size = (int)(entry->filesize);
    if (!entry->is_header)
    {
        stbuf->st_mode |= S_IFREG;
        stbuf->st_mode |= S_IRUSR; // | S_IWUSR; Don't have write support yet
        stbuf->st_mode |= S_IRGRP;
    }
    else
    {
        stbuf->st_mode |= S_IFDIR;
        stbuf->st_mode |= S_IRUSR; // | S_IWUSR; Don't have write support yet
        stbuf->st_mode |= S_IRGRP;
    }
}

// Updated getattr function signature for FUSE3
static int cbm_getattr(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi)
{
    (void)fi;
    int rc = -ENOENT;

    struct cbm_state *cbm = fuse_get_context()->private_data;

    pthread_mutex_lock(&(cbm->mutex));

    memset(stbuf, 0, sizeof(struct stat));
    
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        rc = 0;
    }
    else 
    {
        // Look for filename in dir_entries
        for (int ii = 0; ii < cbm->num_dir_entries; ii++)
        {
            struct cbm_dir_entry *entry = cbm->dir_entries + ii;
            if (!strncmp(path, (char*)(entry->filename), MAX_FILENAME_LEN-1))
            {
                // Match
                set_stat(entry, stbuf);
                rc = 0;
                break;
            }

        }
    }

    pthread_mutex_unlock(&(cbm->mutex));

    return rc;
}

void check_realloc_buffer(char **buffer,
                          unsigned int *buf_len,
                          const unsigned int pos)
{
    char *new_buffer;

    assert(buffer != NULL);
    if (pos >= *buf_len)
    {
        *buf_len += BUF_INC;
        new_buffer = realloc(*buffer, *buf_len);

        // The following handles the case if the remalloc failed -
        // the original buffer will still be freed, and buffer set to NULL
        free(*buffer);
        *buffer = new_buffer;
    }
}

void remove_trailing_spaces(char *str) {
    int len = (int)strlen(str);
    int i;

    // Iterate from the end of the string towards the beginning
    for (i = len - 1; i >= 0; i--) {
        if (str[i] != ' ') {
            break;
        }
    }

    // Terminate the string after the last non-space character
    str[i + 1] = '\0';
}

static int read_dir_from_disk(struct cbm_state *cbm)
{
    unsigned int buf_len;
    unsigned int data_len;
    unsigned int pos;
    char *buffer;
    int rc = 0;
    int error;
    char c;

    INFO("read_dir_from_disk");

    cbm->dir_is_clean = 0;

    // malloc a buffer to store data read from the disk in
    buf_len = BUF_INC;
    buffer = malloc(buf_len);
    if (buffer == NULL)
    {
        rc = -ENOMEM;
        goto EXIT;
    }

    // open the directory "file" ($)
    c = cbm_ascii2petscii_c('$');
    error = cbm_open(cbm->fd, DEVICE_NUM, 0, &c, 1);
    if (error)
    {
        rc = -EIO;
        goto EXIT;
    }

    // Read in directory listing from the drive
    char cc[2];
    pos = 0;
    cbm_talk(cbm->fd, 8, 0);
    int line_count = 0;
    if (cbm_raw_read(cbm->fd, cc, 2) == 2)
    {
        // Ignore those 2 bytes
        while (cbm_raw_read(cbm->fd, cc, 2) == 2)
        {
            // Ignore those 2 bytes
            if (cbm_raw_read(cbm->fd, cc, 2) == 2)
            {
                // We now receive a line of directory listing until we read 0
                line_count++;
                while (cbm_raw_read(cbm->fd, cc, 1) == 1 && cc[0])
                {
                    buffer[pos] = cbm_petscii2ascii_c(cc[0]); 
                    pos++;
                    check_realloc_buffer(&buffer, &buf_len, pos);
                    if (buffer == NULL)
                    {
                        rc = -ENOMEM;
                        goto EXIT;
                    }
                }
                
                // Separate lines with newline not 0 byte
                buffer[pos] = '\n';
                pos++;
                check_realloc_buffer(&buffer, &buf_len, pos);
                if (buffer == NULL)
                {
                    rc = -ENOMEM;
                    goto EXIT;
                }

                // Now continue, to see if there's another line
            }
        }
    }
    data_len = pos;

    // We now have buffer filled with directory data, one line per file, with
    // newlines between
    // We also have a count of the number of lines of data.  This will be one
    // more than the number of files as the last line is number of blocks
    // free.
    // (The first line is the disk header, but we include that as a file)

    // Example of directory data
    //
    // 0 ."disk name       " id 2a
    // 1    "hellorld"         seq
    // 663 blocks free.

    // Next thing to do is create the correct number of directory entries in
    // our array.  This looks more complicated than it seems because we reuse
    // existing memory if it exists and is big enough.
    int new_num_dir_entries = line_count - 1;
    if (new_num_dir_entries < 0)
    {
        // No entries
        goto EXIT;
    }
    if (new_num_dir_entries > cbm->num_dir_entries)
    {
        // We can't reuse - better free and malloc a new one
        if (cbm->dir_entries != NULL)
        {
            free(cbm->dir_entries);
        }
        cbm->dir_entries = calloc((size_t)new_num_dir_entries, sizeof(struct cbm_dir_entry));
        if (cbm->dir_entries == NULL)
        {
            rc = -ENOMEM;
            goto EXIT;
        }
    }
    else
    {
        // We can reuse the existing memory, first set it to zeros
        memset(cbm->dir_entries, 0, (size_t)new_num_dir_entries * sizeof(struct cbm_dir_entry));
    }
    cbm->num_dir_entries = new_num_dir_entries;

    // Now we need to set up the directory entries 1 by 1.  We do this by, for
    // each line of data
    // * reading the file size
    // * reading the file name
    // * reading the file type
    // * filling the cbm_dir_entry structure as appropriate
    int dir_entry = 0;
    pos = 0;
    while (dir_entry < cbm->num_dir_entries)
    {
        // Set up the directory entry
        struct cbm_dir_entry *entry = cbm->dir_entries + dir_entry;

        // Get file size
        if ((pos + 1) >= data_len)
        {
            WARN("Ran out of data before finishing processing directory entries");
            cbm->num_dir_entries = dir_entry;
            break;
        }
        entry->num_blocks = (unsigned short)((unsigned char)buffer[pos] | (unsigned char)buffer[pos+1] << 8);
        entry->filesize = entry->num_blocks * BLOCK_SIZE;
        pos += 2;

        int filename_started = 0;
        int filename_ended = 0;
        int filename_len = 0;
        int is_header = 0;
        int is_footer = 0;
        char suffix[4] = {0, 0, 0, 0};
        int suffix_len = 0;
        while ((pos < data_len) && 
               (buffer[pos != '\n']))
        {
            c = buffer[pos];
            if (is_footer)
            {
                assert(!filename_started);
                // ignore the footer - just says "blocks free"
            }
            else if (!filename_started)
            {
                assert(!filename_ended);
                if (c == ' ')
                {
                    // ignore leading spaces
                }
                else if (c == '.')
                {
                    assert(is_footer);
                    is_header = 1;
                    entry->is_header = 1;
                }
                else if (c == '"')
                {
                    filename_started = 1;
                }
                else if (c == 'b')
                {
                    assert(!is_header);
                    is_footer = 1;

                }
            }
            else if (!filename_ended)
            {
                assert(!is_footer);
                if (c == '"')
                {
                    filename_ended = 1;
                }
                else
                {
                    // Any other char just gets added to the filename
                    // We'll cope with trailing spaces when appending the .XXX
                    // suffix
                    // We sade 5 chars for the 4 digit suffix and 1xNULL terminator
                    if (filename_len < (MAX_FILENAME_LEN - 5))
                    {
                        entry->filename[filename_len] = c;
                        filename_len++;
                    }
                    else
                    {
                        WARN("Filename is longer than max len - truncated version is: %s", entry->filename);
                    }
                }
            }
            else if (suffix_len > 0)
            {
                if (c == ' ')
                {
                    // Suffix has ended - we could match with valid ones, but
                    // we won't bother - instead we'll just add to the
                    // filename
                    remove_trailing_spaces(entry->filename);
                    assert(strnlen(entry->filename, MAX_FILENAME_LEN-1) < (MAX_FILENAME_LEN - 5));
                    entry->filename[filename_len++] = entry->is_header ? ',' : '.';
                    strncat(entry->filename, suffix, 4);
                }
                else if (suffix_len < 3)
                {
                    suffix[suffix_len++] = c;
                }
                else
                {
                    // Drop any more chars
                    assert(suffix[3] == 0);
                    WARN("Suffix is too long - truncated version is: %s", suffix);
                }
            }
            else
            {
                assert(filename_started);
                assert(filename_ended);
                assert(!is_footer);
                assert(suffix_len == 0);
                if (c == ' ')
                {
                    // Ignore
                }
                else
                {
                    suffix[suffix_len++] = c;
                }
            }

            // Move to next char
            pos++;
        }

        // Move to next directory entry (file)
        dir_entry++;
    }

    cbm->dir_is_clean = 1;

EXIT:

    return rc;

}

void *read_dir_from_disk_thread_func(void *vargp)
{
    struct cbm_state *cbm;
    int rc;
    
    assert(vargp != NULL);
    cbm = (struct cbm_state *)vargp;
    
    rc = read_dir_from_disk(cbm);
    (void)rc; // Ignore RC - nothing we can do and read_dir_from_disk logs

    return NULL;
}

static int cbm_readdir(const char *path,
                       void *buf,
                       fuse_fill_dir_t filler,
                       off_t offset,
                       struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
{
    int rc;

    struct cbm_state *cbm = fuse_get_context()->private_data;

    pthread_mutex_lock(&(cbm->mutex));

    (void)offset;
    (void)fi;
    (void)flags;

    if (strcmp(path, "/") != 0) {
        rc = -ENOENT;
        goto EXIT;
    }

    if (!cbm->dir_is_clean)
    {
        rc = read_dir_from_disk(cbm);
        if (!rc)
        goto EXIT;
    }

    assert(cbm->dir_is_clean);

    // Add . and .. first
    struct stat stbuf = {0};
    stbuf.st_mode = S_IFDIR;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    // Now create an entry for each file
    for (int ii = 0; ii < cbm->num_dir_entries; ii++)
    {
        struct cbm_dir_entry *entry = cbm->dir_entries + ii;
        set_stat(entry, &stbuf);
        filler(buf, entry->filename, &stbuf, 0, 0);
    }

EXIT:

    pthread_mutex_destroy(&(cbm->mutex));

    return 0;
}

static const struct fuse_operations cbm_oper = {
    .init     = cbm_init,
    .destroy  = cbm_destroy,
    .getattr  = cbm_getattr,
    .readdir  = cbm_readdir,
};

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
    OPTION("--name=%s", filename),
    OPTION("--contents=%s", contents),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    FUSE_OPT_KEY("-f", FUSE_OPT_KEY_KEEP),
    FUSE_OPT_END
};

// Called by fuse_opt_parse when a non-option argument is found
static int opt_proc(void *data,
                    const char *arg,
                    int key,
                    struct fuse_args *outargs)
{
    (void)data;
    (void)outargs;

    switch (key)
    {
        case FUSE_OPT_KEY_NONOPT:
            if (mountpoint == NULL)
            {
                mountpoint = strdup(arg);
                // Remove from options list so FUSE doesn't see it twice
                return 0;
            }
            break;

        default:
            return 1;
    }

    return 1;
}

void init_logging()
{
    openlog(APP_NAME, LOG_PID | LOG_CONS, LOG_DAEMON);
}

struct signal_handler_data {
    struct cbm_state *cbm;
};
static struct signal_handler_data shd; 

void handle_signal(int signal)
{
    struct cbm_state *cbm = shd.cbm;

    // Try and unmount and destroy fuse
    // We won't bother to get the mutex, because it may well be locked already
    // For a similar reason we won't bother locking the mutex
    // We will free cbm
    switch (signal)
    {
        default:
            INFO("Exception %d caught - cleaning up", signal);
            if (cbm != NULL)
            {
                if (cbm->fuse != NULL)
                {
                    if (cbm->fuse_loop && !cbm->fuse_exited)
                    {
                        fuse_exit(cbm->fuse);
                        cbm->fuse_exited = 1;
                    }
                    if (cbm->fuse_fh != -1)
                    {
                        fuse_unmount(cbm->fuse);
                        cbm->fuse_fh = -1;
                    }
                    fuse_destroy(cbm->fuse);
                    cbm->fuse = NULL;
                }
                free(cbm);
                cbm = NULL;
            }
            INFO("Exiting after handling signal");
            exit(1);
            break;
    }
}

void setup_signal_handler()
{
    int termination_signals[] = {
        SIGHUP,   // Hangup detected on controlling terminal or death of controlling process
        SIGINT,   // Interrupt from keyboard (Ctrl-C)
        SIGQUIT,  // Quit from keyboard (Ctrl-\), also generates a core dump
        SIGILL,   // Illegal Instruction
        SIGABRT,  // Abort signal from abort function
        SIGFPE,   // Floating-point exception
        SIGKILL,  // Kill signal (cannot be caught, blocked, or ignored)
        SIGSEGV,  // Invalid memory reference (segmentation fault)
        SIGPIPE,  // Broken pipe: write to a pipe with no readers
        SIGALRM,  // Timer signal from alarm
        SIGTERM,  // Termination signal
        SIGUSR1,  // User-defined signal 1 (typically terminates unless specifically handled)
        SIGUSR2,  // User-defined signal 2 (typically terminates unless specifically handled)
        SIGBUS,   // Bus error (accessing memory that’s not physically mapped)
        SIGPOLL,  // Pollable event (Sys V). Synonym for SIGIO
        SIGPROF,  // Profiling timer expired
        SIGSYS,   // Bad system call (not implemented)
        SIGTRAP,  // Trace/breakpoint trap
        SIGXCPU,  // CPU time limit exceeded
        SIGXFSZ   // File size limit exceeded
    };
    int num_signals = (int)(sizeof(termination_signals)/sizeof(int));
    for (int ii = 0; ii < num_signals; ii++)
    {
        signal(termination_signals[ii], handle_signal);
    }
}

int main(int argc, char *argv[])
{
    struct cbm_state *cbm;
    struct fuse_cmdline_opts fuse_opts = { 0 };
    int ret = 1;

    DEBUG("Allocate private data");
    cbm = calloc(1, sizeof(struct cbm_state));
    if (cbm == NULL)
    {
        ERROR("Failed to allocate memory\n");
        goto EXIT;
    }
    shd.cbm = cbm;
    cbm->fuse_fh = -1;
    DEBUG("Private data allocated");

    DEBUG("Setup signal handler");
    setup_signal_handler();

    DEBUG("Init fuse arg");
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    // First parse custom options
    DEBUG("Parse args");
    if (fuse_opt_parse(&args, &options, option_spec, opt_proc) == -1)
    {
        ERROR("Failed to parse options");
        goto EXIT;
    }
    if (mountpoint == NULL)
    {
        WARN("No mountpint defined - exiting");
        printf("No mountpoint defined - exiting\n");
        goto EXIT;
    }

    // Then let FUSE parse its built-in options
    DEBUG("Parse fuse args");
    if (fuse_parse_cmdline(&args, &fuse_opts) == -1)
    {
        ERROR("Failed to parse FUSE options\n");
        return 1;
    }

    DEBUG("Fuse new");
    cbm->fuse = fuse_new_30(&args, &cbm_oper, sizeof(cbm_oper), cbm);
    if (cbm->fuse == NULL)
    {
        ERROR("Failed to create FUSE object\n");
        goto EXIT;
    }
    
    DEBUG("Fuse mount");
    cbm->fuse_fh = fuse_mount(cbm->fuse, mountpoint);
    if (cbm->fuse_fh == -1)
    {
        ERROR("Failed to mount FUSE filesystem\n");
        goto EXIT;
    }

    DEBUG("Fuse loop");
    cbm->fuse_loop = 1;
    ret = fuse_loop(cbm->fuse);
    cbm->fuse_exited = 1;

EXIT:

    INFO("Exiting\n");

    // Cleanup code
    if (cbm != NULL)
    {
        if (cbm->fuse_fh != -1)
        {
            DEBUG("Unmount FUSE\n");
            fuse_unmount(cbm->fuse);
            cbm->fuse_fh = -1;
        }

        if (!cbm->fuse_exited && (cbm->fuse != NULL))
        {
            DEBUG("Destroy fuse\n");
            fuse_destroy(cbm->fuse);
            cbm->fuse = NULL;
        }
        DEBUG("Dealloc memory\n");
        free(cbm);
    }

    return ret;
}   