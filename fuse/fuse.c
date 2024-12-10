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
#ifdef DEBUG_BUILD
#define DEBUG(format, ...) \
    if (current_log_level >= LOG_DEBUG) syslog(LOG_DEBUG, format, ##__VA_ARGS__)
#else // DEBUG_BUILD
#define DEBUG(format, ...)
#endif

// Special paths
// Must not begin or terminate the / or FUSE will barf
#define PATH_FORCE_DISK_REREAD  "force_disk_reread" // Could use header for this
const char *special_dirs[] =
{
    ".",
    "..",
    PATH_FORCE_DISK_REREAD,
    NULL
};

// Special files
#define PATH_FORMAT_DISK        "format_disk"        // Could also use header for this
const char *special_files[] = {
    PATH_FORMAT_DISK,
    NULL,
};

// What will be read out of format-disk
#define FORMAT_CONTENTS \
    "To format a disk write the new disk name followed by the ID to this file.\n" \
    "The disk name can be a maximum of 16 characters and the ID two digits.\n" \
    "Separate the two with a comma.  For example:\n" \
    "my new disk,01"


// Various return string prefixes from Commdore DOS
#define DOS_OK_PREFIX "00"        // OK
#define DOS_BOOT_PREFIX "73,CBM"  // When drive has just powered up/reset
#define MAX_ERROR_LENGTH 48

// When allocating buffers for reading data, etc, allocate this much memory
// to being with, and if it's not enough use this as an increment to use to
// realloc.
#define BUF_INC 1024

// Commodore disk drive device numbers.
// Note that these are _device_ numbers, not _drive_ numbers.  Some Commodore
// disk units have 2 drives (the 2040, 3040, etc).  Those are a different
// concept, and not currently supported by this program.
#define DEFAULT_DEVICE_NUM 8
#define MIN_DEVICE_NUM     8
#define MAX_DEVICE_NUM     11

// Information about Commodore DOS channels.  There are 16 (0-15).
// 0, 1 and 15 are special:
// 0 - read
// 1 - write
// 15 - control channel (send commands, or receive status)
//2-14 inclusive can be used for other purposes.
#define NUM_CHANNELS      16
#define MIN_USER_CHANNEL  2
#define MAX_USER_CHANNEL  14
#define DUMMY_CHANNEL     16  // Used to access dummy files/directories

// Other information about Commodore disk file sytem and d
#define CBM_BLOCK_SIZE 256
#define MAX_FILENAME_LEN 16+1+3+1 // 16 chars + 1 for period + 3 for file ending + 1 null terminator

// Valid uses for disk drive channels 
enum cbm_channel_usage
{
    // Unused
    USAGE_NONE,

    // Reserved for channel 0
    USAGE_READ,

    // Reserved for channel 1
    USAGE_WRITE,

    // Used by channel 15
    USAGE_CONTROL,

    // Used by other channels (specifically as requested by FUSE)
    USAGE_OPEN,
};

// Information about a specific channel to the device, including whether it's
// open and what for.
struct cbm_channel
{
    // Can be between 0 and NUM_CHANNELS-1
    unsigned char num;

    // Whether this channel has been opened (and not closed)
    unsigned char open;

    // What this channel is being used for (may be retired if unnecessary)
    enum cbm_channel_usage usage;

    // If usage is USAGE_OPEN (channels 2-14) and open is 1, stores the file
    // of the filename opened
    char filename[MAX_FILENAME_LEN];
};

// Information about an entry from the disk directory.  May be either a header
// (disk name,ID), or a file (name.suffix).
struct cbm_dir_entry
{
    // Number of blocks on the disk used by this file.  Note that Commodore
    // disk blocks are 256 bytes, whereas FUSE expects to be provided the
    // number of 512 byte blocks, so we need to convert.
    unsigned short num_blocks;

    // Filesize in bytes.  Technically this isn't correct as it's calculated
    // by multiplying the number of blocks by 256.  But we wouldn't know the
    // correct value without reading the entire file, which we won't do.  This
    // may lead to some unexpected behaviour, if this filesize is relied upon
    // when listing then processing files.
    unsigned int filesize;

    // Filename.  We use the convention of stripping and trailing spaces
    // from the filename from disk, the appending a suffix, preceeeded by a
    // period, indicating the Commodore file type - so .prg .usr .seq .rel
    // etc.  If the file stored is called test and a PRG file, it'll be
    // stored and shown as test.prg.  Note that if a file test.prg is stored
    // as a prg, it will be called test.prg.prg.  Any spaces within the
    // filename including at the beginning will be retained.
    char filename[MAX_FILENAME_LEN];

    // indicates whether should be treated as a directory.
    // In terms of entries read from disk only the header is a directory.
    // However, we also use this struct for special_dirs (and files).
    unsigned char is_dir;

    // Indicates whether this is a special file representing the header of
    // the disk (i.e. the disk name and ID).  These are separated using a
    // comma, rather than a period, which is a common Commodore convention.
    // E.g. "scratch disk,01" without the quotes.
    unsigned char is_header;
};

// Our FUSE private data.  When called by FUSE, this can be retrieved via
// fuse_get_context()->private_data. 
struct cbm_state
{
    // FUSE's private data, which we have to provide on every call to FUSE.
    // However, we only access this from with the signal handler - within 
    // a FUSE callback context we access via fuse_get_context()->private_data.
    struct fuse *fuse;

    // FUSE's file handle for this mount.  We don't use this after receiving
    // it in response to mounting (unmounting doesn't require it).
    int fuse_fh;

    // Boolean indicating whether we've called fuse_loop yet.
    int fuse_loop;

    // Boolean indicating whether fuse_exit() has been called.
    int fuse_exited;

    // Boolean indicating whether to force a bus (IEC/IEEE-488) reset before
    // attempting to mount
    int force_bus_reset; 

    // Protect access to this data with a mutex.  This mutex will not be used/
    // honoured by the signal handler, if called, nor by the main cleanup code.
    // In the former case because the signal handler could be called when the 
    // mutex is held, and in the latter case because all fuse processing should
    // have exited before the cleanup code is called.  In both cases we want to
    // avoid blocking due to the mutex lock being held elsewhere. 
    pthread_mutex_t mutex;

    // The file descriptor from opencbm, used for all XUM1541 access
    CBM_FILE fd;

    // Commodore device number for this mount - may be 8, 9, 10 or 11
    unsigned char device_num;

    // Boolean indicating whether we have opened the OpenCBM driver
    //successfully.
    int is_initialized;

    // Used to store the last error string the drive.  Examples:
    // 00,OK,00,00
    // 73,CBM DOS 1541 v2.6,00,00
    // etc.  Note may or may not be spaces after commas.
    char error_buffer[MAX_ERROR_LENGTH];

    // Whether we succeeded in doing a successfully read of the floppy disk's
    // directory last time around - and hence whether the data in dir_entries
    // is valid.  Can be used to avoid requerying the physical media if we
    // don't think anything else has changed.
    int dir_is_clean;

    // Number of valid entries in dir_entries - so number of files in the
    // directory.  This includes any "special" files, like the disk header
    // which we represent as a file, but not . or .., which are faked by
    // the _readdir() function, and not stored in dir_entries.  Note there
    // may be more memory pointed to by dir_entries than num_dir_entries
    // suggests.  That's OK as if/when we free the OS will take care of
    // freeing it all.  However we may unnecessary realloc dir_entries if
    // we subsequently need more (and there was more hiding there than we
    // expected).  If you want to understand why this is the case read the
    // code in read_dir_from_disk - but it's essentially because:
    // * we estimate how many entries there will be before we know and
    //   allocate memory based on that (which may be an over-estimate)
    // * and if we subsequently do a directory read and there are fewer files
    //   we will avoid a reallocation at that point - but num_dir_entries will
    //   always represent the valid number of dir_entries, not the amount of
    //   space for them (but there will always be enough space for the number
    //   specified, or we will re-alloc.
    int num_dir_entries;

    // Actual directory entires, including special files, excepting . and ..
    struct cbm_dir_entry *dir_entries;

    // Array containing information about all potentially used channels.
    // Users only need store information about the channels in use if they
    // will remain unused beyond a mutex lock.  If only used within a mutex 
    // and they were free before and will remaing free after, they can be used
    // without updating channels.
    // However, where channels remaing in use between mutex calls - for
    // example when instructed to open a channel by FUSE, and then subsequently
    // read, they must be reserved here. 
    struct cbm_channel channel[NUM_CHANNELS];
};

// Used by our _init() function to kick off a read of the directory listing
// once the initialization is complete, in a separate thread, so as not to
// slow down completion of mounting.  However, this aims to ensure we have a
// listing in hand by the time the user asks for one, to speed up performance
static void *read_dir_from_disk_thread_func(void *vargp);

// Must be called within a mutex lock if called after our fuse _init() function
// has been called, and before fuse_exit() has been called.
// Extended version of check_drive_status which will call the specified
// command (like "UJ" or "I") before issuing the status query.
// Can be called with cmd == NULL, in which case a command is not issued
static int check_drive_status_cmd(struct cbm_state *cbm, char *cmd)
{
    int rc;
    int len;

    // We don't currently support users holding channel 15 open - we'll be
    // done with it before we return
    assert(!cbm->channel[15].open);

    // Send the command first, if so requested.
    if (cmd != NULL)
    {
        DEBUG("Send command: %s", cmd);
        // cbm_exec_command performs:
        // * listen
        // * raw write of the command using channel 15
        // * unlisten
        rc = cbm_exec_command(cbm->fd, cbm->device_num, cmd, 0);
        if (rc < 0)
        {
            return -1;
        }
    }

    // Now query the status.  We do this by:
    // * talk
    // * raw read on channel 15
    // * untalk
    DEBUG("Talk on channel 15");
    rc = cbm_talk(cbm->fd, cbm->device_num, 15);
    if (rc < 0)
    {
        return -1;
    }
    len = cbm_raw_read(cbm->fd, cbm->error_buffer, sizeof(cbm->error_buffer)-1);
    cbm_untalk(cbm->fd);

    // Belt and braces - ensure string properly NULL terminated
    cbm->error_buffer[len] = 0;
    cbm->error_buffer[MAX_ERROR_LENGTH - 1] = 0;

    DEBUG("Exiting check status: %s", cbm->error_buffer);

    // Both 00,OK and 73,CBM ... are OK responses
    // Anything else is considered an error
    rc = -1;
    if (!strncmp(cbm->error_buffer, DOS_OK_PREFIX, strlen(DOS_OK_PREFIX)) ||
        !strncmp(cbm->error_buffer, DOS_BOOT_PREFIX, strlen(DOS_BOOT_PREFIX)))
    {
        rc = 0;
    }

    return rc;
} 

// Must be called within a mutex lock if called after our fuse _init() function
// has been called, and before fuse_exit() has been called.
static int check_drive_status(struct cbm_state *cbm)
{
    return check_drive_status_cmd(cbm, NULL);
}

static void cbm_cleanup(struct cbm_state *cbm)
{
    cbm_driver_close(cbm->fd);
}

// Updated init function signature for FUSE3
static void *cbm_init(struct fuse_conn_info *conn,
                      struct fuse_config *cfg)
{
    (void)conn;
    (void)cfg;
    int failed = 0;
    struct cbm_state *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    int rc;

    // Create the mutex
    DEBUG("Create mutex");
    if (pthread_mutex_init(&(cbm->mutex), NULL) != 0)
    {
        ERROR("Failed to initialize mutex\n");
        return NULL;
    }

    cbm->is_initialized = 0;
    
    DEBUG("Open XUM1541 driver");
    if (cbm_driver_open(&cbm->fd, 0) != 0) {
        WARN("Failed to open OpenCBM driver\n");
        failed = 1;
        goto EXIT;
    }

    if (cbm->force_bus_reset)
    {
        INFO("Performing bus reset");
        rc = cbm_reset(cbm->fd);
        if (rc)
        {
            ERROR("Failed to reset bus");
            failed = 1;
            goto EXIT;
        }
    }
    
    // We don't actually other to lock the mutex here, as no other functions
    // will be called until this _init() function completes.
    // pthread_mutex_lock(&(cbm->mutex));
    DEBUG("Check drive status");
    rc = check_drive_status_cmd(cbm, NULL);
    // pthread_mutex_unlock(&(cbm->mutex));
    if (rc) {
        WARN("Drive status query returned error: %s\n", cbm->error_buffer);
        cbm_cleanup(cbm);
        failed = 1;
        goto EXIT;
    }
    
    cbm->is_initialized = 1;

    // Spawn a thread to read the disk, so it's faster to access this mount
    // later
    DEBUG("Spawn thread to read dir");
    pthread_t thread_id;
    pthread_create(&thread_id,
                   NULL,
                   read_dir_from_disk_thread_func,
                   (void *)cbm);

EXIT:

    if (failed)
    {
        pthread_mutex_destroy(&cbm->mutex);
        ERROR("Mount failed - is the XUM1541 plugged in, the drive turned on and set to device %d?", cbm->device_num);
        printf("Mount failed - is the XUM1541 plugged in, the drive turned on and set to device %d?\n", cbm->device_num);
        struct fuse *fuse = fuse_get_context()->fuse;
        assert(fuse != NULL);
        fuse_exit(fuse);
        cbm->fuse_exited = 1;
        cbm = NULL;
    }

    return cbm;
}

// Clean up when unmounting
static void cbm_destroy(void *private_data)
{
    struct cbm_state *cbm = private_data;
    assert(cbm != NULL);

    if (cbm->is_initialized) {
        check_drive_status(cbm); // Clear any pending errors
    }
    if (cbm->fd)
    {
        cbm_driver_close(cbm->fd);
    }
    else
    {
        WARN("Unexpectedly found OpenCBM file descriptor was not set");
    }

    pthread_mutex_destroy(&(cbm->mutex));
}

static void set_stat(struct cbm_dir_entry *entry, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));

    // Num blocks is tricky.  It's supposed to represent the number of
    // 512 byte blocks.  But our filesystem has size 256 blocks.  So we
    // must convert into 512 byte blocks
    assert(CBM_BLOCK_SIZE == 256);
    stbuf->st_blocks = (int)((entry->filesize + 255) / 256 / 2);
    stbuf->st_blksize = CBM_BLOCK_SIZE;
    stbuf->st_size = (int)(entry->filesize);
    if (!entry->is_dir)
    {
        stbuf->st_mode |= S_IFREG | 0444;
        //stbuf->st_mode |= S_IRUSR; // | S_IWUSR; Don't have write support yet
        //stbuf->st_mode |= S_IRGRP;
        stbuf->st_nlink = 1;
    }
    else
    {
        stbuf->st_mode |= S_IFDIR | 0555;
        //stbuf->st_mode |= S_IRUSR; // | S_IWUSR; Don't have write support yet
        //stbuf->st_mode |= S_IRGRP;
        stbuf->st_nlink = 2;
    }
    //stbuf->st_uid = 1000;
    //stbuf->st_gid = 1000;
}

int is_special(const char *path, const char **strings)
{
    int ii;
    const char *match;
    int rc = 0;
    if (!strcmp(path, "/"))
    {
        rc = 1;
        goto EXIT;
    }
    for (ii = 0, match=strings[ii];
         match != NULL;
         ii++, match=strings[ii])
    {
        if (!strcmp(path+1, match))
        {
            rc = 1;
            goto EXIT;
        }
    }

EXIT:

    return rc;
}

int is_special_dir(const char *path)
{
    return is_special(path, special_dirs);
}

int is_special_file(const char *path)
{
    return is_special(path, special_files);
}

// Updated getattr function signature for FUSE3
static int cbm_getattr(const char *path,
                       struct stat *stbuf,
                       struct fuse_file_info *fi)
{
    (void)fi; // fi is NULL if file is not open, and may be NULL if file is open
    int rc = -ENOENT;
    const char *actual_path;
    int sdir, sfile;

    struct cbm_state *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(path != NULL);
    assert(stbuf != NULL);

    DEBUG("ENTRY: cbm_getattr(), path: %s", path);

    pthread_mutex_lock(&(cbm->mutex));

    // This should be safe as path is NULL-terminated.  Hence if strln(path)
    // == 1, this will point to an empty string.
    // We do this to skip the leading /

    sdir = is_special_dir(path);
    if (!sdir)
    {
        sfile = is_special_file(path);
    } 
    if (sdir || sfile)
    {
        struct cbm_dir_entry entry;
        memset(&entry, 0 , sizeof(entry));
        strncpy(entry.filename, path, MAX_FILENAME_LEN-1);
        entry.is_dir = sdir ? 1 : 0;
        set_stat(&entry, stbuf);
        rc = 0;
    }
    else if (path[0] == '/')
    {
        actual_path = path+1;
        // Look for filename in dir_entries
        for (int ii = 0; ii < cbm->num_dir_entries; ii++)
        {
            struct cbm_dir_entry *entry = cbm->dir_entries + ii;
            if (!strncmp(actual_path, (char*)(entry->filename), MAX_FILENAME_LEN-1))
            {
                // Match
                DEBUG("Matched getattr query with file");
                set_stat(entry, stbuf);
                rc = 0;
                break;
            }

        }
    }
    else
    {
        WARN("getattr called with unexpected path: %s", path);
    }

    pthread_mutex_unlock(&(cbm->mutex));

    DEBUG("EXIT: cbm_getattr()");

    return rc;
}

static void check_realloc_buffer(char **buffer,
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

static int remove_trailing_spaces(char *str) {
    int len = (int)strlen(str);
    int ii;

    // Iterate from the end of the string towards the beginning
    for (ii = len - 1; ii >= 0; ii--)
    {
        if (str[ii] != ' ')
        {
            break;
        }
    }

    // Terminate the string after the last non-space character
    str[ii + 1] = '\0';

    return (ii + 1);
}

static void realloc_dir_entries(struct cbm_state *cbm, int line_count)
{
    if (line_count > cbm->num_dir_entries)
    {
        // We can't reuse - better free and malloc a new one
        if (cbm->dir_entries != NULL)
        {
            free(cbm->dir_entries);
            cbm->dir_entries = NULL;
        }
        cbm->dir_entries = malloc((size_t)line_count * sizeof(struct cbm_dir_entry));
        if (cbm->dir_entries != NULL)
        {
            cbm->num_dir_entries = line_count;
        }
        else
        {
            cbm->num_dir_entries = 0;
            goto EXIT;
        }
    }
    memset(cbm->dir_entries, 0, (size_t)line_count * sizeof(struct cbm_dir_entry));

EXIT:

    return;
}

static int read_dir_from_disk(struct cbm_state *cbm)
{
    unsigned int buf_len;
    unsigned int data_len;
    unsigned int pos;
    char *buffer = NULL;
    int rc = 0;
    int error;
    char c;
    int line_count;
    struct cbm_dir_entry *dir_entry = NULL;

    INFO("read_dir_from_disk");

    cbm->dir_is_clean = 0;

    // malloc a buffer to store data read from the disk in
    DEBUG("Allocate buffer to read in data");
    buf_len = BUF_INC;
    buffer = malloc(buf_len);
    if (buffer == NULL)
    {
        DEBUG("Failed to allocate memory for buffer to read dir into");
        rc = -ENOMEM;
        goto EXIT;
    }

    // open the directory "file" ($)
    DEBUG("Open $");
    c = cbm_ascii2petscii_c('$');
    error = cbm_open(cbm->fd, cbm->device_num, 0, &c, 1);
    if (error)
    {
        DEBUG("Open of $ failed");
        rc = -EIO;
        goto EXIT;
    }
    cbm_talk(cbm->fd, cbm->device_num, 0);

    // Read in directory listing from the drive
    DEBUG("Read in directory data");
    pos = 0;
    while (cbm_raw_read(cbm->fd, buffer + pos, 1) == 1)
    {
        pos++;
        if (pos >= buf_len)
        {
            check_realloc_buffer(&buffer, &buf_len, pos);

        }
        if (buffer == NULL)
        {
            DEBUG("Out of memory while reading directory");
            rc = -ENOMEM;
            goto EXIT;
        }
    }
    data_len = pos;
    DEBUG("Read %d bytes total directory listing", data_len);

    cbm_untalk(cbm->fd);
    if (check_drive_status(cbm))
    {
        DEBUG("Hit error reading from disk");
        goto EXIT;
    }
    cbm_close(cbm->fd, cbm->device_num, 0);

    // Estimate how many lines there are - we'll estimate 28 bytes to a line
#define APPROX_BYTES_IN_DIR_LINE 28
    DEBUG("Calculate appox number of lines in directory listing");
    int approx_line_count = (int)(data_len / APPROX_BYTES_IN_DIR_LINE + (data_len % APPROX_BYTES_IN_DIR_LINE ? 1 : 0));
    DEBUG("Approximate number of lines in directory listing: %d", approx_line_count);
    if (approx_line_count <= 0)
    {
        DEBUG("0 lines in directory listing");
        goto EXIT;
    }

    DEBUG("Realloc directory entries");
    realloc_dir_entries(cbm, approx_line_count);
    if (cbm->dir_entries == NULL)
    {
        DEBUG("Failed to allocate memory for directory entries");
        rc = -ENOMEM;
        goto EXIT;
    }

    // Note our number of directory entries may be wrong - we'll figure this out
    // later

    // Check 1st 3 bytes
    DEBUG("Check 1st 4 bytes of listing");
    pos = 0;
    if (data_len < 4)
    {
        DEBUG("Fewer than 4 bytes in whole dir listing");
        goto EXIT;
    }
    if ((buffer[0] != 0x1) ||
        (buffer[1] != 0x4) ||
        (buffer[2] != 0x1) ||
        buffer[3] != 0x1)
    {
        DEBUG("Unexpected first 4 bytes: 0x%x 0x%x 0x%x 0x%x",
              buffer[0],
              buffer[1],
              buffer[2],
              buffer[3]);
        goto EXIT;
    }
    pos += 4;

    // Now read lines
    DEBUG("Read lines of listing");
    dir_entry = cbm->dir_entries;
    assert(dir_entry != NULL);
    line_count = 0;
    while (pos < data_len)
    {
        DEBUG("Reading line of listing");

        // Check if have run out of dir_entries
        if (cbm->num_dir_entries < (line_count+1))
        {
            INFO("Estimated number of lines in directory incorrectly");
            realloc_dir_entries(cbm, line_count+1);
            if (cbm->dir_entries == NULL)
            {
                DEBUG("Failed to reallocate memory for directory entries");
                rc = -ENOMEM;
                goto EXIT;
            }
        }
        
        DEBUG("Get blocks for this file");
        // Get the number of blocks for this file
        if (pos >= (buf_len + 2))
        {
            DEBUG("Ran out of data too soon");
            goto EXIT;
        }
        DEBUG("Next 2 bytes for block size: 0x%x 0x%x", (unsigned char)buffer[pos], (unsigned char)buffer[pos+1]);
        dir_entry->num_blocks = (unsigned char)buffer[pos++];
        // If the 2nd byte is 0x12 that means reverse text - so header
        // Assume any value below this is high order byte, any value
        // above this isn't.
        if (buffer[pos] < 0x12)
        {
            dir_entry->num_blocks |= (unsigned short)(buffer[pos++] << 8);
        }
        dir_entry->filesize = dir_entry->num_blocks * CBM_BLOCK_SIZE;
        DEBUG("Num blocks: %d, Filesize: %d", dir_entry->num_blocks, dir_entry->filesize);

        int filename_started = 0;
        int filename_ended = 0;
        int filename_len = 0;
        int is_header = 0;
        int is_footer = 0;
        int suffix_ended = 0;
        char suffix[4] = {0, 0, 0, 0};
        int suffix_len = 0;

        DEBUG("Read rest of line data");
        while ((pos < data_len) && 
               (buffer[pos] != 0x1))
        {
            c = buffer[pos];
            DEBUG("Got byte: 0x%x", c);
            if (is_footer)
            {
                // ignore the footer - just says "blocks free"
                DEBUG("Footer - ignore");
                assert(!filename_started);
            }
            else if (suffix_ended)
            {
                // ignore any remaining bytes
            }
            else if (!filename_started)
            {
                assert(!filename_ended);
                if (c == 0x20)
                {
                    // ignore leading spaces
                }
                else if (c == 0x12)
                {
                    DEBUG("Found header");
                    is_header = 1;
                    dir_entry->is_header = 1;
                    dir_entry->is_dir = 1;
                }
                else if (c == '"')
                {
                    DEBUG("Filename started");
                    filename_started = 1;
                }
                else if (c == 0x42) // PETSCII for b
                {
                    DEBUG("Found footer");
                    assert(!is_header);
                    is_footer = 1;
                }
            }
            else if (!filename_ended)
            {
                assert(!is_footer);
                if (c == '"')
                {
                    DEBUG("Filename ended");
                    filename_ended = 1;
                }
                else
                {
                    DEBUG("Add char to filename: %c", c);
                    // Any other char just gets added to the filename
                    // We'll cope with trailing spaces when appending the .XXX
                    // suffix
                    // We sade 5 chars for the 4 digit suffix and 1xNULL terminator
                    if (filename_len < (MAX_FILENAME_LEN - 5))
                    {
                        dir_entry->filename[filename_len] = cbm_petscii2ascii_c(c);
                        filename_len++;
                    }
                    else
                    {
                        WARN("Filename is longer than max len - truncated version is: %s", dir_entry->filename);
                    }
                }
            }
            else if (suffix_len > 0)
            {
                if (c == ' ')
                {
                    DEBUG("End of suffix: %s", suffix);
                    // Suffix has ended - we could match with valid ones, but
                    // we won't bother - instead we'll just add to the
                    // filename
                    filename_len = remove_trailing_spaces(dir_entry->filename);
                    assert(filename_len < (MAX_FILENAME_LEN - 5));
                    dir_entry->filename[filename_len] = dir_entry->is_header ? ',' : '.';
                    dir_entry->filename[filename_len+1] = 0;
                    strncat(dir_entry->filename, suffix, 4);
                    suffix_ended = 1;
                }
                else if (suffix_len < 3)
                {
                    DEBUG("Add char to suffix: %c", c);
                    suffix[suffix_len++] = cbm_petscii2ascii_c(c);
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
                    DEBUG("Ignore space after filename and before suffix");
                    // Ignore
                }
                else
                {
                    DEBUG("First char of suffix: %c", c);
                    suffix[suffix_len++] = cbm_petscii2ascii_c(c);
                }
            }

            // Move to next char
            pos++;
        }


        if (!is_footer)
        {
            DEBUG("Added directory entry #%d: header %d name %s size %d cbm blocks %d",
                line_count,
                dir_entry->is_header,
                dir_entry->filename,
                dir_entry->filesize,
                dir_entry->num_blocks);
            dir_entry++;
            line_count++;
        }

        // Don't add the footer
        if (pos >= (buf_len + 2))
        {
            DEBUG("Not enough data to read another line - exiting line parsing");
        }
        // Next two bytes should be 0x1 and 0x1, or 0x0 and 0x0 after footer
        DEBUG("Skipping next 2 bytes: 0x%d 0x%d", buffer[pos], buffer[pos+1]);
        pos += 2;
    }

    assert(line_count <= cbm->num_dir_entries);
    cbm->num_dir_entries = line_count;
    cbm->dir_is_clean = 1;
    rc = 0;

EXIT:

    DEBUG("Exiting read directory function");
    if (!rc)
    {
        DEBUG("Number of directory entries: %d is_clean: %d", cbm->num_dir_entries, cbm->dir_is_clean);
    }

    if (buffer != NULL)
    {
        free(buffer);
    }

    return rc;

}

static void *read_dir_from_disk_thread_func(void *vargp)
{
    struct cbm_state *cbm;
    int rc;
    
    assert(vargp != NULL);
    cbm = (struct cbm_state *)vargp;
    assert(cbm != NULL);

    pthread_mutex_lock(&(cbm->mutex));
    rc = read_dir_from_disk(cbm);
    pthread_mutex_unlock(&(cbm->mutex));

    // Ignore the return code - there's nothing we can do here, and 
    // read_dir_from_disk logs any errors itself 
    (void)rc;

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
    struct cbm_dir_entry entry;
    struct stat stbuf;

    struct cbm_state *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);

    pthread_mutex_lock(&(cbm->mutex));

    (void)fi;
#ifndef DEBUG_BUILD
    (void)flags;
    (void)offset;
#endif

    assert(path != NULL);

    DEBUG("ENTRY: cbm_readdir() path: %s offset: %ld flags: 0x%x",
          path,
          offset,
          flags);

    // Check we support the directory being queried.
    DEBUG("Check if we support this path: %s", path);
    if (!is_special_dir(path))
    {
        DEBUG("Attempt to read non-existant path: %s", path);
        rc = -ENOENT;
        goto EXIT;
    }

    // If the path isn't / we return nothing (no files)
    if (strcmp(path, "/") && strcmp(path+1, PATH_FORCE_DISK_REREAD))
    {
        DEBUG("Special path, not / - exiting");
        rc = -ENOENT;
        goto EXIT;
    }

    // Re-read the disk if we didn't read cleanly last time
    DEBUG("Check if need to reread directory listing");
    if (!cbm->dir_is_clean || (!strcmp(path+1, PATH_FORCE_DISK_REREAD)))
    {
        rc = read_dir_from_disk(cbm);
        if (rc)
        {
            DEBUG("Failed to load directory listing");
            goto EXIT;
        }

        // We did successfully re-read, but we don't return any files here
        // as that would indicate that there are files below the reread
        // special dir
        rc = -ENOENT;
        goto EXIT; 
    }

    assert(cbm->dir_is_clean);


    // Add any special directories not in dir_entries first
    DEBUG("Fill in special directories");

    int ii;
    const char *sd;
    for (ii = 0, sd = special_dirs[ii]; sd != NULL; ii++, sd = special_dirs[ii])
    {
        DEBUG("Special dir: %s", sd);
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.filename, sd, MAX_FILENAME_LEN-1);
        entry.is_dir = 1;
        set_stat(&entry, &stbuf);
        rc = filler(buf, sd, &stbuf, 0, 0);
        if (rc)
        {
            WARN("FUSE filler returned error - directory listing will be truncated");
            goto EXIT;
        }
    }

    // Add any special files
    DEBUG("Fill in special files");
    stbuf.st_mode = S_IFREG | 0444;;
    stbuf.st_nlink = 1;
    const char *sf;
    for (ii = 0, sf = special_files[ii]; sf != NULL; ii++, sf = special_files[ii])
    {
        memset(&entry, 0, sizeof(entry));
        strncpy(entry.filename, sf, MAX_FILENAME_LEN-1);
        set_stat(&entry, &stbuf);
        DEBUG("Special file: %s", sf);
        rc = filler(buf, sf, &stbuf, 0, 0);
        if (rc)
        {
            WARN("FUSE filler returned error - directory listing will be truncated");
            goto EXIT;
        }
    }

    // Now create an entry for each file
    DEBUG("Add files from disk to directory listing");
    for (ii = 0; ii < cbm->num_dir_entries; ii++)
    {
        struct cbm_dir_entry *pentry = cbm->dir_entries + ii;
        DEBUG("Regular file: %s", pentry->filename);
        set_stat(pentry, &stbuf);
        rc = filler(buf, pentry->filename, &stbuf, 0, 0);
        if (rc)
        {
            WARN("FUSE filler returned error - directory listing will be truncated");
            goto EXIT;
        }
    }

EXIT:

    pthread_mutex_unlock(&(cbm->mutex));

    DEBUG("EXIT:  cbm_readdir()");

    return 0;
}

static int allocate_free_channel(struct cbm_state *cbm,
                                 enum cbm_channel_usage usage,
                                 const char *filename)
{
    int min, max;
    int ch = -1;

    assert(cbm != NULL);
    assert(usage != USAGE_NONE);

    // Figure out valid channels based on usage
    switch (usage)
    {
        case USAGE_READ:
            min = 0;
            max = 0;
            break;

        case USAGE_WRITE:
            min = 1;
            max = 1;
            break;

        case USAGE_CONTROL:
            min = 15;
            max = 15;
            break;

        case USAGE_OPEN:
            min = MIN_USER_CHANNEL;
            max = MAX_USER_CHANNEL;
            break;

        default:
            assert(0);
            goto EXIT;
            break;
    }

    // Find a free channel
    for (ch = min; ch <= max; ch++)
    {
        if (!cbm->channel[ch].open)
        {
            // Found a free channel
            break;
        }
    }

    if (ch <= max)
    {
        // Found a valid channel
        assert(cbm->channel[ch].num == ch);
        cbm->channel[ch].open = 1;
        cbm->channel[ch].usage = usage;
        strncpy(cbm->channel[ch].filename, filename, MAX_FILENAME_LEN-1);
    }

EXIT:

    return ch;
}

// Must not be called with dummy channel!
void cbm_free_channel(struct cbm_state *cbm, int ch)
{
    assert(cbm != NULL);
    assert((ch >= 0) && (ch < NUM_CHANNELS));

    assert(cbm->channel[ch].num == ch);
    assert(cbm->channel[ch].open);

    memset(cbm->channel+ch, 0, sizeof(struct cbm_channel));
    cbm->channel[ch].num = (unsigned char)ch;
}

static int cbm_fuseopen(const char *path, struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int ch = -1;

    struct cbm_state *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);

    if (strlen(path) > (MAX_FILENAME_LEN-1))
    {
        WARN("Request to open file with filename exceeding max length failed: %s", path);
        goto EXIT;
    }

    if ((!strcmp(path, PATH_FORMAT_DISK)))
    {
        DEBUG("Request to open special file: %s", path);
        fi->fh = DUMMY_CHANNEL;
        rc = 0;
        goto EXIT;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Check if the directory listing is clean
    if (!cbm->dir_is_clean)
    {
        rc = read_dir_from_disk(cbm);
        if (!rc)
        {
            WARN("Failed to load directory listing prior to opening file: %s", path);
            goto EXIT;
        }
    }

    // Lookup the file in dir_entries
    struct cbm_dir_entry *entry = NULL;
    for (int ii = 0; ii < cbm->num_dir_entries; ii++)
    {
        if (!strcmp(path, cbm->dir_entries[ii].filename))
        {
            entry = cbm->dir_entries + ii;
            break;
        }
    }
    if (entry == NULL)
    {
        WARN("Request to open non-existant file: %s", path);
        goto EXIT;
    }

    // Header is a special case - there's no file to open
    if (entry->is_header)
    {
        DEBUG("Request to open header");
        fi->fh = DUMMY_CHANNEL;
        rc = 0;
        goto EXIT;
    }

    // Allocate a channel to communicate to the drive with
    ch = allocate_free_channel(cbm, USAGE_OPEN, path);
    if (ch < 0)
    {
        WARN("Failed to allocate a free channel to open file: %s", path);
        goto EXIT;
    }

    // Open the file on the disk drive
    rc = cbm_open(cbm->fd, cbm->device_num, (unsigned char)ch, path, strlen(path));
    if (!rc)
    {
        rc = check_drive_status(cbm);
        (void)rc;
        WARN("Failed to open file: %s channel: %d", path, ch);
        WARN("Drive status: %s", cbm->error_buffer);
        rc = -1;
        goto EXIT;
    }
    
    DEBUG("Succeeded in opening file: %s channel: %d", path, ch);
    fi->fh = (long unsigned int)ch;
    rc = 0;

EXIT:

    if (locked)
    {
        pthread_mutex_lock(&(cbm->mutex));
    }

    return rc;
}

static int cbm_release(const char *path, struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int ch;
    struct cbm_channel *channel;

    struct cbm_state *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);

    ch = (int)(fi->fh);

    if (ch == DUMMY_CHANNEL)
    {
        DEBUG("Release for dummy file: %s", path);
        rc = 0;
        goto EXIT;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    assert((ch >= 0) && (ch < NUM_CHANNELS));
    channel = cbm->channel+ch;
    assert(!strcmp(path, channel->filename));

    rc = cbm_close(cbm->fd, cbm->device_num, (unsigned char)ch);
    if (!rc)
    {
        rc = check_drive_status(cbm);
        (void)rc;
        WARN("Hit error closing channel %d", ch);
        WARN("Drive status: %s", cbm->error_buffer);
        rc = -1;
        goto EXIT;
    }

    cbm_free_channel(cbm, ch);
    rc = 0;
    DEBUG("Release for file: %s channel: %d", path, ch);

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    return rc;
}

static struct cbm_dir_entry *cbm_get_dir_entry(struct cbm_state *cbm,
                                               const char *filename)
{
    struct cbm_dir_entry *entry = NULL;

    assert(cbm != NULL);
    assert(filename != NULL);

    for (int ii = 0; ii < cbm->num_dir_entries; ii++)
    {
        if (!strcmp(filename, cbm->dir_entries[ii].filename))
        {
            entry = cbm->dir_entries + ii;
            break;
        }
    }

    return entry;
}

static int cbm_read(const char *path,
                    char *buf,
                    size_t size,
                    off_t offset,
                    struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int ch;
    struct cbm_channel *channel;
    unsigned int len;
    struct cbm_dir_entry *entry;
    char *temp_buf = NULL;

    struct cbm_state *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);
    assert(offset >= 0);

    ch = (int)(fi->fh);

    if (ch == DUMMY_CHANNEL)
    {
        if (!strcmp(path+1, PATH_FORMAT_DISK))
        {
            len = strlen(FORMAT_CONTENTS);
            if (offset < len)
            {
                if ((long unsigned int)offset + size > len)
                {
                    size = len - (long unsigned int)offset;
                }
                memcpy(buf, FORMAT_CONTENTS, size);
            }
            else
            {
                size = 0;
            }
            rc = (int)size;
            goto EXIT;

        }
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    assert((ch >= 0) && (ch < NUM_CHANNELS));
    channel = cbm->channel+ch;
    assert(!strcmp(path, channel->filename));

    entry = cbm_get_dir_entry(cbm, path);
    if (entry == NULL)
    {
        WARN("Couldn't find file which is apparently open: %s channel %d", path, ch);
        goto EXIT;
    }
    if (entry->is_header)
    {
        // We expose a size of 0 for the header
        assert(entry->filesize == 0);
        size = 0;
        goto EXIT;
    }

    // TO DO - actually read in the file
    rc = cbm_talk(cbm->fd, cbm->device_num, (unsigned char)ch);
    if (rc)
    {
        rc = check_drive_status(cbm);
        (void)rc;
        WARN("Hit error instructing drive to talk, to read file %s channel %d", path, ch);
        WARN("Drive status: %s", cbm->error_buffer);
        goto EXIT;
    }

    // TO DO = store this off in the channel info, so we don't need to read
    // again if the kernel asks us for more of the file.

    // Allocate temporary buffer to read entire file into
    len = entry->filesize;
    temp_buf = malloc(len);
    if (temp_buf == NULL)
    {
        WARN("Failed to malloc buffer to read in file: %s", path);
        goto EXIT;
    }
    rc = cbm_raw_read(cbm->fd, buf, len);
    if (rc < 0)
    {
        rc = check_drive_status(cbm);
        (void)rc;
        WARN("Hit error reading file %s channel %d", path, ch);
        WARN("Drive status: %s", cbm->error_buffer);
        cbm_untalk(cbm->fd);
    }
    else if ((unsigned int)rc < len)
    {
        WARN("Couldn't read the whole of file %s channel %d", path, ch);
        goto EXIT;
    }
    if ((unsigned int)offset < len)
    {
        if ((long unsigned int)offset + size > len)
        {
            size = len - (long unsigned int)offset;
        }
        memcpy(buf, temp_buf+offset, size);
    }
    else
    {
        size = 0;
    }
    rc = (int)size;
    goto EXIT;

EXIT:

    if (temp_buf != NULL)
    {
        free(temp_buf);
    }

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    return rc;
}

static const struct fuse_operations cbm_oper =
{
    .init     = cbm_init,
    .destroy  = cbm_destroy,
    .getattr  = cbm_getattr,
    .readdir  = cbm_readdir,
    .open     = cbm_fuseopen,
    .release  = cbm_release,
    .read     = cbm_read,
};

static struct options
{
    char *device_num;
    int show_help;
    int show_version;
    int force_bus_reset;
} options;

static char *mountpoint; 

#define OPTION(t, p) \
    { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
    OPTION("-d %s", device_num),
    OPTION("--device %s", device_num),
    OPTION("--version", show_version),
    OPTION("-?", show_help),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    OPTION("-b", force_bus_reset),
    OPTION("--bus-reset", force_bus_reset),
    FUSE_OPT_KEY("-f", FUSE_OPT_KEY_KEEP),
    FUSE_OPT_END
};

// Called by fuse_opt_parse when a non-option (-o) argument is found so we can
// handle it
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

// Set up logging to syslog/messages.
void init_logging()
{
    openlog(APP_NAME, LOG_PID | LOG_CONS, LOG_DAEMON);
}

// We need to expose cbm to the signal handler so it can cleanup.  We do so
// via a signal handler struct in order to discourage other functions from
// accessing cbm this way.  Other functions within the fuse context should
// get using fuse_get_context()->private_data.
struct signal_handler_data {
    struct cbm_state *cbm;
};
static struct signal_handler_data shd; 

void handle_signal(int signal)
{
    // Grab the signal handler data
    // Technically this isn't thread safe - another thread could be in the
    // process of accessing this CBM, which is controlled via a contained
    // mutex.  But we can't help that, as a signal could be caught and handled
    // while the lock is held.
    struct cbm_state *cbm = shd.cbm;

    // Try and unmount and destroy fuse
    // We won't bother to get the mutex, because it may well be locked already
    // For a similar reason we won't bother locking the mutex
    // We will free cbm
    // Note that there's an extra step here that isn't in the main cleanup
    // code - we will call fuse_exit.  In main, fuse will already have exited
    // before the cleanup code is called.
    switch (signal)
    {
        default:
            // TO DO: Consider whether we can safely reset the drive to stop
            // it spinning (if it is)
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

int process_args(struct fuse_args *args, struct cbm_state *cbm)
{
    int ret = 1;
    struct fuse_cmdline_opts fuse_opts = { 0 };

    assert(args != NULL);
    assert(cbm != NULL);

    // First parse custom options
    DEBUG("Parse args");
    if (fuse_opt_parse(args, &options, option_spec, opt_proc) == -1)
    {
        ERROR("Failed to parse options");
        goto EXIT;
    }

    // Then let FUSE parse its built-in options
    DEBUG("Parse fuse args");
    if (fuse_parse_cmdline(args, &fuse_opts) == -1)
    {
        ERROR("Failed to parse FUSE options\n");
        goto EXIT;
    }

    // Now handle our args
    if (options.show_version)
    {
        printf("1541fs-fuse version %s\n", VERSION);
        ret = -1;
        goto EXIT;
    }
    if (options.show_help)
    {
        printf("1541fs-fuse\n");
        printf("\n");
        printf("Mounts one or more XUM1541 attached Commodore disk drives as a linux FUSE\nfilesystem.\n");
        printf("\n");
        printf("Usage:\n");
        printf("  1541fs-fuse [options] mountpoint\n");
        printf("    -d|--device <device_num=8|9|10|11>  set device number (default: 8)\n");
        printf("    -b|--bus-reset         force a bus (IEC/IEEE-488) reset before mount");
        printf("    -?|-h|--help           show help\n");
        printf("    --version              show version\n");
        fuse_lib_help(args);
        ret = -1;
        goto EXIT;
    }
    if (mountpoint == NULL)
    {
        WARN("No mountpint defined - exiting");
        printf("No mountpoint defined - exiting\n");
        goto EXIT;
    }
    cbm->force_bus_reset = options.force_bus_reset;
    if (options.device_num == NULL)
    {
        cbm->device_num = DEFAULT_DEVICE_NUM;
        INFO("No device number specified - defaulting to device 8");
    }
    else
    {
        int device_num = atoi(options.device_num);
        assert(MIN_DEVICE_NUM >= 0);
        assert(MIN_DEVICE_NUM < 256);
        assert(MAX_DEVICE_NUM < 256);
        if ((device_num < MIN_DEVICE_NUM) || (device_num > MAX_DEVICE_NUM))
        {
            WARN("Invalid device number specified: %s", options.device_num);
            printf("Invalid device number specified: %s\n", options.device_num);
            goto EXIT;
        }
        else
        {
            cbm->device_num = (unsigned char)device_num;
        }
    }
    INFO("Using device number: %d", cbm->device_num);
    printf("Using device number: %d\n", cbm->device_num);
    fflush(stdout);

    ret = 0;

EXIT:

    return ret;
}

struct cbm_state *allocate_private_data(void)
{
    // Allocate and zero memory
    struct cbm_state *cbm = malloc(sizeof(struct cbm_state));
    if (cbm == NULL)
    {
        ERROR("Failed to allocate memory");
        goto EXIT;
    }
    memset(cbm, 0, sizeof(struct cbm_state));

    // Set up channels
    for (unsigned char ch = 0; ch < NUM_CHANNELS; ch++)
    {
        cbm->channel[ch].num = ch;
    }

EXIT:

    return cbm;
} 

int main(int argc, char *argv[])
{
    struct cbm_state *cbm;
    int ret = 1;

    // Set up first, as the signal handler will need access
    DEBUG("Allocate private data");
    cbm = allocate_private_data();
    cbm = calloc(1, sizeof(struct cbm_state));
    if (cbm == NULL)
    {
        ERROR("Failed to allocate memory\n");
        goto EXIT;
    }
    shd.cbm = cbm;
    cbm->fuse_fh = -1;
    DEBUG("Private data allocated");

    // Set up next, before anything else happens, so we can gracefully handle
    // signals
    DEBUG("Setup signal handler");
    setup_signal_handler();

    // Process command line args
    DEBUG("Init fuse arg");
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    ret = process_args(&args, cbm);
    if (ret)
    {
        // Return code of -1 means exit, but with 0 return code
        // Return code of 1 means exit with 1 return code
        // Return code of 0 means args processed successfully
        if (ret < 0)
        {
            ret = 0;
        }
        goto EXIT;
    }

    // Create a fuse object
    DEBUG("Fuse new");
    cbm->fuse = fuse_new_30(&args, &cbm_oper, sizeof(cbm_oper), cbm);
    if (cbm->fuse == NULL)
    {
        ERROR("Failed to create FUSE object\n");
        goto EXIT;
    }

    // Attempt the mount - this will call our _init() function, which in turn
    // will, assuming everything else is OK, will start a thread to do an
    // immediate directory read, caching it so we are ready to return that
    // quickly when required.
    // Any failure in _init() will cause fuse_exit() to be called.  That will
    // in turn cause the fuse_loop below to exit, meaning we can clean up and
    // exit.
    DEBUG("Fuse mount");
    cbm->fuse_fh = fuse_mount(cbm->fuse, mountpoint);
    if (cbm->fuse_fh == -1)
    {
        ERROR("Failed to mount FUSE filesystem\n");
        goto EXIT;
    }

    // Start the main fuse_loop and run forever - or until we hit a fatal
    // or catch and handle a signal
    DEBUG("Fuse loop");
    cbm->fuse_loop = 1;
    ret = fuse_loop(cbm->fuse);
    cbm->fuse_exited = 1;

EXIT:

    INFO("Exiting\n");

    // Cleanup code
    // The signal handler has similar processing, in case this isn't run
    // Note neither this code nor the signal handler attempts to destroy our
    // mutex, to avoid hanging, or undefied behaviour, if it's locked.
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
        shd.cbm = NULL;
    }

    return ret;
}   