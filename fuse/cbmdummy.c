#include "cbmfuse.h"

// Details about dummy files

#define MIN_HANDLE_DUMMY 1
#define MAX_HANDLE_DUMMY 8
#define HANDLE_DUMMY_DIR_DOT    1
#define HANDLE_DUMMY_DIR_DOTDOT 2

#define HANDLE_DUMMY_FILE_DISK_FORMAT 3
#define PATH_FILE_DISK_FORMAT "disk_format.cmd"
#define CONTENTS_FILE_DISK_FORMAT \
    "To format a disk write the new disk name followed by the ID to this file.\n" \
    "The disk name can be a maximum of 16 characters and the ID two digits.\n" \
    "Separate the two with a comma.  For example:\n" \
    "  echo \"my new disk,01\" > ./" PATH_FILE_DISK_FORMAT "\n"

#define HANDLE_DUMMY_FILE_DIR_REREAD 4
#define PATH_FILE_DIR_REREAD  "dir_reread.cmd"
#define CONTENTS_FILE_DIR_REREAD \
    "To force a disk re-read, write anything to this file.  For example:\n" \
    "  echo \"1\" > ./" PATH_FILE_DIR_REREAD "\n"

#define HANDLE_DUMMY_GET_LAST_STATUS     5
#define PATH_GET_LAST_STATUS      GET_LAST_STATUS_CMD

#define HANDLE_DUMMY_GET_LAST_ERROR     6
#define PATH_GET_LAST_ERROR       GET_LAST_ERROR_CMD

#define HANDLE_DUMMY_GET_STATUS_NOW      7
#define PATH_GET_STATUS_NOW       "get_status_now.cmd"

#define HANDLE_DUMMY_EXEC_COMMAND        8
#define PATH_EXEC_COMMAND         "exec_command.cmd"
#define CONTENTS_EXEC_COMMAND \
    "To execute a command write the command to this file.  For example, to\n" \
    "scratch file 1 write:\n" \
    "  echo \"scratch:1\" > ./" PATH_EXEC_COMMAND "\n"

struct dummy_entry
{
    int handle;
    int dir;
    const char *filename;
    const off_t filesize;
    const char *contents;
    const struct callbacks *cbs;
};

const struct dummy_entry dummies[] =
{
    { 
        HANDLE_DUMMY_DIR_DOT,
        1,
        ".",
        0,
        NULL,
        NULL,
    },
    {
        HANDLE_DUMMY_DIR_DOT,
        1,
        "..",
        0,
        NULL,
        NULL,
    },
    {
        HANDLE_DUMMY_FILE_DISK_FORMAT,
        0,
        PATH_FILE_DISK_FORMAT,
        sizeof(CONTENTS_FILE_DISK_FORMAT),
        CONTENTS_FILE_DISK_FORMAT,
        NULL,
    },
    {
        HANDLE_DUMMY_FILE_DIR_REREAD,
        0,
        PATH_FILE_DIR_REREAD,
        sizeof(CONTENTS_FILE_DIR_REREAD),
        CONTENTS_FILE_DIR_REREAD,
        NULL,
    },
    {
        HANDLE_DUMMY_GET_LAST_STATUS,
        0,
        PATH_GET_LAST_STATUS,
        100, // Set to status OK (100 + 00 OK)
        NULL,
        NULL,
    },
    {
        HANDLE_DUMMY_GET_LAST_ERROR,
        0,
        PATH_GET_LAST_ERROR,
        100, // Set to status OK
        NULL,
        NULL,
    },
    {
        HANDLE_DUMMY_GET_STATUS_NOW,
        0,
        PATH_GET_STATUS_NOW,
        99, // use 99 to indicate not a valid error 
        NULL,
        NULL,
    },
    {
        HANDLE_DUMMY_EXEC_COMMAND,
        0,
        PATH_EXEC_COMMAND,
        sizeof(CONTENTS_EXEC_COMMAND),
        CONTENTS_EXEC_COMMAND,
        NULL,
    },
    { 0 },
};

static int check_dummy_valid(int handle)
{
    int rc = -1;

    if ((handle < MIN_HANDLE_DUMMY) || (handle > MAX_HANDLE_DUMMY))
    {
        DEBUG("Invalid dummy file %d", handle);
        rc = -ENOENT;
    }
    else
    {
        DEBUG("Valid dummy file %d %s",
            handle,
            dummies[handle-1].filename);
        rc = 0;
    }

    return rc;
}

static int handle_dummy_open(CBM *cbm,
                            int handle,
                            struct cbm_file *entry,
                            const char *path,
                            struct fuse_file_info *fi)
{
    int rc = -1;
    (void)cbm;
    (void)entry;
    (void)path;
    (void)fi;

    ENTRY();

    rc = check_dummy_valid(handle);
    if (rc)
    {
        goto EXIT;
    }

    fi->fh = DUMMY_CHANNEL;
    rc = 0;

EXIT:

    EXIT();

    return rc;
}

static int handle_dummy_release(CBM *cbm,
                                int handle,
                                struct cbm_file *entry,
                                const char *path,
                                struct fuse_file_info *fi)
{
    int rc = -1;
    (void)cbm;
    (void)entry;
    (void)path;
    (void)fi;

    ENTRY();

    rc = check_dummy_valid(handle);
    if (rc)
    {
        goto EXIT;
    }

    // Don't know if we should reset this or not - but we will anyway
    fi->fh = 0;
    rc = 0;

EXIT:

    EXIT();

    return rc;
}

static int handle_dummy_read(CBM *cbm,
                            int handle,
                            struct cbm_file *entry,
                            const char *path,
                            char *buf,
                            size_t size,
                            off_t offset,
                            struct fuse_file_info *fi)
{
    int rc = -1;
    int rc2;
    const struct dummy_entry *dentry;
    const char *error_src;
    size_t error_len;
    (void)cbm;
    (void)entry;
    (void)path;
    (void)fi;

    ENTRY();

    rc = check_dummy_valid(handle);
    if (rc)
    {
        goto EXIT;
    }

    if (fi->fh != DUMMY_CHANNEL)
    {
        rc = -EBADF;
        goto EXIT;
    }

    dentry = &(dummies[handle-1]);

    // Check it's not a directory - we don't support reading from these
    if (dentry->dir)
    {
        DEBUG("Request to read from dir %s not supported", dentry->filename);
        rc = -EISDIR;
        goto EXIT;
    }

    if ((handle == HANDLE_DUMMY_GET_STATUS_NOW) ||
        (handle == HANDLE_DUMMY_GET_LAST_STATUS) ||
        (handle == HANDLE_DUMMY_GET_LAST_ERROR))
    {
        // TO DO need to check this will all fit in size!
        if (size < MAX_ERROR_LENGTH)
        {
            rc = -ENOBUFS;
            goto EXIT;
        }
        DEBUG("Request to read drive status, size %zu offset %zu", size, offset);
        if (handle == HANDLE_DUMMY_GET_STATUS_NOW)
        {
            rc2 = check_drive_status(cbm);
            (void)rc2;
        }
        if ((handle == HANDLE_DUMMY_GET_STATUS_NOW) ||
            (handle == HANDLE_DUMMY_GET_LAST_STATUS))
        {
            error_src = cbm->error_buffer;
        }
        else
        {
            assert(handle == HANDLE_DUMMY_GET_LAST_ERROR);
            error_src = cbm->last_error;
        }
        DEBUG("Error string: %s", error_src);
        error_len = strlen(error_src);
        // error_len has to be less than MAX_ERROR_LENGTH to give space for
        // newline char we add.  Doesn't need to include NULL terminator
        assert(error_len < (MAX_ERROR_LENGTH-1));
        memcpy(buf, error_src, error_len);
        buf[error_len++] = '\n';
        rc = (int)error_len;
        goto EXIT;
    }

    // Copy the correct bit of the file into the buffer
    assert(dentry->contents != NULL);
    assert(offset >= 0);
    if (offset < dentry->filesize)
    {
        if ((size_t)offset + size > (size_t)dentry->filesize)
        {
            size = (size_t)(dentry->filesize - offset);
        }
        memcpy(buf, dentry->contents + (size_t)offset, size);
        rc = (int)size;
    }

EXIT:

    EXIT();

    return rc;
}

static int handle_dummy_write(CBM *cbm,
                            int handle,
                            struct cbm_file *entry,
                            const char *path,
                            const char *buf,
                            size_t size,
                            off_t offset,
                            struct fuse_file_info *fi)
{
    int rc = -1;
    const struct dummy_entry *dentry;
    (void)entry;
    (void)path;
    (void)fi;
    (void)buf;
    (void)size;
    (void)offset;

    ENTRY();

    rc = check_dummy_valid(handle);
    if (rc)
    {
        goto EXIT;
    }

    if (fi->fh != DUMMY_CHANNEL)
    {
        rc = -EBADF;
        goto EXIT;
    }

    dentry = &(dummies[handle-1]);

    // Check it's not a directory - we don't support reading from these
    if (dentry->dir)
    {
        DEBUG("Request to read from dir %s not supported", dentry->filename);
        rc = -EISDIR;
        goto EXIT;
    }

    if (size == 0)
    {
        WARN("Write request for 0 bytes to dummy file %s", dentry->filename);
        rc = 0;
        goto EXIT;
    }

    switch (handle)
    {
        case HANDLE_DUMMY_FILE_DIR_REREAD:
            // So long as the size was greater than 0, it doesn't matter what
            // was written - we will kick off a disk reread
            DEBUG("Valid write request to reread disk - kicking off");
            cbm->dir_is_clean = 0;
            cbm_create_read_dir_thread(cbm);
            rc = (int)size;
            break;

        case HANDLE_DUMMY_FILE_DISK_FORMAT:
            // Received some data requesting that we format the disk
            // Technically it's possible we're only receiving part of what's
            // been written to the file - or the user might want to write
            // part of the new header, and then the rest, and hence we'd get
            // multiple write requests.  But whatever, we're going to assume
            // This is all we're getting.  A subsequent write will be
            // processed on its own merits
            rc = process_format_request(cbm, buf, size);
            break;

        case HANDLE_DUMMY_EXEC_COMMAND:
            // Received some data requesting that we execute a command
            rc = process_exec_command(cbm, buf, size);
            break;

        case HANDLE_DUMMY_GET_LAST_STATUS:
        case HANDLE_DUMMY_GET_LAST_ERROR:
        case HANDLE_DUMMY_GET_STATUS_NOW:
            // We do not support writing to this file
            rc = -EROFS;
            break;

        default:
            assert(0);
            rc = -ENOENT;
            break;
    }

EXIT:

    EXIT();

    return rc;
}

// Creates cbm_file entries for all of our dummy files and directories
// Returns 0 on success, errno on failure
int create_dummy_entries(CBM *cbm)
{
    int rc = -1;
    struct callbacks dir_cbs;
    struct callbacks file_cbs =
    {
        .handle  = 0,
        .open    = handle_dummy_open,
        .release = handle_dummy_release,
        .read    = handle_dummy_read,
        .write   = handle_dummy_write,
    };
    const struct dummy_entry *entry;

    ENTRY();

    assert(cbm != NULL);

    // Set the callbacks 
    memset(&dir_cbs, 0, sizeof(dir_cbs));

    for (entry = dummies; entry->handle != 0; entry++)
    {
        struct callbacks *cbs;
        if (entry->dir)
        {
            cbs = &dir_cbs;
        }
        else
        {
            cbs = &file_cbs;
        }
        cbs->handle = entry->handle;
        create_dummy_file_entry(cbm,
                                entry->filename,
                                entry->dir,
                                entry->filesize,
                                cbs,
                                &rc);

        if (rc)
        {
            WARN("Hit error %d creating dummy dir: %s", rc, entry->filename);
            goto EXIT;
        }
    } 

    rc = 0;

EXIT:

    EXIT();

    return rc;
}
