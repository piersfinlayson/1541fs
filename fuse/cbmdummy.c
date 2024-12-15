#include "cbmfuse.h"

// Details about dummy files

#define MIN_HANDLE_DUMMY 1
#define MAX_HANDLE_DUMMY 6
#define HANDLE_DUMMY_DIR_DOT    1
#define HANDLE_DUMMY_DIR_DOTDOT 2

#define HANDLE_DUMMY_FILE_FORMAT_DISK 3
#define PATH_FILE_FORMAT_DISK "format_disk.cmd"
#define CONTENTS_FILE_FORMAT_DISK \
    "To format a disk write the new disk name followed by the ID to this file.\n" \
    "The disk name can be a maximum of 16 characters and the ID two digits.\n" \
    "Separate the two with a comma.  For example:\n" \
    "  echo \"my new disk,01\" > ./" PATH_FILE_FORMAT_DISK "\n"

#define HANDLE_DUMMY_FILE_DISK_REREAD 4
#define PATH_FILE_DISK_REREAD  "disk_reread.cmd"
#define CONTENTS_FILE_DISK_REREAD \
    "To force a disk re-read, write anything to this file.  For example:\n" \
    "  echo \"1\" > ./" PATH_FILE_DISK_REREAD "\n"

#define HANDLE_DUMMY_SHOW_LAST_STATUS     5
#define PATH_SHOW_LAST_STATUS       "show_status.cmd"

#define HANDLE_DUMMY_RECHECK_DRIVE_STATUS     6
#define PATH_RECHECK_DRIVE_STATUS       "recheck_status.cmd"

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
        HANDLE_DUMMY_FILE_FORMAT_DISK,
        0,
        PATH_FILE_FORMAT_DISK,
        sizeof(CONTENTS_FILE_FORMAT_DISK),
        CONTENTS_FILE_FORMAT_DISK,
        NULL,
    },
    {
        HANDLE_DUMMY_FILE_DISK_REREAD,
        0,
        PATH_FILE_DISK_REREAD,
        sizeof(CONTENTS_FILE_DISK_REREAD),
        CONTENTS_FILE_DISK_REREAD,
        NULL,
    },
    {
        HANDLE_DUMMY_SHOW_LAST_STATUS,
        0,
        PATH_SHOW_LAST_STATUS,
        64,
        NULL,
        NULL,
    },
    {
        HANDLE_DUMMY_RECHECK_DRIVE_STATUS,
        0,
        PATH_RECHECK_DRIVE_STATUS,
        64,
        NULL,
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

    if ((handle == HANDLE_DUMMY_SHOW_LAST_STATUS) ||
        (handle == HANDLE_DUMMY_RECHECK_DRIVE_STATUS))
    {
        // TO DO need to check this will all fit in size!
        assert(size >= 32);
        DEBUG("Request to read drive status, size %zu offset %zu", size, offset);
        if (handle == HANDLE_DUMMY_RECHECK_DRIVE_STATUS)
        {
            rc2 = check_drive_status(cbm);
            (void)rc2;
        }
        memcpy(buf, cbm->error_buffer, strlen(cbm->error_buffer));
        rc = (int)strlen(cbm->error_buffer);
        buf[rc] = '\n';
        rc++;
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
        case HANDLE_DUMMY_FILE_DISK_REREAD:
            // So long as the size was greater than 0, it doesn't matter what
            // was written - we will kick off a disk reread
            DEBUG("Valid write request to reread disk - kicking off");
            cbm->dir_is_clean = 0;
            cbm_create_read_dir_thread(cbm);
            rc = (int)size;
            break;

        case HANDLE_DUMMY_FILE_FORMAT_DISK:
            // Received some data requesting that we format the disk
            // Technically it's possible we're only receiving part of what's
            // been written to the file - or the user might want to write
            // part of the new header, and then the rest, and hence we'd get
            // multiple write requests.  But whatever, we're going to assume
            // This is all we're getting.  A subsequent write will be
            // processed on its own merits
            rc = process_format_request(cbm, buf, size);
            break;

        case HANDLE_DUMMY_SHOW_LAST_STATUS:
        case HANDLE_DUMMY_RECHECK_DRIVE_STATUS:
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
