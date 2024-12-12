#include "cbmfuse.h"

// Updated init function signature for FUSE3
static void *cbm_init(struct fuse_conn_info *conn,
                      struct fuse_config *cfg)
{
    (void)conn;
    (void)cfg;
    int failed = 0;
    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    int rc;

    // Create the mutex
    DEBUG("Create mutex");
    if (pthread_mutex_init(&(cbm->mutex), NULL) != 0)
    {
        ERROR("Failed to initialize mutex\n");
        return NULL;
    }
    else
    {
        cbm->mutex_initialized = 1;
    }

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
    if (rc)
    {
        WARN("Drive status query returned error: %s\n", cbm->error_buffer);
        cbm_driver_close(cbm->fd);
        cbm->fd = (CBM_FILE)0;
        failed = 1;
        goto EXIT;
    }
    
    cbm->is_initialized = 1;

    // Spawn a thread to read the disk, so it's faster to access this mount
    // later
    DEBUG("Spawn thread to read dir");
    cbm_create_read_dir_thread(cbm);

EXIT:

    if (failed)
    {
        if (cbm->mutex_initialized)
        {
            pthread_mutex_destroy(&cbm->mutex);
        }
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
// Not a static, as also called directly by main
void cbm_destroy(void *private_data)
{
    CBM *cbm = private_data;
    assert(cbm != NULL);

    if (cbm->is_initialized)
    {
        // Clear pending errors
        check_drive_status(cbm);
        cbm->is_initialized = 0;
    }
    if (cbm->fd != (CBM_FILE)0)
    {
        cbm_driver_close(cbm->fd);
        cbm->fd = (CBM_FILE)0;
    }
    if (cbm->mutex_initialized)
    {
        pthread_mutex_destroy(&(cbm->mutex));
        cbm->mutex_initialized = 0;
    }
}

// REWORK for cbm_file
// Updated getattr function signature for FUSE3
static int cbm_getattr(const char *path,
                       struct stat *stbuf,
                       struct fuse_file_info *fi)
{
    (void)fi; // fi is NULL if file is not open, and may be NULL if file is open
    int rc = -ENOENT;
    const char *actual_path;
    int sdir, sfile;

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(path != NULL);
    assert(stbuf != NULL);

    ENTRY();
    PARAMS("Path %s", path);

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
        entry.is_special = 1;
        if (!strcmp(path+1, PATH_FORMAT_DISK))
        {
            entry.filesize = strlen(FORMAT_CONTENTS);
        }
        else if (!strcmp(path+1, PATH_FORCE_DISK_REREAD))
        {
            entry.filesize = strlen(FORCE_DISK_REREAD_CONTENTS);
        }
        else
        {
            // Ignore - must be one of the dirs
        }
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

    EXIT();

    return rc;
}

// REWORK for cbm_file
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
    int locked = 0;

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);

    (void)fi;
#ifndef DEBUG_BUILD
    (void)flags;
    (void)offset;
#endif

    assert(path != NULL);

    ENTRY();
    PARAMS("Path %s offset %ld flags 0x%x",
          path,
          offset,
          flags);

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // If the path isn't / we return nothing (no files)
    if (strcmp(path, "/"))
    {
        DEBUG("Attempt to read path with isn't / - exiting");
        rc = -ENOENT;
        goto EXIT;
    }
    // Add any special directories not in dir_entries first
    DEBUG("Fill in special directories");
    int ii;
    const char *sd;
    for (ii = 0, sd = special_dirs[ii]; sd != NULL; ii++, sd = special_dirs[ii])
    {
        DEBUG("Special dir: %s", sd);
        memset(&entry, 0, sizeof(entry));
        entry.is_special = 1;
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
        entry.is_special = 1;
        if (!strcmp(sf, PATH_FORMAT_DISK))
        {
            entry.filesize = strlen(FORMAT_CONTENTS);
        }
        else if (!strcmp(sf, PATH_FORCE_DISK_REREAD))
        {
            entry.filesize = strlen(FORCE_DISK_REREAD_CONTENTS);
        }
        else
        {
            assert(0);
        }
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

    // Now onto files that are actually on the disk

    // Re-read the disk if we didn't read cleanly last time
    if (!cbm->dir_is_clean)
    {
        DEBUG("Re-eread directory listing from disk");
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

    // Create an entry for each file
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

    if (locked)
    {
    pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return 0;
}

// REWORK for cbm_file
static int cbm_fuseopen(const char *path, struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int rc2;
    int ch = -1;
    char actual_path[MAX_FILENAME_LEN];
    char *petscii_path;

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);

    ENTRY();
    PARAMS("Path %s", path);

    if (strlen(path) > (MAX_FILENAME_LEN-1))
    {
        WARN("Request to open file with filename exceeding max length failed: %s", path);
        rc = -ENAMETOOLONG;
        goto EXIT;
    }

    // Special file - just return OK using dummy channel
    if (is_special_file(path))
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
        if (rc)
        {
            WARN("Failed to load directory listing prior to opening file: %s", path);
            goto EXIT;
        }
    }

    // Copy path to actual_path (discardig leading /), so we can convert
    // to petscii later.  We already asserted path wasn't too long too copy
    strcpy(actual_path, path+1);

    // Lookup the file in dir_entries
    struct cbm_dir_entry *entry = NULL;
    for (int ii = 0; ii < cbm->num_dir_entries; ii++)
    {
        if (!strcmp(actual_path, cbm->dir_entries[ii].filename))
        {
            DEBUG("Found file");
            entry = cbm->dir_entries + ii;
            break;
        }
    }

    // It's OK if we didn't find a file - we will create it
    // This would be the case where we wanted to write the file, for example
    if ((entry != NULL) && entry->is_header)
    {
        // Header is a special case - there's no file to open
        DEBUG("Request to open header");
        fi->fh = DUMMY_CHANNEL;
        rc = 0;
        goto EXIT;
    }

    // Allocate a channel to communicate to the drive with
    DEBUG("Allocate free channel");
    ch = allocate_free_channel(cbm, USAGE_OPEN, actual_path);
    if (ch < 0)
    {
        WARN("Failed to allocate a free channel to open file: %s", actual_path);
        rc = -EMFILE; // Too many open files
        goto EXIT;
    }

    // Open the file on the disk drive
    petscii_path = cbm_petscii2ascii(strtok(actual_path, "."));
    DEBUG("Open file on disk drive - petscii filename: %s", petscii_path);

    rc = cbm_open(cbm->fd, cbm->device_num, (unsigned char)ch, petscii_path, strlen(petscii_path));
    if (rc)
    {
        rc2 = check_drive_status(cbm);
        (void)rc2;
        WARN("Failed to open file: %s channel: %d", actual_path, ch);
        WARN("Drive status: %d %s", rc, cbm->error_buffer);
        goto EXIT;
    }
    
    DEBUG("Succeeded in opening file: %s channel: %d", actual_path, ch);
    fi->fh = (long unsigned int)ch;
    rc = 0;

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
}

// REWORK for cbm_file (doesn't use dir_entry but prob should!)
static int cbm_release(const char *path, struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int rc2;
    int ch;
    struct cbm_channel *channel;
    const char *actual_path;

    ENTRY();

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);

    ch = (int)(fi->fh);
    actual_path = path+1;

    // Just OK releasing the dummy channel - as we didn't do anything when
    // opening it
    if (ch == DUMMY_CHANNEL)
    {
        DEBUG("Release for dummy file: %s", actual_path);
        rc = 0;
        goto EXIT;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Get the channel based on the handle
    assert((ch >= 0) && (ch < NUM_CHANNELS));
    channel = cbm->channel+ch;
    if (strcmp(actual_path, channel->filename))
    {
        DEBUG("Filename provided on release doesn't match that for channel %d", ch);
        rc = -EBADF;
        goto EXIT;
    }

    rc = cbm_close(cbm->fd, cbm->device_num, (unsigned char)ch);
    if (rc)
    {
        rc2 = check_drive_status(cbm);
        (void)rc2;
        WARN("Hit error closing channel %d %d", ch, rc);
        WARN("Drive status: %s", cbm->error_buffer);
        goto EXIT;
    }

    // Clear the channel handles
    if (channel->handle1 != NULL)
    {
        DEBUG("Freeing buffer stored in channel");
        free(channel->handle1);
        channel->handle1 = NULL;
        channel->handle2 = 0;
    }

    // Release channel back to pool
    release_channel(cbm, ch);

    rc = 0;
    DEBUG("Release %s channel %d", actual_path, ch);

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
}

// DELETE (replaced by find_cbm_file_entry)
static struct cbm_dir_entry *cbm_get_dir_entry(CBM *cbm,
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

// REWORK for cbm_file
static int cbm_read(const char *path,
                    char *buf,
                    size_t size,
                    off_t offset,
                    struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int rc2;
    int ch;
    struct cbm_channel *channel;
    unsigned int len;
    struct cbm_dir_entry *entry;
    char *temp_buf = NULL;
    const char *actual_path;
    char *dummy_contents;
    off_t total_read;

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);
    assert(offset >= 0);

    ENTRY();
    PARAMS("Path %s Size %lu Offset %ld", path, size, offset);

    ch = (int)(fi->fh);

    actual_path = path+1;

    if (ch == DUMMY_CHANNEL)
    {
        DEBUG("Request to read special file");
        if (!strcmp(actual_path, PATH_FORMAT_DISK))
        {
            dummy_contents = FORMAT_CONTENTS;
        }
        else if (!strcmp(actual_path, PATH_FORCE_DISK_REREAD))
        {
            dummy_contents = FORCE_DISK_REREAD_CONTENTS;
        }
        else
        {
            assert(0);
        }
        DEBUG("Request to read %s", actual_path);
        len = (unsigned int)strlen(dummy_contents);
        if (offset < len)
        {
            if ((long unsigned int)offset + size > len)
            {
                size = len - (long unsigned int)offset;
            }
            memcpy(buf, dummy_contents, size);
        }
        else
        {
            rc = 0;
        }
        rc = (int)size;
        goto EXIT;

    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    assert((ch >= 0) && (ch < NUM_CHANNELS));
    channel = cbm->channel+ch;
    if (strcmp(actual_path, channel->filename))
    {
        // Channel we've been given doesn't match the filename we opened
        rc = -EBADF;
        goto EXIT;
    }
    assert(!strcmp(actual_path, channel->filename));

    entry = cbm_get_dir_entry(cbm, actual_path);
    if (entry == NULL)
    {
        // This is a problem - as cbm_create re-reads dir when file is opened
        // so it should exist by now
        WARN("Couldn't find file which is apparently open: %s channel %d", actual_path, ch);
        rc = -EBADF;
        goto EXIT;
    }
    if (entry->is_header)
    {
        // We expose a size of 0 for the header
        assert(entry->filesize == 0);
        rc = 0;
        goto EXIT;
    }

    // Only read in the file if we haven't already - in which case it will
    // be stored in handle1 (with length read in handle2) 
    if (channel->handle1 == NULL)
    {
        rc = cbm_talk(cbm->fd, cbm->device_num, (unsigned char)ch);
        if (rc)
        {
            rc = check_drive_status(cbm);
            (void)rc;
            WARN("Hit error instructing drive to talk, to read file %s channel %d", actual_path, ch);
            WARN("Drive status: %s", cbm->error_buffer);
            goto EXIT;
        }

        int read_block_size = CBM_BLOCK_SIZE;
        DEBUG("Read in file in %d byte chunks", read_block_size);

        // Allocate temporary buffer to read entire file into
        len = entry->filesize;
        temp_buf = malloc(len);
        if (temp_buf == NULL)
        {
            WARN("Failed to malloc buffer to read in file: %s", actual_path);
            goto EXIT;
        }

        // Read the whole file
        total_read = 0;
        while (total_read < len)
        {
            off_t to_read = (len - total_read < read_block_size) ? len - total_read : read_block_size;
            rc = cbm_raw_read(cbm->fd, temp_buf + total_read, (size_t)to_read);
            if (rc < 0)
            {
                rc2 = check_drive_status(cbm);
                (void)rc2;
                WARN("Hit error reading file %s channel %d", actual_path, ch);
                WARN("Drive status: %d %s", rc, cbm->error_buffer);
                cbm_untalk(cbm->fd);
                goto EXIT;
            }
            else if (rc == 0)
            {
                WARN("Reached end of file for %s channel %d", actual_path, ch);
                break;
            }
            else
            {
                total_read += rc;
            }
        }

        // Remember, len is not the file system - it was our estimate of the 
        // filesize, based on the number of blocks the file took on the disk.
        // If the reading didn't hit an error then we can reasonably assume we
        // read the whole file - so update the filesize
        DEBUG("Size of file %s channel %d is %lu bytes", actual_path, ch, total_read);
        entry->filesize = (unsigned int)total_read;

        // Store off the file in the channel handles so we don't need to
        // re-read if the kernel wants more of the file before releasing
        assert(channel->handle1 == NULL);
        assert(channel->handle2 == 0);
        channel->handle1 = temp_buf;
        temp_buf = NULL;
        channel->handle2 = (int)total_read;
    }
    else
    {
        // As we already read the file in, and updated the size in entry->filesize - check that
        DEBUG("Already have this file read in - use it");
        assert(channel->handle2 == (int)entry->filesize);
    }

    DEBUG("Handle1 0x%p handle2 %d", channel->handle1, channel->handle2);

    // Only prove the bit of the file FUSE asked for
    if (offset < channel->handle2)
    {
        if ((size_t)offset + size > (size_t)channel->handle2)
        {
            size = (size_t)channel->handle2 - (size_t)offset;
        }
        memcpy(buf, ((char *)channel->handle1)+offset, size);
    }
    else
    {
        size = 0;
    }
    rc = (int)size;

    // Store the file off in the channel info, so we don't need to read
    // again if the kernel asks us for more of the file.
    // We may not need to do this ... if we got the buffer from the handle
    // in the first place.  But we also set temp_buf, 

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

// REWORK for cbm_file
static int cbm_write(const char *path,
                     const char *buf,
                     size_t size,
                     off_t offset,
                     struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int rc2;
    int ch;
    struct cbm_channel *channel;
    struct cbm_dir_entry *entry;
    char *temp_buf = NULL;
    const char *actual_path;

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);
    assert(offset >= 0);

    ch = (int)(fi->fh);

    actual_path = path+1;

    if (ch == DUMMY_CHANNEL)
    {
        DEBUG("Request to write special file: %s", path);
        if (!strcmp(actual_path, PATH_FORMAT_DISK))
        {
            rc = process_format_request(cbm, buf, size);
        }
        else if (!strcmp(actual_path, PATH_FORCE_DISK_REREAD))
        {
            // Does't matter what gets written - we'll kick off reread anyway
            DEBUG("Request to force disk reread");
            cbm_create_read_dir_thread(cbm);
            rc = (int)size;
        }
        else 
        {
            DEBUG("Unsupported special file");
            rc = -EACCES;
        }
        goto EXIT;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    assert((ch >= 0) && (ch < NUM_CHANNELS));
    channel = cbm->channel+ch;
    if (strcmp(channel->filename, actual_path))
    {
        WARN("Filename doesn't match channel provided %d", ch);
        rc = -EBADF;
        goto EXIT;
    }

    entry = cbm_get_dir_entry(cbm, path);
    if (entry == NULL)
    {
        WARN("Couldn't find file which is apparently open: %s channel %d", path, ch);
        rc = -EBADF;
        goto EXIT;
    }
    if (entry->is_header)
    {
        // Can't write to the header
        rc = -EROFS;
        goto EXIT;
    }

    if (offset != 0)
    {
        DEBUG("Asked to write at offset - not yet supported");
        rc = -ENOTSUP;
        goto EXIT;
    }

    rc = cbm_listen(cbm->fd, cbm->device_num, (unsigned char)ch);
    if (rc < 0)
    {
        rc2 = check_drive_status(cbm);
        (void)rc2;
        WARN("Hit error instructing drive to listen, to write file %s channel %d", actual_path, ch);
        WARN("Drive status: %s", cbm->error_buffer);
        goto EXIT;
    }

    rc = cbm_raw_write(cbm->fd, buf, size);
    cbm_unlisten(cbm->fd);
    if (rc < 0)
    {
        rc = check_drive_status(cbm);
        (void)rc;
        WARN("Hit error writing file %s channel %d", actual_path, ch);
        WARN("Drive status: %s", cbm->error_buffer);
    }
    else if ((unsigned long)rc < size)
    {
        WARN("Couldn't write the whole of file %s channel %d", actual_path, ch);
        goto EXIT;
    }

    DEBUG("Successfully wrote file: %s bytes: %d", actual_path, rc);

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

static int cbm_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int rc = -1;
    (void)fi;
    (void)mode;  // We can avoid mode, because we don't bother with file permissions

    ENTRY();
    PARAMS("path %s", path);

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(fi != NULL);

    // DO NOT LOCK - cbm_fuseopen will

    rc = cbm_fuseopen(path, fi);
    if (rc)
    {
        WARN("Failed to open channel to write: %s", path);
        goto EXIT;
    }

    rc = cbm_write(path, "", 0, 0, fi);
    if (rc)
    {
        WARN("Failed to write 0 bytes to new file");
    }

    // Now re-read directory so file exists! 
    cbm_create_read_dir_thread(cbm);

EXIT:

    EXIT();

    return rc;
}

const struct fuse_operations cbm_operations =
{
    .init     = cbm_init,
    .destroy  = cbm_destroy,
    .getattr  = cbm_getattr,
    .readdir  = cbm_readdir,
    .open     = cbm_fuseopen,
    .release  = cbm_release,
    .read     = cbm_read,
    .write    = cbm_write,
    .create   = cbm_create,
};
