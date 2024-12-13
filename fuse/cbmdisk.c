#include "cbmfuse.h"

// File contains CBM disk operation code

// Process an incoming request to format a disk
int process_format_request(CBM *cbm, const char *buf, size_t size)
{
    int rc = -1;
    int rc2;

    ENTRY();
    
    // For length, 1 char longer is actually OK if ends with \r or \n
    if (size > (MAX_HEADER_LEN))
    {
        DEBUG("Disk name, ID data too long");
        goto EXIT;
    }
    if (size < 4)
    {
        DEBUG("Disk name, ID data too short");
        goto EXIT;
    }

    // Buf may not be NULL terminated - turn into a string
    // By memsetting to 0 and checking size above we can guarantee
    // this is NULL terminated
    char header[MAX_HEADER_LEN+1];
    memset(header, 0, MAX_HEADER_LEN+1);
    memcpy(header, buf, size);
    int ii;
    for (ii = (int)(size-1); ii >= 0; ii--)
    {
        if ((header[ii] == '\r') || (header[ii] == '\n'))
        {
            header[ii] = 0;
        }
        else
        {
            // Only go as far back as 1st none new line char
            break;
        }
    }

    char *name;
    name = strtok(header, ",");
    if (name == NULL)
    {
        DEBUG("Disk name, ID data not properly formatted");
        goto EXIT;
    }
    char *id;
    id = strtok(NULL, ",");
    if (id == NULL)
    {
        DEBUG("Disk name, ID data not properly formatted");
        goto EXIT;
    }
    if (strtok(NULL, ",") != NULL)
    {
        DEBUG("Too much data");
        goto EXIT;
    }
    if (strlen(name) > MAX_FILE_LEN)
    {
        DEBUG("Header name too long");
        goto EXIT;
    }
    if (strlen(id) != CBM_ID_LEN)
    {
        DEBUG("ID not 2 chars long: %lu %s", strlen(id), id);
        goto EXIT;
    }
    char cmd[MAX_HEADER_LEN+3];
    name = cbm_ascii2petscii(name);
    id = cbm_ascii2petscii(id);
    sprintf(cmd, "N0:%s,%s", name, id);

    if (!cbm->dummy_formats)
    {
        // It's all good - format the disk
        // TO DO check 15 not open properly
        assert(!cbm->channel[15].open);
        DEBUG("Formatting disk with cmd: %s", cmd);
        rc = cbm_open(cbm->fd, cbm->device_num, 15, NULL, 0);
        if (rc)
        {
            rc2 = check_drive_status(cbm);
            (void)rc2;
            WARN("Failed to open command channel: %d %s", rc, cbm->error_buffer);
            goto EXIT;
        }
        cbm_listen(cbm->fd, cbm->device_num, 15);
        rc = cbm_raw_write(cbm->fd, cmd, strlen(cmd));
        cbm_unlisten(cbm->fd);

        if (rc != (int)strlen(cmd))
        {
            rc2 = check_drive_status(cbm);
            (void)rc2;
            DEBUG("Failed to write entire command: %d %s", rc2, cbm->error_buffer);
            rc = -EIO;
            goto EXIT;
        }
    }
    else
    {
        DEBUG("Pretending to format disk with cmd: %s", cmd);
    }

    // Force directory reread
    cbm->dir_is_clean = 0;
    cbm_create_read_dir_thread(cbm);

    DEBUG("Format successful");
    rc = (int)size;

EXIT:

    EXIT();

    return rc;
}

static int open_file_on_disk(CBM *cbm,
                             int handle,
                             struct cbm_file *entry,
                             const char *path,
                             struct fuse_file_info *fi)
{
    int rc = -1;
    int ch = -1;
    int rc2;
    int locked = 0;
    (void)handle;

    ENTRY();

    assert(cbm != NULL);
    assert(entry != NULL);
    assert(path != NULL);
    assert(fi != NULL);

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    switch (entry->type)
    {
        case CBM_DISK_HDR:
            DEBUG("Allocated dummy channel for disk header open");
            fi->fh = DUMMY_CHANNEL;
            rc = 0;
            goto EXIT;
            break;

        case CBM_PRG:
        case CBM_REL:
        case CBM_USR:
        case CBM_SEQ:
            break;

        default:
            assert(0);
    }

    // Allocate a channel to communicate to the drive with
    DEBUG("Allocate free channel");
    ch = allocate_free_channel(cbm, USAGE_OPEN, entry);
    if (ch < 0)
    {
        WARN("Failed to allocate a free channel to open file: %s",
             path);
        rc = -EMFILE; // Too many open files
        goto EXIT;
    }

    // Open the file on the disk drive
    DEBUG("Open file on disk drive using filename: %s", entry->cbm_filename);

    rc = cbm_open(cbm->fd,
                  cbm->device_num,
                  (unsigned char)ch,
                  entry->cbm_filename,
                  strlen(entry->cbm_filename));
    if (rc)
    {
        rc2 = check_drive_status(cbm);
        WARN("Failed to open file: %s channel: %d", path, ch);
        WARN("Drive status: %d %s", rc2, cbm->error_buffer);
        goto EXIT;
    }
    
    DEBUG("Succeeded in opening file: %s channel: %d", entry->cbm_filename, ch);
    fi->fh = (long unsigned int)ch;
    rc = 0;

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
        locked = 0;
    }

    EXIT();

    return rc;
}

static int release_file_on_disk(CBM *cbm,
                                int handle,
                                struct cbm_file *entry,
                                const char *path,
                                struct fuse_file_info *fi)
{
    int rc = -1;
    int rc2;
    int locked = 0;
    (void)handle;

    ENTRY();

    assert(cbm != NULL);
    assert(entry != NULL);
    assert(entry->channel != NULL);
    assert(path != NULL);
    assert(fi != NULL);

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    switch (entry->type)
    {
        case CBM_DISK_HDR:
            if (fi->fh != DUMMY_CHANNEL)
            {
                WARN("Kernel asked to free wrong disk header channel %zu",
                     fi->fh);
                rc = -ENOENT;
            }
            else
            {
                DEBUG("\"Freed\" dummy channel for disk header");
                rc = 0;
            }
            goto EXIT;
            break;

        case CBM_PRG:
        case CBM_REL:
        case CBM_USR:
        case CBM_SEQ:
            break;

        default:
            assert(0);
    }

    // Attempt to close the channel
    rc = cbm_close(cbm->fd, cbm->device_num, (unsigned char)entry->channel->num);
    if (rc)
    {
        rc2 = check_drive_status(cbm);
        WARN("Hit error closing channel %d %d", entry->channel->num, rc);
        WARN("Drive status: %d %s", rc2, cbm->error_buffer);
        goto EXIT;
    }

    // Clear the channel handles
    if (entry->channel->handle1 != NULL)
    {
        DEBUG("Freeing buffer stored in channel");
        free(entry->channel->handle1);
        entry->channel->handle1 = NULL;
    }
    entry->channel->handle2 = 0;

    // Release channel back to pool
    release_channel(cbm, entry->channel->num);

    DEBUG("Succeedding in releasing %s channel %d",
          entry->fuse_filename,
          entry->channel->num);
    rc = 0;

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
        locked = 0;
    }

    if (!rc) // Succeeded
    {
        // Don't know if we should reset this or not - but we will anyway
        fi->fh = 0;
    }

    EXIT();

    return rc;
}

static int read_file_from_disk(CBM *cbm,
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
    int locked = 0;
    (void)handle;
    (void)fi;
    struct cbm_channel *channel;
    char *temp_buf = NULL;
    off_t total_read;
    size_t len;

    ENTRY();

    // Processing
    // * Checks
    // * If we don't already the file read in and stored read it in
    // * If we now have the file copy whatever FUSE wanted to the provided
    //   buffer 

    assert(cbm != NULL);
    assert(entry != NULL);
    assert(path != NULL);
    assert(buf != NULL);
    assert(entry->channel != NULL);

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    switch (entry->type)
    {
        case CBM_DISK_HDR:
            DEBUG("Read completed for disk header (0 bytes)");
            rc = 0;
            goto EXIT;
            break;

        case CBM_PRG:
        case CBM_REL:
        case CBM_USR:
        case CBM_SEQ:
            break;

        default:
            assert(0);
    }

    channel = entry->channel;
    if (strcmp(path, entry->fuse_filename))
    {
        // Channel we've been given doesn't match the filename we opened
        rc = -EBADF;
        goto EXIT;
    }
    assert(!strcmp(path, entry->fuse_filename));

    // Only read in the file if we haven't already - in which case it will
    // be stored in handle1 (with length read in handle2) 
    if (channel->handle1 == NULL)
    {
        rc = cbm_talk(cbm->fd, cbm->device_num, (unsigned char)channel->num);
        if (rc)
        {
            rc = check_drive_status(cbm);
            (void)rc;
            WARN("Hit error instructing drive to talk, to read file %s channel %d",
                 path,
                 channel->num);
            WARN("Drive status: %s", cbm->error_buffer);
            goto EXIT;
        }

        DEBUG("Read in file in %d byte chunks", CBM_BLOCK_SIZE);

        // Allocate temporary buffer to read entire file into
        len = (size_t)entry->st.st_size;
        temp_buf = malloc(len);
        if (temp_buf == NULL)
        {
            WARN("Failed to malloc buffer to read in file: %s", path);
            goto EXIT;
        }

        // Read the whole file
        total_read = 0;
        while (total_read < (off_t)len)
        {
            off_t to_read = ((off_t)len - total_read < CBM_BLOCK_SIZE) ? (off_t)len - total_read : CBM_BLOCK_SIZE;
            rc = cbm_raw_read(cbm->fd, temp_buf + total_read, (size_t)to_read);
            if (rc < 0)
            {
                rc2 = check_drive_status(cbm);
                (void)rc2;
                WARN("Hit error reading file %s channel %d", path, channel->num);
                WARN("Drive status: %d %s", rc, cbm->error_buffer);
                cbm_untalk(cbm->fd);
                goto EXIT;
            }
            else if (rc == 0)
            {
                WARN("Reached end of file for %s channel %d", path, channel->num);
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
        DEBUG("Size of file %s channel %d is %lu bytes",
              path,
              channel->num,
              total_read);
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

    // Only provide the bit of the file FUSE asked for
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

EXIT:

    if (temp_buf != NULL)
    {
        free(temp_buf);
    }

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
}

static int write_file_to_disk(struct cbm_state *cbm,
                              int handle,
                              struct cbm_file *entry,
                              const char *path,
                              const char *buf,
                              size_t size,
                              off_t offset,
                              struct fuse_file_info *fi)
{
    int rc = -1;
    int rc2;
    int locked = 0;
    char *temp_buf = NULL;
    int ch;
    (void)handle;
    (void)fi;

    ENTRY();

    // Processing:
    // * Some checks
    // 

    assert(cbm != NULL);
    assert(entry != NULL);
    assert(path != NULL);
    assert(buf != NULL);
    assert(entry->channel != NULL);

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    switch (entry->type)
    {
        case CBM_DISK_HDR:
            DEBUG("Write failed for disk header");
            rc = -EROFS;
            goto EXIT;
            break;

        case CBM_PRG:
        case CBM_REL:
        case CBM_USR:
        case CBM_SEQ:
            break;

        default:
            assert(0);
    }

    if (strcmp(path, entry->fuse_filename))
    {
        // Channel we've been given doesn't match the filename we opened
        rc = -EBADF;
        goto EXIT;
    }
    assert(!strcmp(path, entry->fuse_filename));
    ch = entry->channel->num;
    
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
        WARN("Hit error instructing drive to listen, to write file %s channel %d",
             path,
             ch);
        WARN("Drive status: %d %s", rc, cbm->error_buffer);
        goto EXIT;
    }

    rc = cbm_raw_write(cbm->fd, buf, size);
    cbm_unlisten(cbm->fd);
    if (rc < 0)
    {
        rc = check_drive_status(cbm);
        (void)rc;
        WARN("Hit error writing file %s channel %d", path, ch);
        WARN("Drive status: %d %s", rc, cbm->error_buffer);
    }
    else if ((size_t)rc < size)
    {
        WARN("Couldn't write the whole of file %s channel %d", path, ch);
        goto EXIT;
    }

    DEBUG("Successfully wrote file: %s bytes: %d", path, rc);

EXIT:

    if (temp_buf != NULL)
    {
        free(temp_buf);
    }

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
}

struct callbacks disk_cbs =
{
    .handle = 0,
    .open = open_file_on_disk,
    .release = release_file_on_disk,
    .read = read_file_from_disk,
    .write = write_file_to_disk,
};