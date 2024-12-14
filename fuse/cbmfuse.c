#include "cbmfuse.h"

// Updated init function signature for FUSE3
static void *cbm_init(struct fuse_conn_info *conn,
                      struct fuse_config *cfg)
{
    int rc;
    int locked = 0;
    int failed = 1;
    CBM *cbm = fuse_get_context()->private_data;
    (void)conn;
    (void)cfg;

    // Checks
    assert(cbm != NULL);

    // Create the mutex
    DEBUG("Create mutex");
    assert(!cbm->mutex_initialized);
    if (pthread_mutex_init(&(cbm->mutex), NULL) != 0)
    {
        ERROR("Failed to initialize mutex\n");
        goto EXIT;
    }
    cbm->mutex_initialized = 1;

    DEBUG("Open XUM1541 driver");
    if (cbm_driver_open_ex(&cbm->fd, NULL) != 0) {
        ERROR("Failed to open OpenCBM driver\n");
        goto EXIT;
    }

    if (cbm->force_bus_reset)
    {
        INFO("Performing bus reset");
        rc = cbm_reset(cbm->fd);
        if (rc)
        {
            ERROR("Failed to reset bus");
            goto EXIT;
        }
    }
    
    // We don't actually need to lock the mutex here, as no other functions
    // will be called until this _init() function completes. But, we'll do
    // it anyway.
    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    DEBUG("Check drive status");
    rc = check_drive_status_cmd(cbm, NULL);
    if (rc)
    {
        ERROR("Drive status query returned error: %d %s\n", rc, cbm->error_buffer);
        goto EXIT;
    }
    
    cbm->is_initialized = 1;

    // Create dummy file entries
    rc = create_dummy_entries(cbm);
    if (rc)
    {
        ERROR("Failed to create dummy entries %d", rc);
        goto EXIT;
    }

    // Spawn a thread to read the disk, so it's faster to access this mount
    // later
    DEBUG("Spawn thread to read dir");
    cbm_create_read_dir_thread(cbm);
    failed = 0;

EXIT:

    if (cbm->mutex_initialized && locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
        locked = 0;
    }

    if (failed)
    {
        if (cbm->fd != (CBM_FILE)0)
        {
            cbm_driver_close(cbm->fd);
            cbm->fd = 0;
        }
        if (cbm->mutex_initialized)
        {
            pthread_mutex_destroy(&cbm->mutex);
            cbm->mutex_initialized = 0;
        }
        ERROR("Mount failed - is the XUM1541 plugged in, the drive turned on and set to device %d?", cbm->device_num);
        printf("Mount failed - is the XUM1541 plugged in, the drive turned on and set to device %d?\n", cbm->device_num);
        
        // Cause FUSE to exit
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

    for (int ii = 0; ii < NUM_CHANNELS; ii++)
    {
        if (cbm->channel[ii].handle1 != NULL)
        {
            DEBUG("Free memory for channel %d: 0x%p",
                  ii,
                  cbm->channel[ii].handle1);
            free(cbm->channel[ii].handle1);
        }
    }
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
    int rc = -1;
    int locked = 0;
    const char *actual_path;
    struct cbm_file *entry;

    CBM *cbm = fuse_get_context()->private_data;
    assert(cbm != NULL);
    assert(path != NULL);
    assert(stbuf != NULL);

    ENTRY();
    PARAMS("Path %s", path);

    if (path[0] == 0)
    {
        DEBUG("Empty path provided");
        rc = -ENOENT;
        goto EXIT;
    }

    // Set up actual path appropriately
    if (!strcmp(path, "/"))
    {
        actual_path = ".";
    }
    else if (strcmp(path, "/") && (path[0] == '/'))
    {
        // Skip the initial
        DEBUG("Make path %s", actual_path);
        actual_path = path+1;
    }
    else
    {
        actual_path = path;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Find the file entry
    entry = find_fuse_file_entry(cbm, actual_path);
    if (entry == NULL)
    {
        DEBUG("Failed to find file entry for %s", actual_path);
        rc = -ENOENT;
        goto EXIT;
    }

    // Copy stat info
    memcpy(stbuf, &(entry->st), sizeof(entry->st));
    rc = 0;

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
}

static int cbm_readdir(const char *path,
                       void *buf,
                       fuse_fill_dir_t filler,
                       off_t offset,
                       struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
{
    int rc = -1;
    int locked = 0;
    struct cbm_file *entry;

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


    // If the path isn't / or . or ./ we return nothing (no files)
    if (strcmp(path, "/") && strcmp(path, ".") && strcmp(path, "./"))
    {
        DEBUG("Attempt to read path with isn't / or . or ./ - exiting");
        rc = -ENOENT;
        goto EXIT;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Re-read the disk if we didn't read cleanly last time - we do this
    // synchronously here
    if (!cbm->dir_is_clean)
    {
        DEBUG("Re-eread directory listing from disk");
        rc = read_dir_from_disk(cbm);
        if (rc)
        {
            WARN("Failed to load directory listing %d", rc);
        }
    }

    // Fill in the files
    // If we didn't get a clean directory read this will only show special
    // files
    for (size_t ii=0; ii < cbm->num_files; ii++)
    {
        entry = &(cbm->files[ii]);
        DEBUG("Adding file %zu %s", ii, entry->fuse_filename);
        rc = filler(buf, entry->fuse_filename, &(entry->st), 0, 0);
    }

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return 0;
}

static int cbm_fuseopen(const char *path, struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int ch = -1;
    const char *actual_path;
    struct cbm_file *entry;
    CBM *cbm = fuse_get_context()->private_data;

    ENTRY();
    PARAMS("Path %s", path);

    // Processing:
    // * Check some assumptions
    // * Get the file entry
    // * If there isn't one - try and reread the directory
    // * Try and get the file entry again
    // * If there still isn't one, this open might be to open a new file, so
    //   create a file entry and mark is as not yet written to disk
    // * Call the callback for this file entry - if there isn't one return an
    //   error

    assert(cbm != NULL);
    assert(fi != NULL);

    if (path[0] == 0)
    {
        WARN("Asked to open zero length path");
        rc = -ENOENT;
        goto EXIT;
    }

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Get the file entry
    actual_path = path+1;
    if (strlen(actual_path) >= MAX_FUSE_FILENAME_STR_LEN)
    {
        WARN("Request to open file with filename exceeding max length failed: %s", path);
        rc = -ENAMETOOLONG;
        goto EXIT;
    }
    entry = find_fuse_file_entry(cbm, actual_path);

    if ((entry == NULL) && (!cbm->dir_is_clean))
    {
        // Perhaps we failed to find the file entry becaus we didn't update
        // the directory recently.  Do that and try again.
        assert(locked);
        if (!cbm->dir_is_clean)
        {
            rc = read_dir_from_disk(cbm);
            if (rc)
            {
                WARN("Failed to load directory listing prior to opening file: %s %d", path, rc);
            }
        }
        else
        {
            // Now try and find the file again
            entry = find_fuse_file_entry(cbm, actual_path);
        }
    }

    // It's OK if we didn't find a file - we will create it
    // This would be the case where we wanted to write a new file, for example
    if (entry == NULL)
    {
        entry = create_fuse_file_entry(cbm,
                                       actual_path,
                                       0,
                                       NULL,
                                       &rc);
        if (entry == NULL)
        {
            assert(rc != 0);
            INFO("Failed to create fuse file entry for filename %s %d",
                 actual_path,
                 rc);
            goto EXIT;
        }
        entry->not_yet_on_disk = 1;
    }
    assert(entry != NULL);

    // Release the lock before we call the callback
    assert(locked);
    pthread_mutex_unlock(&(cbm->mutex));
    locked = 0;

    if (entry->cbs.open != NULL)
    {
        DEBUG("Use open callback");
        rc = entry->cbs.open(cbm,
                             entry->cbs.handle,
                             entry,
                             actual_path,
                             fi);
        goto EXIT;
    }

    // We don't have any default handling of open
    rc = -ENOTSUP;

EXIT:

    if (rc && (ch >= 0))
    {
        // Release the channel we allocated above if cbm_open fails
        if (!locked)
        {
            pthread_mutex_lock(&(cbm->mutex));
            locked = 1;
        }
        release_channel(cbm, ch);
    }

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
}

static int cbm_release(const char *path, struct fuse_file_info *fi)
{
    int locked = 0;
    int rc = -1;
    int ch;
    const char *actual_path;
    struct cbm_file *entry;
    CBM *cbm = fuse_get_context()->private_data;

    ENTRY();

    // Processing:
    // * Check some assumptions
    // * Get the file entry
    // * If there isn't one then why are we releasing a file?
    // * Call the release callback for this file entry - if there isn't one
    //   return an error

    assert(cbm != NULL);
    assert(fi != NULL);

    ch = (int)(fi->fh);

    // Sanity checks
    if ((ch < MIN_CHANNEL) || (ch > MAX_CHANNEL))
    {
        WARN("Asked to release invalid channel %d", ch);
        rc = -ENOENT;
        goto EXIT;
    }
    if (path[0] == 0)
    {
        WARN("Kernel asked us to release zero length filename");
        rc = -ENOENT;
        goto EXIT;
    }

    actual_path = path+1;

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Get the file entry.  If we have a channel we can get it via the channel
    // struct.  If it's for the dummy channel we will look up based on the
    // path
    // Note we already checked ch is not < MIN_CHANNEL above
    if (ch < DUMMY_CHANNEL)
    {
        entry = cbm->channel[ch].file;
        assert((entry == NULL) || (entry->channel->num == ch));
    }
    else
    {
        entry = find_fuse_file_entry(cbm, actual_path);
    }

    if (entry == NULL)
    {
        WARN("Couldn't find entry associated with channel %d %s",
             ch,
             actual_path);
        rc = -ENOENT;
        goto EXIT;
    }

    assert(locked);
    pthread_mutex_unlock(&(cbm->mutex));
    locked = 0;

    if (entry->cbs.open != NULL)
    {
        DEBUG("Use release callback");
        rc = entry->cbs.release(cbm,
                                entry->cbs.handle,
                                entry,
                                actual_path,
                                fi);
        goto EXIT;
    }

    // We don't have any default handling of open
    rc = -ENOTSUP;

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

    return rc;
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
    int ch;
    struct cbm_file *entry;
    const char *actual_path;

    CBM *cbm = fuse_get_context()->private_data;

    ENTRY();
    PARAMS("Path %s Size %lu Offset %ld", path, size, offset);

    // Processing:
    // * Do some checks
    // * Try and find the entry based on the provided ch
    // * Or if ch is dummy channel, using path+1
    // * Then call the read callback

    assert(cbm != NULL);
    assert(fi != NULL);
    assert(offset >= 0);

    ch = (int)(fi->fh);

    // Sanity checks
    if ((ch < MIN_CHANNEL) || (ch > MAX_CHANNEL))
    {
        WARN("Asked to release invalid channel %d", ch);
        rc = -ENOENT;
        goto EXIT;
    }
    if (path[0] == 0)
    {
        WARN("Kernel asked us to release zero length filename");
        rc = -ENOENT;
        goto EXIT;
    }

    actual_path = path+1;

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    // Get the file entry.  If we have a channel we can get it via the channel
    // struct.  If it's for the dummy channel we will look up based on the
    // path
    // Note we already checked ch is not < MIN_CHANNEL above
    if (ch < DUMMY_CHANNEL)
    {
        entry = cbm->channel[ch].file;
        assert((entry == NULL) || (entry->channel->num == ch));
    }
    else
    {
        entry = find_fuse_file_entry(cbm, actual_path);
    }

    if (entry == NULL)
    {
        WARN("Couldn't find entry associated with channel %d %s",
             ch,
             actual_path);
        rc = -ENOENT;
        goto EXIT;
    }

    assert(locked);
    pthread_mutex_unlock(&(cbm->mutex));

    rc = entry->cbs.read(cbm,
                         entry->cbs.handle,
                         entry,
                         actual_path,
                         buf,
                         size,
                         offset,
                         fi);

EXIT:

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
    int ch;
    struct cbm_file *entry;
    const char *actual_path;
    CBM *cbm = fuse_get_context()->private_data;

    ENTRY();

    // Processing
    // * Checks
    // * Try and find the file entry
    // * Call the write callback for this file entry

    actual_path = path+1;

    pthread_mutex_lock(&(cbm->mutex));
    locked = 1;

    assert(cbm != NULL);
    assert(fi != NULL);
    assert(offset >= 0);

    ch = (int)(fi->fh);

    actual_path = path+1;

    // Get the file entry.  If we have a channel we can get it via the channel
    // struct.  If it's for the dummy channel we will look up based on the
    // path
    // Note we already checked ch is not < MIN_CHANNEL above
    if (ch < DUMMY_CHANNEL)
    {
        entry = cbm->channel[ch].file;
        assert((entry == NULL) || (entry->channel->num == ch));
    }
    else
    {
        entry = find_fuse_file_entry(cbm, actual_path);
    }

    if (entry == NULL)
    {
        WARN("Couldn't find entry associated with channel %d %s",
             ch,
             actual_path);
        rc = -ENOENT;
        goto EXIT;
    }

    assert(locked);
    pthread_mutex_unlock(&(cbm->mutex));

    rc = entry->cbs.write(cbm,
                          entry->cbs.handle,
                          entry,
                          actual_path,
                          buf,
                          size,
                          offset,
                          fi);

EXIT:

    if (locked)
    {
        pthread_mutex_unlock(&(cbm->mutex));
    }

    EXIT();

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
