#include "cbmfuse.h"

static struct cbm_state *allocate_private_data(void)
{
    DEBUG("ENTRY: allocate_private_data()");

    // Allocate and zero memory
    struct cbm_state *cbm = malloc(sizeof(struct cbm_state));
    if (cbm == NULL)
    {
        ERROR("Failed to allocate memory");
        goto EXIT;
    }
    memset(cbm, 0, sizeof(struct cbm_state));

    // Set up channels
    for (int ch = 0; ch < NUM_CHANNELS; ch++)
    {
        cbm->channel[ch].num = ch;
    }

EXIT:

    DEBUG("EXIT: allocate_private_data()");

    return cbm;
} 

static void destroy_private_data(struct cbm_state *cbm)
{
    DEBUG("ENTRY: destroy_private_data()");

    if (cbm->fd != (CBM_FILE)0)
    {
        cbm_driver_close(cbm->fd);
        cbm->fd = (CBM_FILE)0;
    }
    if (cbm->mountpoint != NULL)
    {
        free(cbm->mountpoint);
        cbm->mountpoint = NULL;
    }
    if (cbm->dir_entries != NULL)
    {
        free(cbm->dir_entries);
        cbm->dir_entries = NULL;
    }
    if (cbm->files != NULL)
    {
        free(cbm->files);
        cbm->files = NULL;
    }
    free(cbm);

    DEBUG("EXIT: destroy_private_data()");
}

static void cleanup_fuse(struct cbm_state *cbm)
{
    DEBUG("ENTRY: cleanup_fuse()");
    
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
    }

    DEBUG("EXIT: cleanup_fuse()");
}

int main(int argc, char *argv[])
{
    struct cbm_state *cbm;
    int ret = 1;

    // Set up first, as the signal handler will need access
    DEBUG("Allocate private data");
    cbm = malloc(sizeof(struct cbm_state));
    if (cbm == NULL)
    {
        ERROR("Failed to allocate memory\n");
        goto EXIT;
    }
    cbm = allocate_private_data();
    cbm->fuse_fh = -1;
    DEBUG("Private data allocated");

    // Set up next, before anything else happens, so we can gracefully handle
    // signals
    DEBUG("Setup signal handler");
    setup_signal_handler(cbm);

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
    cbm->fuse = fuse_new_30(&args,
                            &cbm_operations,
                            sizeof(cbm_operations),
                            cbm);
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
    cbm->fuse_fh = fuse_mount(cbm->fuse, cbm->mountpoint);
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

    DEBUG("Cleanup");

    // Cleanup code
    // The signal handler has similar processing, in case this isn't run
    // Note neither this code nor the signal handler attempts to destroy our
    // mutex, to avoid hanging, or undefied behaviour, if it's locked.
    cleanup_fuse(cbm);

    // Cleanup signal handler before freeing cbm
    cleanup_signal_handler();

    destroy_private_data(cbm);
    cbm = NULL;

    DEBUG("Exiting");

    return ret;
}   