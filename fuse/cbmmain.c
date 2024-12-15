#include "cbmfuse.h"

static CBM *allocate_private_data(void)
{
    ENTRY();

    // Allocate and zero memory
    CBM *cbm = malloc(sizeof(struct cbm_state));
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

    EXIT();

    return cbm;
} 

// Not static, as called by handle_signal()
void destroy_private_data(CBM *cbm, int clean)
{
    ENTRY();

    assert(cbm != NULL);

    // handle_signal() doesn't want to attempt a clean shutdown as it may fail
    // and hang
    if (clean)
    {
        cbm_destroy(cbm);
    }
    destroy_args(cbm);
    destroy_files(cbm);
    if (cbm->mountpoint != NULL)
    {
        free(cbm->mountpoint);
    }
    free(cbm);

    EXIT();
}

static void cleanup_fuse(CBM *cbm)
{
    ENTRY();
    
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

    EXIT();
}

// Run fuse_loop in a separate thread to keep main thread clear for signal
// handling
static pthread_t fuse_thread;
static void *fuse_thread_func(void *arg)
{
    int rc;
    CBM *cbm = (CBM *)arg;

    ENTRY();

    assert(cbm != NULL);
    assert(!cbm->fuse_loop);
    assert(!cbm->fuse_exited);
    cbm->fuse_loop = 1;
    rc = fuse_loop(cbm->fuse);
    DEBUG("FUSE loop exited");
    (void)rc;
    cbm->fuse_exited = 1;

    EXIT();

    return NULL;
}

int kill_fuse_thread(void)
{
    return pthread_cancel(fuse_thread);
}

int main(int argc, char *argv[])
{
    CBM *cbm;
    int ret = 1;

    init_logging();

    // Set up first, as the signal handler will need access
    DEBUG("Allocate private data");
    cbm = malloc(sizeof(struct cbm_state));
    if (cbm == NULL)
    {
        ERROR("Failed to allocate memory");
        goto EXIT;
    }
    cbm = allocate_private_data();
    cbm->fuse_fh = -1;
    DEBUG("Private data allocated");

    // Set up next, before anything else happens, so we can gracefully handle
    // signals
    DEBUG("Setup signal handler");
    if(setup_signal_handler(cbm))
    {
        ERROR("Failed to set up signal handle");
        goto EXIT;
    }

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
        ERROR("Failed to create FUSE object");
        goto EXIT;
    }

    // Mount our mountpoint.  Note that this doesn't actually call our _init()
    // function - that only happens when fuse_loop() is called below.
    DEBUG("Fuse mount");
    cbm->fuse_fh = fuse_mount(cbm->fuse, cbm->mountpoint);
    if (cbm->fuse_fh == -1)
    {
        ERROR("Failed to mount FUSE filesystem");
        goto EXIT;
    }

    // Do pre-initialization.  This ensure as much as possible is working
    // before daemonization.
    if(cbm_pre_init(cbm))
    {
        ERROR("Pre-initialization failed - exiting");
        goto EXIT;
    }

    if (cbm->daemonize)
    {
        // nochdir can be 0 to change directory to root - as we've mounted
        // from the relative mountpoint now.
        DEBUG("Run as daemon");
        if (daemon(0,0))
        {
            ERROR("Failed to daemonize - exiting");
            printf("Failed to daemonize - exiting");
            goto EXIT;
        }
        cbm->is_daemon = 1;

    }

    // Attempt the mount - this will call our _init() function, which in turn
    // will, assuming everything else is OK, will start a thread to do an
    // immediate directory read, caching it so we are ready to return that
    // quickly when required.
    // Any failure in _init() will cause fuse_exit() to be called.  That will
    // in turn cause the fuse_loop below to exit, meaning we can clean up and
    // exit.

    // Start the main fuse_loop and run forever - or until we hit a fatal
    // or catch and handle a signal
    DEBUG("Fuse loop");
    pthread_create(&fuse_thread, NULL, fuse_thread_func, cbm);
    pthread_join(fuse_thread, NULL); // Wait for thread we just started to exit
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

    destroy_private_data(cbm, 1);
    cbm = NULL;

    DEBUG("Exiting");

    return ret;
}   