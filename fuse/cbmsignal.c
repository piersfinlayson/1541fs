#include "cbmfuse.h"

// We need to expose cbm to the signal handler so it can cleanup.  We do so
// via a signal handler struct in order to discourage other functions from
// accessing cbm this way.  Other functions within the fuse context should
// get using fuse_get_context()->private_data.
struct signal_handler_data {
    CBM *cbm;
    int attempts;
};

static struct signal_handler_data shd; 

static void handle_signal(int signal)
{
    // Grab the signal handler data
    // Technically this isn't thread safe - another thread could be in the
    // process of accessing this CBM, which is controlled via a contained
    // mutex.  But we can't help that, as a signal could be caught and handled
    // while the lock is held.
    CBM *cbm = shd.cbm;
    shd.attempts++;
    
    if (shd.attempts > 1)
    {
        ERROR("Second time in the signal handler exit immediately");
        printf("Failed to handle signal cleanly - we may have left resources open.\n");
        printf("You may need to manually unmount your filesystem and reset the USB driver.\n");
        exit(1);
    }

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
            INFO("Signal %d caught - cleaning up", signal);
            if (cbm != NULL)
            {
                // We gracefully handle cbm being NULL, as main may be exiting
                // in which case it may have called cleanup_signal_handler
                // which sets cbm to NULL.
                if (cbm->fuse != NULL)
                {
                    if (cbm->fuse_loop && !cbm->fuse_exited)
                    {
                        // To exit FUSE we need to call fuse_exit() AND
                        // fuse_session_exit()
                        DEBUG("Fuse unmount");
                        fuse_unmount(cbm->fuse);
                        DEBUG("Fuse unmounted");
                        DEBUG("Exit FUSE");
                        fuse_exit(cbm->fuse);
                        struct fuse_session *se = fuse_get_session(cbm->fuse);
                        if (se)
                        {
                            DEBUG("Exit FUSE session");
                            fuse_session_exit(se);
                        }

                        // We now need open a file on our mountpoint in order
                        // kick FUSE into doing something - as for some reason
                        // the signal we received doesn't cause the system
                        // call FUSE is blocked in to exit.
                        FILE *file = fopen(cbm->mountpoint, "r");
                        if (file == NULL)
                        {
                            ERROR("Error opening file to kick FUSE to close - mountpoint may be left mounted");
                        }
                        else
                        {
                            fclose(file);
                            DEBUG("FUSE kicked by opening and closing mountpoint");
                        }
                        // Now allow fuse_loop() within main() will exit, and
                        // main() will then do remaining cleanup
                    }
                    else
                    {
                        // It doesn't seem like FUSE was running, so we
                        // can't just terminate it and wait for it to 
                        // finish and main to cleanup.
                        // So we need to force an exit
                        WARN("Unclean exit from signal handler - no fuse_loop");
                        exit(1);
                    }
                }
                else
                {
                    // It doesn't seem like FUSE was running, so we
                    // can't just terminate it and wait for it to 
                    // finish and main to cleanup.
                    // So we need to force an exit
                    WARN("Unclean exit from signal handler - no FUSE");
                    exit(1);
                }
            }
            break;
    }

    DEBUG("Exiting signal handler");

    return;
}

int setup_signal_handler(CBM *cbm)
{
    int rc = -1;
    struct sigaction sa;

    int termination_signals[] = {
        SIGHUP,   // Hangup detected on controlling terminal or death of controlling process
        SIGINT,   // Interrupt from keyboard (Ctrl-C)
        SIGQUIT,  // Quit from keyboard (Ctrl-\), also generates a core dump
        SIGILL,   // Illegal Instruction
        SIGABRT,  // Abort signal from abort function
        SIGFPE,   // Floating-point exception
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

    assert(cbm != NULL);
    shd.cbm = cbm;
    shd.attempts = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    for (int ii = 0; ii < num_signals; ii++)
    {
        if (sigaction(termination_signals[ii], &sa, NULL) != 0)
        {
            ERROR("Failed to set signal handler for signal %d",
                  termination_signals[ii]);
            goto EXIT;
        }
    }

    rc = 0;

EXIT:

    return rc;
}

void cleanup_signal_handler()
{
    shd.cbm = NULL;
}