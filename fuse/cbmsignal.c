#include "cbmfuse.h"

// We need to expose cbm to the signal handler so it can cleanup.  We do so
// via a signal handler struct in order to discourage other functions from
// accessing cbm this way.  Other functions within the fuse context should
// get using fuse_get_context()->private_data.
struct signal_handler_data {
    struct cbm_state *cbm;
};

static struct signal_handler_data shd; 

static void handle_signal(int signal)
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
                destroy_private_data(cbm, 0);
                cbm = NULL;
            }
            INFO("Exiting after handling signal");
            exit(1);
            break;
    }
}

void setup_signal_handler(struct cbm_state *cbm)
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

    assert(cbm != NULL);
    shd.cbm = cbm;

    for (int ii = 0; ii < num_signals; ii++)
    {
        signal(termination_signals[ii], handle_signal);
    }

}

void cleanup_signal_handler()
{
    shd.cbm = NULL;
}