#include "cbmfuse.h"

// Function to check the status of a CBM disk drive, including by sending a
// specific command first (like "UJ" or "I" to reset or initialize the drive)
//
// Must be called within a mutex lock if called after our fuse _init() function
// has been called, and before fuse_exit() has been called.
// Extended version of check_drive_status which will call the specified
// command (like "UJ" or "I") before issuing the status query.
// Can be called with cmd == NULL, in which case a command is not issued
int check_drive_status_cmd(struct cbm_state *cbm, char *cmd)
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

// Function to query drive status.  If you want to run a command first, call
// check_drive_status_cmd() directly.
//
// Must be called within a mutex lock if called after our fuse _init() function
// has been called, and before fuse_exit() has been called.
int check_drive_status(struct cbm_state *cbm)
{
    return check_drive_status_cmd(cbm, NULL);
}

