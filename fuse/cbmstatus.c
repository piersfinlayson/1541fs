#include "cbmfuse.h"

// Function to check the status of a CBM disk drive, including by sending a
// specific command first (like "UJ" or "I" to reset or initialize the drive)
//
// Must be called within a mutex lock if called after our fuse _init() function
// has been called, and before fuse_exit() has been called.
// Extended version of check_drive_status which will call the specified
// command (like "UJ" or "I") before issuing the status query.
// Can be called with cmd == NULL, in which case a command is not issued
int check_drive_status_cmd(CBM *cbm, char *cmd)
{
    int rc;
    int len;
    int status;
    struct cbm_file *entry;
    time_t now;

    // Channel 15 will already be open if something was using it
    // It will call this function if it hits an error.  Therefore we're
    // going to use channel 15 without explicitly allocating it

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
            return rc;
        }
    }

    // Now query the status.  We do this by:
    // * talk
    // * raw read on channel 15
    // * untalk
    DEBUG("Talk on channel 15");
    rc = cbm_talk(cbm->fd, cbm->device_num, COMMAND_CHANNEL);
    if (rc < 0)
    {
        return rc;
    }
    DEBUG("Read");
    now = time(NULL);
    len = cbm_raw_read(cbm->fd, cbm->error_buffer, sizeof(cbm->error_buffer)-1);
    DEBUG("Untalk");
    cbm_untalk(cbm->fd);
    if (len < 0)
    {
        return rc;
    }
    assert(len < (int)sizeof(cbm->error_buffer));

    // Ensure string properly NULL terminated
    if (len > 0)
    {
        // Strip off a single byte cos this seems to return a weird byte
        // at the end
        len--;
    }
    cbm->error_buffer[len] = 0;
    cbm->error_buffer[MAX_ERROR_LENGTH - 1] = 0;

    DEBUG("Exiting check status: %d %s", len, cbm->error_buffer);

    // Both 00,OK 01, FILES SCRATCHED and 73,CBM ... are OK responses
    // Anything else is considered an error
    rc = -1;
    if (!strncmp(cbm->error_buffer,
                 DOS_OK_PREFIX,
                 strlen(DOS_OK_PREFIX)) ||
        !strncmp(cbm->error_buffer,
                 DOS_FS_PREFIX,
                 strlen(DOS_FS_PREFIX)) ||
        !strncmp(cbm->error_buffer,
                 DOS_BOOT_PREFIX,
                 strlen(DOS_BOOT_PREFIX)))
    {
        rc = 0;
    }

    // Store off the last error code.  Here 00 and 01 are not errors, but 73
    // is considered an error
    if (strncmp(cbm->error_buffer,
                 DOS_OK_PREFIX,
                 strlen(DOS_OK_PREFIX)) &&
        strncmp(cbm->error_buffer,
                 DOS_FS_PREFIX,
                 strlen(DOS_FS_PREFIX)))
    {
        strcpy(cbm->last_error, cbm->error_buffer);
    }

    // Get the error status as an integer
    status = atoi(cbm->error_buffer);
    status += 100;
    assert(status >= 0);
    entry = find_fuse_file_entry(cbm, GET_LAST_STATUS_CMD);
    if (entry != NULL)
    {
        // Update the get current status command filesize with the error code
        entry->filesize = status;
        update_fuse_stat(entry, &now);
    }

    // Codes above (100+) 00 and 01 considered error for last_error:
    if (status > 101)
    {
        entry = find_fuse_file_entry(cbm, GET_LAST_ERROR_CMD);
        if (entry != NULL)
        {
            // Update the get current status command filesize with the error code
            entry->filesize = status;
            update_fuse_stat(entry, &now);
        }
    }

    return rc;
} 

// Function to query drive status.  If you want to run a command first, call
// check_drive_status_cmd() directly.
//
// Must be called within a mutex lock if called after our fuse _init() function
// has been called, and before fuse_exit() has been called.
int check_drive_status(CBM *cbm)
{
    return check_drive_status_cmd(cbm, NULL);
}

