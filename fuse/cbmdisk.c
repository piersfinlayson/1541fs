#include "cbmfuse.h"

// Contains CBM disk operation code

int process_format_request(CBM *cbm, const char *buf, size_t size)
{
    int rc = -1;
    int rc2;

    DEBUG("ENTRY: process_format_request()");

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
    if (strlen(id) != ID_LEN)
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

    DEBUG("EXIT: process_format_request()");

    return rc;
}