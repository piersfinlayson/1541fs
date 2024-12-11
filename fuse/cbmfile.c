#include "cbmfuse.h"

// Special paths
// Must not begin or terminate the / or FUSE will barf
const char *special_dirs[] =
{
    ".",
    "..",
    NULL
};

const char *special_files[] = {
    PATH_FORCE_DISK_REREAD,
    PATH_FORMAT_DISK,
    NULL,
};

// Removes any trailing spaces from the end of a string
static int remove_trailing_spaces(char *str) {
    int len = (int)strlen(str);
    int ii;

    // Iterate from the end of the string towards the beginning
    for (ii = len - 1; ii >= 0; ii--)
    {
        if (str[ii] != ' ')
        {
            break;
        }
    }

    // Terminate the string after the last non-space character
    str[ii + 1] = '\0';

    return (ii + 1);
}

// Reallocates a line_count number of directory entries, retaining the
// existing entries
static void realloc_dir_entries(CBM *cbm, int line_count)
{
    if (line_count > cbm->num_dir_entries)
    {
        // We can't reuse - better free and malloc a new one
        if (cbm->dir_entries != NULL)
        {
            free(cbm->dir_entries);
            cbm->dir_entries = NULL;
        }
        cbm->dir_entries = malloc((size_t)line_count * sizeof(struct cbm_dir_entry));
        if (cbm->dir_entries != NULL)
        {
            cbm->num_dir_entries = line_count;
        }
        else
        {
            cbm->num_dir_entries = 0;
            goto EXIT;
        }
    }
    memset(cbm->dir_entries, 0, (size_t)line_count * sizeof(struct cbm_dir_entry));

EXIT:

    return;
}

// Reallocates a buffer if we've run out of space
static void check_realloc_buffer(char **buffer,
                          unsigned int *buf_len,
                          const unsigned int pos)
{
    char *new_buffer;

    assert(buffer != NULL);
    if (pos >= *buf_len)
    {
        *buf_len += BUF_INC;
        new_buffer = realloc(*buffer, *buf_len);

        // The following handles the case if the remalloc failed -
        // the original buffer will still be freed, and buffer set to NULL
        free(*buffer);
        *buffer = new_buffer;
    }
}

// Reads in the directory from a CBM disk
int read_dir_from_disk(CBM *cbm)
{
    unsigned int buf_len;
    unsigned int data_len;
    unsigned int pos;
    char *buffer = NULL;
    int rc = 0;
    int error;
    char c;
    int line_count;
    struct cbm_dir_entry *dir_entry = NULL;

    cbm->dir_is_clean = 0;

    // malloc a buffer to store data read from the disk in
    DEBUG("Allocate buffer to read in data");
    buf_len = BUF_INC;
    buffer = malloc(buf_len);
    if (buffer == NULL)
    {
        DEBUG("Failed to allocate memory for buffer to read dir into");
        rc = -ENOMEM;
        goto EXIT;
    }

    // open the directory "file" ($)
    DEBUG("Open $");
    c = cbm_ascii2petscii_c('$');
    error = cbm_open(cbm->fd, cbm->device_num, 0, &c, 1);
    if (error)
    {
        DEBUG("Open of $ failed");
        rc = -EIO;
        goto EXIT;
    }
    cbm_talk(cbm->fd, cbm->device_num, 0);

    // Read in directory listing from the drive
    DEBUG("Read in directory data");
    pos = 0;
    while (cbm_raw_read(cbm->fd, buffer + pos, 1) == 1)
    {
        pos++;
        if (pos >= buf_len)
        {
            check_realloc_buffer(&buffer, &buf_len, pos);

        }
        if (buffer == NULL)
        {
            DEBUG("Out of memory while reading directory");
            rc = -ENOMEM;
            goto EXIT;
        }
    }
    data_len = pos;
    DEBUG("Read %d bytes total directory listing", data_len);

    cbm_untalk(cbm->fd);
    if (check_drive_status(cbm))
    {
        DEBUG("Hit error reading from disk");
        goto EXIT;
    }
    cbm_close(cbm->fd, cbm->device_num, 0);

    // Estimate how many lines there are - we'll estimate 28 bytes to a line
#define APPROX_BYTES_IN_DIR_LINE 28
    DEBUG("Calculate appox number of lines in directory listing");
    int approx_line_count = (int)(data_len / APPROX_BYTES_IN_DIR_LINE + (data_len % APPROX_BYTES_IN_DIR_LINE ? 1 : 0));
    DEBUG("Approximate number of lines in directory listing: %d", approx_line_count);
    if (approx_line_count <= 0)
    {
        DEBUG("0 lines in directory listing");
        goto EXIT;
    }

    DEBUG("Realloc directory entries");
    realloc_dir_entries(cbm, approx_line_count);
    if (cbm->dir_entries == NULL)
    {
        DEBUG("Failed to allocate memory for directory entries");
        rc = -ENOMEM;
        goto EXIT;
    }

    // Note our number of directory entries may be wrong - we'll figure this out
    // later

    // Check 1st 3 bytes
    DEBUG("Check 1st 4 bytes of listing");
    pos = 0;
    if (data_len < 4)
    {
        DEBUG("Fewer than 4 bytes in whole dir listing");
        goto EXIT;
    }
    if ((buffer[0] != 0x1) ||
        (buffer[1] != 0x4) ||
        (buffer[2] != 0x1) ||
        buffer[3] != 0x1)
    {
        DEBUG("Unexpected first 4 bytes: 0x%x 0x%x 0x%x 0x%x",
              buffer[0],
              buffer[1],
              buffer[2],
              buffer[3]);
        goto EXIT;
    }
    pos += 4;

    // Now read lines
    DEBUG("Read lines of listing");
    dir_entry = cbm->dir_entries;
    assert(dir_entry != NULL);
    line_count = 0;
    while (pos < data_len)
    {
        DEBUG("Reading line of listing");

        // Check if have run out of dir_entries
        if (cbm->num_dir_entries < (line_count+1))
        {
            INFO("Estimated number of lines in directory incorrectly");
            realloc_dir_entries(cbm, line_count+1);
            if (cbm->dir_entries == NULL)
            {
                DEBUG("Failed to reallocate memory for directory entries");
                rc = -ENOMEM;
                goto EXIT;
            }
        }
        
        DEBUG("Get blocks for this file");
        // Get the number of blocks for this file
        if (pos >= (buf_len + 2))
        {
            DEBUG("Ran out of data too soon");
            goto EXIT;
        }
        DEBUG("Next 2 bytes for block size: 0x%x 0x%x", (unsigned char)buffer[pos], (unsigned char)buffer[pos+1]);
        dir_entry->num_blocks = (unsigned char)buffer[pos++];
        // If the 2nd byte is 0x12 that means reverse text - so header
        // Assume any value below this is high order byte, any value
        // above this isn't.
        if (buffer[pos] < 0x12)
        {
            dir_entry->num_blocks |= (unsigned short)(buffer[pos++] << 8);
        }
        dir_entry->filesize = dir_entry->num_blocks * CBM_BLOCK_SIZE;
        DEBUG("Num blocks: %d, Filesize: %d", dir_entry->num_blocks, dir_entry->filesize);

        int filename_started = 0;
        int filename_ended = 0;
        int filename_len = 0;
        int is_header = 0;
        int is_footer = 0;
        int suffix_ended = 0;
        char suffix[4] = {0, 0, 0, 0};
        int suffix_len = 0;

        DEBUG("Read rest of line data");
        while ((pos < data_len) && 
               (buffer[pos] != 0x1))
        {
            c = buffer[pos];
            DEBUG("Got byte: 0x%x", c);
            if (is_footer)
            {
                // ignore the footer - just says "blocks free"
                DEBUG("Footer - ignore");
                assert(!filename_started);
            }
            else if (suffix_ended)
            {
                // ignore any remaining bytes
            }
            else if (!filename_started)
            {
                assert(!filename_ended);
                if (c == 0x20)
                {
                    // ignore leading spaces
                }
                else if (c == 0x12)
                {
                    DEBUG("Found header");
                    is_header = 1;
                    dir_entry->is_header = 1;
                }
                else if (c == '"')
                {
                    DEBUG("Filename started");
                    filename_started = 1;
                }
                else if (c == 0x42) // PETSCII for b
                {
                    DEBUG("Found footer");
                    assert(!is_header);
                    is_footer = 1;
                }
            }
            else if (!filename_ended)
            {
                assert(!is_footer);
                if (c == '"')
                {
                    DEBUG("Filename ended");
                    filename_ended = 1;
                }
                else
                {
                    DEBUG("Add char to filename: %c", c);
                    // Any other char just gets added to the filename
                    // We'll cope with trailing spaces when appending the .XXX
                    // suffix
                    // We sade 5 chars for the 4 digit suffix and 1xNULL terminator
                    if (filename_len < (MAX_FILENAME_LEN - 5))
                    {
                        dir_entry->filename[filename_len] = cbm_petscii2ascii_c(c);
                        filename_len++;
                    }
                    else
                    {
                        WARN("Filename is longer than max len - truncated version is: %s", dir_entry->filename);
                    }
                }
            }
            else if (suffix_len > 0)
            {
                if (c == ' ')
                {
                    DEBUG("End of suffix: %s", suffix);
                    // Suffix has ended - we could match with valid ones, but
                    // we won't bother - instead we'll just add to the
                    // filename
                    filename_len = remove_trailing_spaces(dir_entry->filename);
                    assert(filename_len < (MAX_FILENAME_LEN - 5));
                    dir_entry->filename[filename_len] = dir_entry->is_header ? ',' : '.';
                    dir_entry->filename[filename_len+1] = 0;
                    strncat(dir_entry->filename, suffix, 4);
                    suffix_ended = 1;
                }
                else if (suffix_len < 3)
                {
                    DEBUG("Add char to suffix: %c", c);
                    suffix[suffix_len++] = cbm_petscii2ascii_c(c);
                }
                else
                {
                    // Drop any more chars
                    assert(suffix[3] == 0);
                    WARN("Suffix is too long - truncated version is: %s", suffix);
                }
            }
            else
            {
                assert(filename_started);
                assert(filename_ended);
                assert(!is_footer);
                assert(suffix_len == 0);
                if (c == ' ')
                {
                    DEBUG("Ignore space after filename and before suffix");
                    // Ignore
                }
                else
                {
                    DEBUG("First char of suffix: %c", c);
                    suffix[suffix_len++] = cbm_petscii2ascii_c(c);
                }
            }

            // Move to next char
            pos++;
        }


        if (!is_footer)
        {
            DEBUG("Added directory entry #%d: header %d name %s size %d cbm blocks %d",
                line_count,
                dir_entry->is_header,
                dir_entry->filename,
                dir_entry->filesize,
                dir_entry->num_blocks);
            dir_entry++;
            line_count++;
        }

        // Don't add the footer
        if (pos >= (buf_len + 2))
        {
            DEBUG("Not enough data to read another line - exiting line parsing");
        }
        // Next two bytes should be 0x1 and 0x1, or 0x0 and 0x0 after footer
        DEBUG("Skipping next 2 bytes: 0x%d 0x%d", buffer[pos], buffer[pos+1]);
        pos += 2;
    }

    assert(line_count <= cbm->num_dir_entries);
    cbm->num_dir_entries = line_count;
    cbm->dir_is_clean = 1;
    rc = 0;

EXIT:

    DEBUG("Exiting read directory function");
    if (!rc)
    {
        DEBUG("Number of directory entries: %d is_clean: %d", cbm->num_dir_entries, cbm->dir_is_clean);
    }

    if (buffer != NULL)
    {
        free(buffer);
    }

    return rc;

}

// Generic function which decides in this is a special file or special
// directory
static int is_special(const char *path, const char **strings)
{
    int ii;
    const char *match;
    int rc = 0;
    if (!strcmp(path, "/"))
    {
        rc = 1;
        goto EXIT;
    }
    for (ii = 0, match=strings[ii];
         match != NULL;
         ii++, match=strings[ii])
    {
        if (!strcmp(path+1, match))
        {
            rc = 1;
            goto EXIT;
        }
    }

EXIT:

    return rc;
}

int is_special_dir(const char *path)
{
    return is_special(path, special_dirs);
}

int is_special_file(const char *path)
{
    return is_special(path, special_files);
}

// Sets up stat information about the file in order to provide it to FUSE
void set_stat(struct cbm_dir_entry *entry, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));

    // Num blocks is tricky.  It's supposed to represent the number of
    // 512 byte blocks.  But our filesystem has size 256 blocks.  So we
    // must convert into 512 byte blocks
    assert(CBM_BLOCK_SIZE == 256);
    stbuf->st_blocks = (int)((entry->filesize + 255) / 256 / 2);
    stbuf->st_blksize = CBM_BLOCK_SIZE;
    stbuf->st_size = (int)(entry->filesize);
    if (!entry->is_dir)
    {
        stbuf->st_mode |= S_IFREG | 0444;
        stbuf->st_nlink = 1;
    }
    else
    {
        stbuf->st_mode |= S_IFDIR | 0555;
        stbuf->st_nlink = 2;
    }
    if (!entry->is_special)
    {
        stbuf->st_atime = stbuf->st_ctime = stbuf->st_mtime = time(NULL);
    }
}

void destroy_files(CBM *cbm)
{
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
}
