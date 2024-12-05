#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <opencbm.h>

#ifndef VERSION
#define VERSION 0.1
#endif
#define FILENAME "HELLORLD,S"
#define BUFFER_SIZE 256
#define DEVICE_NUM 8
#define SA_DIR 0
#define SA_READ 0
#define SA_WRITE 1
#define SA_CMD 15
#define SA_SCRATCH SA_CMD
#define SA_FORMAT SA_CMD
#define TO_PETSCII_C(X) cbm_ascii2petscii_c(X)
#define TO_ASCII_C(X) cbm_petscii2ascii_c(X)
#define TO_PETSCII(X) cbm_ascii2petscii(X)
#define TO_ASCII(X) cbm_petscii2ascii(X)

const char *test_data = "Hellord!";

// Function prototypes
void possibly_format_disk();
void clean_exit(int rv);
void check_error(const char *operation);
void list_directory();
void read_file(const char *filename);
void write_file(const char *filename, const char *data);
void run_command(const char *command);
void scratch_file(const char *filename);
void format_disk(const char *disk_name, const char *disk_id);
static CBM_FILE fd;
static int error;
static char status[65];

int main()
{
    fprintf(stdout, "1541fs-test  version: %s\n", VERSION);
    fprintf(stdout, "===========\n");
    fprintf(stdout, "\n");

    // Initialize the driver
    error = cbm_driver_open(&fd, 0);
    check_error("Opening driver");

    // Reset the drive
    error = cbm_reset(fd);
    check_error("Resetting drive");

    possibly_format_disk();

    // Directory listing
    list_directory(fd);

    // Write a test file
    write_file(FILENAME, test_data);

    // Directory listing
    list_directory(fd);

    // Read it back
    read_file(FILENAME);

    // Scratch it
    scratch_file(FILENAME);

    // Directory listing again
    list_directory();

    // Clean up
    clean_exit(0);
}

void possibly_format_disk()
{
    char c;
    char diskname[17];
    char diskid[3];
    char input_buffer[128];

    fprintf(stdout, "Would you like to format the disk? ");
    if (fgets(input_buffer, 128, stdin) == NULL)
    {
        input_buffer[0] = 0;
    }
    c = input_buffer[0];
    if (c == 'y' || c == 'Y')
    {
        do
        {
            fprintf(stdout, "Enter disk name (max 16 chars): ");
            if (fgets(input_buffer, 128, stdin) == NULL)
            {
                input_buffer[0] = 0;
            }
            input_buffer[strcspn(input_buffer, "\n")] = 0; // Get rid of newline
        } while (strnlen(input_buffer, 128) > 16);
        snprintf(diskname, sizeof(diskname), "%s", input_buffer);
        do
        {
            fprintf(stdout, "Enter disk ID (2 chars): ");
            if (fgets(input_buffer, 128, stdin) == NULL)
            {
                input_buffer[0] = 0;
            }
            input_buffer[strcspn(input_buffer, "\n")] = 0; // Get rid of newline
        } while (strnlen(input_buffer, 128) != 2);
        snprintf(diskid, sizeof(diskid), "%s", input_buffer);

        fprintf(stdout, "Formatting disk: %s,%s", diskname, diskid);
        snprintf(diskid, sizeof(diskid), "%s", input_buffer);

        format_disk(diskname, diskid);
    }
    else
    {
        fprintf(stdout, "Not formatting disk\n");
    }
}

void clean_exit(int rv)
{
    if (fd)
    {
        cbm_driver_close(fd);
    }
    exit(rv);
}

void check_error(const char* operation)
{
    if (error) {
        fprintf(stderr, "Error during %s: %d\n", operation, error);
        clean_exit(1);
    }
}

void list_directory()
{
    unsigned char buffer[BUFFER_SIZE];
    char c;

    // Open the directory channel (usually "$")
    c = TO_PETSCII_C('$');
    error = cbm_open(fd, DEVICE_NUM, SA_DIR, &c, 1);
    check_error("Opening directory");

    // Get drive status
    error = cbm_device_status(fd, DEVICE_NUM, status, sizeof(status));
    check_error("Reading device status after opening directory");

    cbm_talk(fd, DEVICE_NUM, 0);

    // Read directory entries
    if (cbm_raw_read(fd, buffer, 2) == 2)
    {
        fprintf(stdout, "\nDirectory listing:\n");
        while (cbm_raw_read(fd, buffer, 2) == 2)
        {
            if (cbm_raw_read(fd, buffer, 2) == 2)
            {
                fprintf(stdout, "%u ", (unsigned char)buffer[0] | (unsigned char)buffer[1] << 8 );
                while((cbm_raw_read(fd, &c, 1) == 1) && c)
                {
                    putchar(TO_ASCII_C(c));
                }
                putchar('\n');
            }
        }
    }
    cbm_untalk(fd);

    // Get drive status
    error = cbm_device_status(fd, DEVICE_NUM, status, sizeof(status));
    check_error("Reading device status after directory listing");

    // Close the directory
    error = cbm_close(fd, DEVICE_NUM, SA_DIR);
    check_error("Closing connection");
}

void read_file(const char* filename)
{
    unsigned char buffer[BUFFER_SIZE];
    int bytes_written;

    size_t filename_len = strlen(filename);

    // Open the file for reading
    error = cbm_open(fd, DEVICE_NUM, SA_READ, NULL, 0);
    check_error("Opening connection");
    bytes_written = cbm_raw_write(fd, filename, filename_len);
    if (bytes_written < 0)
    {
        fprintf(stderr, "Error: Failed to write data %d", bytes_written);
        clean_exit(1);
    }
    if ((size_t)bytes_written != filename_len)
    {
        fprintf(stderr, "Error: Only wrote %d of %zu bytes of filename\n", bytes_written, filename_len);
        clean_exit(1);
    }
    cbm_unlisten(fd);
    error = cbm_device_status(fd, DEVICE_NUM, status, sizeof(status));
    check_error("Sending filename");

    fprintf(stdout, "\nReading %s:\n", filename);
    cbm_talk(fd, DEVICE_NUM, SA_READ);
    // Read file contents in chunks
    while (1) {
        int bytes_read = cbm_raw_read(fd, buffer, sizeof(buffer));
        if (bytes_read <= 0) break;

        // Process the data (here we just print it)
        fprintf(stdout, "%.*s", bytes_read, buffer);
    }
    fprintf(stdout, "\n");
    cbm_untalk(fd);

    // Close the file
    error = cbm_close(fd, DEVICE_NUM, SA_READ);
    check_error("Closing connection");
}

void write_file(const char* filename, const char* data)
{
    int bytes_written;

    size_t filename_len = strlen(filename);

    // Open the file for writing
    error = cbm_open(fd, DEVICE_NUM, SA_WRITE, NULL, 0);
    check_error("Opening connection");
    bytes_written = cbm_raw_write(fd, filename, filename_len);
    if (bytes_written < 0)
    {
        fprintf(stderr, "Error: Failed to write data %d", bytes_written);
        clean_exit(1);
    }
    if ((size_t)bytes_written != filename_len)
    {
        fprintf(stderr, "Error: Only wrote %d of %zu bytes of filename\n", bytes_written, filename_len);
        clean_exit(1);
    }
    cbm_unlisten(fd);
    error = cbm_device_status(fd, DEVICE_NUM, status, sizeof(status));
    check_error("Sending filename");

    // Write the data
    size_t data_length = strlen(data);
    cbm_listen(fd, DEVICE_NUM, SA_WRITE);
    bytes_written = cbm_raw_write(fd, (const void*)data, data_length);
    if (bytes_written < 0)
    {
        fprintf(stderr, "Error: Failed to write data %d", bytes_written);
        clean_exit(1);
    }
    if ((size_t)bytes_written != data_length) {
        fprintf(stderr, "Error: Only wrote %d of %zu bytes\n", 
                bytes_written, data_length);
        error = cbm_device_status(fd, DEVICE_NUM, status, sizeof(status));
        check_error("Sending file contents to write");
        clean_exit(1);
    }

    // Close the file
    cbm_unlisten(fd);
    error = cbm_close(fd, DEVICE_NUM, SA_WRITE);
    check_error("Closing connection");

    fprintf(stdout, "\nSuccessfully wrote %s\n", filename);
}

void run_command(const char* command)
{
    int bytes_written;
    size_t command_len;

    fprintf(stdout, "\nIssuing command: %s\n", command);
    command_len = strlen(command);

    error = cbm_open(fd, DEVICE_NUM, SA_CMD, NULL, 0);
    check_error("Opening connection");

    cbm_listen(fd, DEVICE_NUM, SA_CMD);
    bytes_written = cbm_raw_write(fd, command, strlen(command));
    if (bytes_written < 0)
    {
        fprintf(stderr, "Error: Failed to write data %d", bytes_written);
        clean_exit(1);
    }
    if ((size_t)bytes_written != command_len)
    {
        fprintf(stderr, "Error: Only wrote %d of %zu bytes of command: %s\n", bytes_written, command_len, command);
    }
    while (1)
    {
        error = cbm_device_status(fd, DEVICE_NUM, status, sizeof(status));
        if ((error != 73) || (command[0] != 'N'))
        {
            break;
        }
        else
        {
            fprintf(stdout, "Received error code 73 - ignoring, as this expected for a format/new command\n");
        }
    }
    check_error("Issuing command");

    cbm_unlisten(fd);
    error = cbm_close(fd, DEVICE_NUM, SA_CMD);
    check_error("Closing connection");
}

void scratch_file(const char* filename)
{
    char command[128];

    sprintf(command, "SCRATCH0:%s", filename);
    run_command(command);

    fprintf(stdout, "Successfully scratched %s\n", filename);
}

void format_disk(const char* disk_name, const char* disk_id)
{
    char command[128];

    assert(strlen(disk_name) <= 17);
    assert(strlen(disk_id) == 2);

    sprintf(command, "N0:%s,%s", disk_name, disk_id);
    run_command(command);

    fprintf(stdout, "Successfully formatted %s,%s\n", disk_name, disk_id);
}