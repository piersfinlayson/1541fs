#include "cbmfuse.h"

// Details about dummy files

const struct dummy_files dummy_files[] =
{
    {
        PATH_FORCE_DISK_REREAD,
        "To format a disk write the new disk name followed by the ID to this file.\n"
        "The disk name can be a maximum of 16 characters and the ID two digits.\n"
        "Separate the two with a comma.  For example:\n"
        "  echo \"my new disk,01\" > ./" PATH_FORMAT_DISK "\n",
    },
    {
        PATH_FORMAT_DISK,
        "To force a disk re-read, write anything to this file.  For example:\n"
        "  echo \"1\" > ./" PATH_FORCE_DISK_REREAD "\n",
    },
    {
        NULL,
        NULL,
    },
};

const char *dummy_dirs[] =
{
    ".",
    "..",
    NULL,
};