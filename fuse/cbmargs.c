#include "cbmfuse.h"

static struct options
{
    char *device_num;
    int show_help;
    int show_version;
    int force_bus_reset;
    int dummy_formats;
    char *mountpoint;
} options;

#define OPTION(t, p) \
    { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
    OPTION("-d %s", device_num),
    OPTION("--device %s", device_num),
    OPTION("--version", show_version),
    OPTION("-?", show_help),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    OPTION("-b", force_bus_reset),
    OPTION("--bus-reset", force_bus_reset),
    OPTION("-u", dummy_formats),
    OPTION("--dummy-formats", dummy_formats),
    FUSE_OPT_KEY("-f", FUSE_OPT_KEY_KEEP),
    FUSE_OPT_END
};

// Called by fuse_opt_parse when a non-option (-o) argument is found so we can
// handle it
static int opt_proc(void *data,
                    const char *arg,
                    int key,
                    struct fuse_args *outargs)
{
    (void)data;
    (void)outargs;

    switch (key)
    {
        case FUSE_OPT_KEY_NONOPT:
            if (options.mountpoint == NULL)
            {
                options.mountpoint = strdup(arg);
                // Remove from options list so FUSE doesn't see it twice
                return 0;
            }
            break;

        default:
            return 1;
    }

    return 1;
}

// Main arg processing, called by main()
int process_args(struct fuse_args *args, CBM *cbm)
{
    int ret = 1;
    struct fuse_cmdline_opts fuse_opts = { 0 };

    assert(args != NULL);
    assert(cbm != NULL);

    // First parse custom options
    DEBUG("Parse args");
    if (fuse_opt_parse(args, &options, option_spec, opt_proc) == -1)
    {
        ERROR("Failed to parse options");
        goto EXIT;
    }

    // Then let FUSE parse its built-in options
    DEBUG("Parse fuse args");
    if (fuse_parse_cmdline(args, &fuse_opts) == -1)
    {
        ERROR("Failed to parse FUSE options\n");
        goto EXIT;
    }

    // Now handle our args
    if (options.show_version)
    {
        printf("1541fs-fuse version %s\n", VERSION);
        ret = -1;
        goto EXIT;
    }
    if (options.show_help)
    {
        printf("1541fs-fuse\n");
        printf("\n");
        printf("Mounts one or more XUM1541 attached Commodore disk drives as a linux FUSE\nfilesystem.\n");
        printf("\n");
        printf("Usage:\n");
        printf("  1541fs-fuse [options] mountpoint\n");
        printf("    -d|--device <device_num=8|9|10|11>  set device number (default: 8)\n");
        printf("    -b|--bus-reset         force a bus (IEC/IEEE-488) reset before mount\n");
        printf("    -u|--dummy-formats     don't actually format the disk if requested\n");
        printf("    -?|-h|--help           show help\n");
        printf("    --version              show version\n");
        fuse_lib_help(args);
        ret = -1;
        goto EXIT;
    }
    if (options.mountpoint == NULL)
    {
        WARN("No mountpint defined - exiting");
        printf("No mountpoint defined - exiting\n");
        goto EXIT;
    }
    cbm->mountpoint = options.mountpoint;
    cbm->force_bus_reset = options.force_bus_reset;
    cbm->dummy_formats = options.dummy_formats;
    if (options.device_num == NULL)
    {
        cbm->device_num = DEFAULT_DEVICE_NUM;
        INFO("No device number specified - defaulting to device 8");
    }
    else
    {
        int device_num = atoi(options.device_num);
        assert(MIN_DEVICE_NUM >= 0);
        assert(MIN_DEVICE_NUM < 256);
        assert(MAX_DEVICE_NUM < 256);
        if ((device_num < MIN_DEVICE_NUM) || (device_num > MAX_DEVICE_NUM))
        {
            WARN("Invalid device number specified: %s", options.device_num);
            printf("Invalid device number specified: %s\n", options.device_num);
            goto EXIT;
        }
        else
        {
            cbm->device_num = (unsigned char)device_num;
        }
    }
    INFO("Using device number: %d", cbm->device_num);
    printf("Using device number: %d\n", cbm->device_num);
    fflush(stdout);

    ret = 0;

EXIT:

    return ret;
}

void destroy_args(CBM *cbm)
{
    if (cbm->mountpoint != NULL)
    {
        free(cbm->mountpoint);
        cbm->mountpoint = NULL;
    }
}