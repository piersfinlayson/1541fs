#include "cbmfuse.h"

static struct options
{
    char *device_num;
    int show_help;
    int show_version;
    int force_bus_reset;
    int dummy_formats;
    int daemonize;
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
    OPTION("--daemonize", daemonize),
    OPTION("--daemonise", daemonize),
    OPTION("--daemon", daemonize),
    OPTION("-z", daemonize),
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

int handle_mountpoint(CBM *cbm, const char *mountpoint)
{
    int rc = -1;

    ENTRY();

    if (mountpoint == NULL)
    {
        ERROR("No mountpint defined - exiting");
        printf("No mountpoint defined - exiting\n");
        goto EXIT;
    }
    if (mountpoint[0] == '/')
    {
        // Absolute path
        cbm->mountpoint = strdup(mountpoint);
        if (cbm->mountpoint == NULL)
        {
            ERROR("Couldn't get memory to store mountpoint %s",
                  mountpoint);
            goto EXIT;
        }
    }
    else 
    {
        // Relative path

        // Get path we were executed from
        char path[PATH_MAX];
        ssize_t rl_len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (rl_len == -1)
        {
            ERROR("Can't get current path, to contruct mountpoint");
            printf("Error getting current path - exiting\n");
            goto EXIT;
        }
        path[rl_len] = '\0';
        assert(rl_len > 0);
        assert(rl_len < (PATH_MAX-1));
        char *last_slash = strrchr(path, '/');
        if (last_slash != NULL)
        {
            // Truncate the string at the last '/' to strip the executable
            // name
            *(last_slash+1) = '\0';
        }
        DEBUG("Executed from path %s", path);

        size_t len = strlen(path);
        size_t len_left = PATH_MAX-len-1;
        assert(len_left > strlen(mountpoint));
        off_t offset = 0;
        if ((strlen(mountpoint) >= 2) && 
            (mountpoint[0] == '.') && 
            (mountpoint[1] == '/'))
        {
            // If the mountpoint started with ./ strip it, because it's not
            // needed
            offset = 2;
        }
        strncat(path, mountpoint+offset, len_left);
        cbm->mountpoint = strdup(path);
        DEBUG("Mountpoint: %s", cbm->mountpoint);
    }

    rc = 0;

EXIT:

    EXIT();

    return rc;
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
        printf("    -z|--daemonize         daemonize (after initialization has completed)");
        printf("    -?|-h|--help           show help\n");
        printf("    --version              show version\n");
        fuse_lib_help(args);
        ret = -1;
        goto EXIT;
    }

    ret = handle_mountpoint(cbm, options.mountpoint);
    free(options.mountpoint);
    if (ret)
    {
        goto EXIT;
    }

    printf("Mountpoint: %s\n", cbm->mountpoint);

    cbm->force_bus_reset = options.force_bus_reset;
    cbm->dummy_formats = options.dummy_formats;
    cbm->daemonize = options.daemonize;
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
