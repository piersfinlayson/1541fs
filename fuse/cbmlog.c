#include "cbmfuse.h"

int current_log_level = LOG_DEBUG;

// Set up logging to syslog/messages.
void init_logging()
{
    openlog(APP_NAME, LOG_PID | LOG_CONS, LOG_DAEMON);
    DEBUG("Started logging");
}

