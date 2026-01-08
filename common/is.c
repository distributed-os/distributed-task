#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <stdbool.h>

bool is_valid_ipv4(const char *ip_str)
{
    regex_t regex;
    int ret;

    if (!ip_str)
        return false;

    // Regular expression pattern for IPv4 addresses
    // Matches 0.0.0.0 to 255.255.255.255
    const char *pattern = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                         "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

    // Compile the regular expression
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        return false;
    }

    // Execute the match
    ret = regexec(&regex, ip_str, 0, NULL, 0);

    // Free the regular expression
    regfree(&regex);

    return (ret == 0);
}
