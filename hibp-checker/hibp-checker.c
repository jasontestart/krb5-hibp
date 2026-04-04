#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <confuse.h>
#include <hibp.h>

int main(void) {

    int retval = 0;
    long long threshold = 0;
    char *proxy_url = NULL;
    char *api_url = NULL;

    const char *conf_filename = "/etc/hibp-checker.conf";

    /* The conf file needs to be a private root-owned regular file with
     * permissions 0700. If not, silently ignore it.
     */
    struct stat conf_stat;
    if (stat(conf_filename, &conf_stat) == 0) {
        if ( !S_ISREG(conf_stat.st_mode) || (conf_stat.st_mode & 0777) != 0700 || conf_stat.st_uid != 0 ) {
            goto ignoreconfig;
        }
    } else {
        goto ignoreconfig;
    }

    /* Process the config file */
    FILE *conf_file;
    conf_file = fopen(conf_filename, "r");
    if (!conf_file)
        goto ignoreconfig;

    cfg_opt_t opts[] = {
        CFG_INT("threshold", 0, CFGF_NONE),
        CFG_STR("proxy", NULL, CFGF_NONE),
        CFG_STR("api", NULL, CFGF_NONE),
        CFG_END()
    };

    cfg_t *cfg;
    cfg = cfg_init(opts, CFGF_NONE);
    
    if(cfg_parse_fp(cfg, conf_file) != CFG_PARSE_ERROR) {
        threshold = cfg_getint(cfg, "threshold");
        api_url = cfg_getstr(cfg, "api");
        proxy_url = cfg_getstr(cfg, "proxy");
    }

    cfg_free(cfg);
    fclose(conf_file);

ignoreconfig:

    /* Process stdin */
    char line_one[256+13];
    char line_two[512+16];
    char line_three[3+2];
    char principal[256];
    char password[512];

    /* Init buffers to null */
    memset(principal, 0, sizeof(principal));
    memset(password, 0, sizeof(password));

    const char *input_error = "Invalid input: Heimdal KDC external check protocol failure.";
    if (fgets(line_one, sizeof(line_one), stdin)  && !strncmp(line_one, "principal: ", 11)) {
        /* extract the principal value from the first line of stdin, removing the newline character(s) */
        strncpy(principal, (char *)(line_one+11), strlen((char *)(line_one+11)));
        principal[strcspn(principal, "\r\n")] = '\0';
    } else {
        puts(input_error);
        return(1);
    }

    if (fgets(line_two, sizeof(line_two), stdin)  && !strncmp(line_two, "new-password: ", 14)) {
        /* extract the password value from the second line of stdin, removing the newline character(s) */
        strncpy(password, (char *)(line_two+14), strlen((char *)(line_two+14)));
        password[strcspn(password, "\r\n")] = '\0';
    } else {
        puts(input_error);
        return(1);
    }

    if (fgets(line_three, sizeof(line_three), stdin)  && strncmp(line_three, "end\n", 4)) {
        puts(input_error);
        retval = 1;
        goto cleanup;
    }

    /* Check the Pwned Password database. */
    long long occurences = is_pwned_password(password, proxy_url, api_url);

    if (occurences < 0) {
        puts("API Error");
        retval = 1;
        goto cleanup;
    }

    if (occurences > threshold)
        printf("REJECTED: New password for %s found Pwned Password database.\n", principal);
    else
        puts("APPROVED");

cleanup:

    /* Erase the plain text password from memory - wipe the whole buffer */
    memset(password, 0, sizeof(password));

    return(retval);
}
