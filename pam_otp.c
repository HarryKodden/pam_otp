/* Copyright (C) 2018 Harry Kodden
 */

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <ldap.h>

#include "otp.h"

#define LASTLOGON "Lastlogin: %d"

typedef struct {
    int debug;
    char *ldap_uri;
    char *ldap_basedn;
    char *ldap_binddn;
    char *ldap_passwd;
    char *uid;
    char *ttl;
} module_config;

void
free_config(module_config *cfg)
{
    if (cfg) {
        free(&cfg->ldap_uri);
        free(&cfg->ldap_basedn);
        free(&cfg->ldap_binddn);
        free(&cfg->ldap_passwd);
        free(&cfg->uid);
        free(&cfg->ttl);
        free(cfg);
    }
}

void debug(const pam_handle_t *pamh, module_config *cfg, const char *fmt, ...) {

    if (cfg->debug) {
        va_list l;

        va_start(l, fmt);
        pam_vsyslog(pamh, LOG_DEBUG, fmt, l);
        va_end(l);
    }
}

int ldap(pam_handle_t * pamh, module_config * cfg, const char *user, const char *token)
{
    LDAP *ld = NULL;
    LDAPMessage *result = NULL;

    if (! user) {
        pam_syslog(pamh, LOG_ERR, "Module error: called without an user");
        return PAM_AUTH_ERR;
    }

    if (! token) {
        pam_syslog(pamh, LOG_ERR, "Module error: called without an token");
        return PAM_AUTH_ERR;
    }

    int status = ldap_initialize(&ld, cfg->ldap_uri);

    if (status != LDAP_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Unable to connect to LDAP server");
        return PAM_AUTH_ERR;
    }

    BerValue *servercred = NULL;
    BerValue cred = { .bv_len = strlen(cfg->ldap_passwd) , .bv_val = cfg->ldap_passwd };
    int protocol = LDAP_VERSION3;

    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);
    status = ldap_sasl_bind_s(ld, cfg->ldap_binddn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &servercred);

    debug(pamh, cfg, "Binding...\n");

    if (status != LDAP_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Could not bind to LDAP server: %s", ldap_err2string(status));

        // cleanup ldap structure
        ldap_unbind_ext(ld, NULL, NULL);
        return PAM_AUTH_ERR;
    }

    char *base;

    if (asprintf(&base, "ou=people,%s", cfg->ldap_basedn) < 0) {
        ldap_unbind_ext(ld, NULL, NULL);
        return PAM_AUTH_ERR;
    }

    debug(pamh, cfg, "Searching: %s\n", base);
    char *filter;
    asprintf(&filter, "(%s=%s)", cfg->uid, user);

    status = ldap_search_ext_s(ld, base, LDAP_SCOPE_SUBTREE, filter,
                               0, 0, NULL,
                               NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &result);

    free(base);
    free(filter);

    if (status != LDAP_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Could not search in LDAP server: %s", ldap_err2string(status));

        // cleanup ldap structure
        ldap_unbind_ext(ld, NULL, NULL);
        return PAM_AUTH_ERR;
    }

    int retval = PAM_AUTH_ERR;

    LDAPMessage *e = NULL;
    for (e = ldap_first_entry(ld, result); e != NULL; e = ldap_next_entry(ld, e)) {

        char *dn = NULL;
        if ( (dn = ldap_get_dn( ld, e )) != NULL ) {
            debug(pamh, cfg, "DN: %s\n", dn);
        }

        BerElement *ber = NULL;
        char *a = NULL;
        int match = 0;
        char *secret = NULL;
        int lastlogon = 0;

        for (a = ldap_first_attribute(ld, e, &ber); a != NULL;
                a = ldap_next_attribute(ld, e, ber)) {

            BerValue **val;
            BerValue **vals = ldap_get_values_len(ld, e, a);

            for (val = vals; *val; ++val) {
                char *v = (*val)->bv_val;

                debug(pamh, cfg, "%s -> %s\n", a, v);

                if (!strcmp(a, "uid") && !strcmp(v, user)) {
                    debug(pamh, cfg, "MATCH !!!\n");
                    match = 1;
                }

                if (!strcmp(a, "userPassword")) {
                    debug(pamh, cfg, "SECRET FOUND !!!\n");
                    secret = strdup(v);
                }

                if (!strcmp(a, "description") && (sscanf(v, LASTLOGON, &lastlogon) == 1)) {
                    debug(pamh, cfg, "LAST LOGON FOUND: %d\n", lastlogon);
                }
            }

            ldap_value_free_len(vals);
            ldap_memfree(a);
        }

        ber_free(ber, 0);

        if (match && (secret != NULL)) {
            debug(pamh, cfg, "EVALUATING TOKEN: %s...\n", token);

	    debug(pamh, cfg, "Lastlogon = %d\n", lastlogon);
	    debug(pamh, cfg, "valid_token = %d\n", valid_token(secret, lastlogon, atoi(token)));
	    debug(pamh, cfg, "valid_token now = %d\n", valid_token(secret, time(NULL), atoi(token)));

            if ((lastlogon > 0) && valid_token(secret, lastlogon, atoi(token))) {

                int ttl = 0;
                if (cfg->ttl != NULL) {
                   ttl = atoi(cfg->ttl);
                }

                debug(pamh, cfg, "LAST TOKEN IS VALID ! (exists: %d seconds)\n", time(NULL) - lastlogon);

                if (!ttl || ((time(NULL) - lastlogon) <= ttl)) {
                    retval = PAM_SUCCESS;
                }
            }

            if ((retval != PAM_SUCCESS) && (lastlogon > 0)) {
                LDAPMod lastLogon;
                LDAPMod *mods[2];

    	        debug(pamh, cfg, "Removing LastLogon...\n");

                char *t;
                asprintf(&t, LASTLOGON, lastlogon);
                char *lastLogon_values[] = {t, NULL};
                lastLogon.mod_op     = LDAP_MOD_DELETE;
                lastLogon.mod_type   = "description";
                lastLogon.mod_values = lastLogon_values;

                mods[0] = &lastLogon;
                mods[1] = NULL;

                if ((status = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
                   pam_syslog(pamh, LOG_ERR, "Could not delete attribute: \"%s\"", ldap_err2string(status));
                }

                free(t);
            }

            if ((retval != PAM_SUCCESS) && valid_token(secret, time(NULL), atoi(token))) {
                debug(pamh, cfg, "TOKEN OK !\n");

                retval = PAM_SUCCESS;
                char *t;

    	        debug(pamh, cfg, "Updating LastLogon...\n");
                if (asprintf(&t, LASTLOGON, time(NULL)) >= 0) {

    	            debug(pamh, cfg, "Modify LastLogon...\n");

                    LDAPMod objectClass, lastLogon;
                    LDAPMod *mods[2];

                    char *lastLogon_values[] = {t, NULL};
                    lastLogon.mod_op     = LDAP_MOD_REPLACE;
                    lastLogon.mod_type   = "description";
                    lastLogon.mod_values = lastLogon_values;

                    mods[0] = &lastLogon;
                    mods[1] = NULL;

                    if ((status = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
                       pam_syslog(pamh, LOG_ERR, "Could not update attribute: \"%s\"", ldap_err2string(status));
                    }

                    free(t);
                }
            }

            if (retval != PAM_SUCCESS) {
                debug(pamh, cfg, "TOKEN NOT OK !\n", token);
            }

            ldap_memfree( dn );
        }

        free(secret);

        if (retval == PAM_SUCCESS)
            break;
    }

    // cleanup
    ldap_msgfree(result);
    ldap_unbind_ext(ld, NULL, NULL);

    return retval;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return (PAM_SUCCESS);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return (PAM_SUCCESS);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return (PAM_SUCCESS);
}

/**
 * Handles the basic parsing of a given option.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * Note that dst has to be freed by the caller in case of 0 return code
 * returns 0 if the option was not found
 * returns -1 if an error occured (duplicate option)
 * returns the position of the start of the value in the buffer otherwise
 */
int raw_parse_option(pam_handle_t *pamh, const char* buf, const char* opt_name_with_eq, char** dst)
{
    size_t opt_len = strlen(opt_name_with_eq);
    if (0 == strncmp(buf, opt_name_with_eq, opt_len)) {
        if (dst && *dst) {
            pam_syslog(pamh, LOG_ERR,
                       "Duplicated option : %s. Only first one is taken into account",
                       opt_name_with_eq);
            return -1;
        } else {
            return (int)opt_len;
        }
    }
    return 0;
}

/// calls strdup and returns whether we had a memory error
int strdup_or_die(char** dst, const char* src)
{
    *dst = strdup(src);
    return *dst ? 0 : -1;
}

/**
 * Handles the parsing of a given option.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * @arg dst is the destination buffer for the value found if any.
 * Note that dst has to be freed by the caller in case of 0 return code
 * returns 0 if the option was not found in the buffer
 * returns 1 if the option was found in buffer and parsed properly
 * returns -1 in case of error
 */
int parse_str_option(pam_handle_t *pamh, const char* buf, const char* opt_name_with_eq, char** dst)
{
    int value_pos = raw_parse_option(pamh, buf, opt_name_with_eq, dst);
    if (value_pos > 0) {
        if (strdup_or_die(dst, buf + value_pos)) {
            return -1;
        }
        return 1;
    } else if (value_pos == -1) {
        // Don't crash on duplicate, ignore 2nd value
        return 1;
    }
    return value_pos;
}

void
parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg)
{
    module_config *cfg = NULL;
    int mem_error = 0;
    int i;

    cfg = (module_config *) calloc(1, sizeof(module_config));
    if (!cfg) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        return;
    }

    cfg->debug = 0;
    cfg->ldap_uri = NULL;
    cfg->ldap_basedn = NULL;
    cfg->ldap_binddn = NULL;
    cfg->ldap_passwd = NULL;
    cfg->uid = NULL;
    cfg->ttl = NULL;

    for (i = 0; i < argc; ++i) {
        int retval = !strcmp(argv[i], "debug");
        if (retval) cfg->debug = 1;

        if (retval == 0) retval = parse_str_option(pamh, argv[i], "ldap=", &cfg->ldap_uri);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "basedn=", &cfg->ldap_basedn);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "binddn=", &cfg->ldap_binddn);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "passwd=", &cfg->ldap_passwd);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "uid=", &cfg->uid);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "ttl=", &cfg->ttl);

        if (0 == retval) {
            pam_syslog(pamh, LOG_ERR, "Invalid option: %s", argv[i]);
            free_config(cfg);
            return;
        } else if (retval < 0) {
            mem_error = retval;
            break;
        }
    }

    // in case we got a memory error in the previous code, give up immediately
    if (mem_error) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        free_config(cfg);

        return;
    }

    if (! cfg->uid) {
       debug(pamh, cfg, "Setting default value for 'uid' (=uid)");
       cfg->uid = strdup("uid");
    }

    if (! cfg->ttl) {
       debug(pamh, cfg, "Setting default value for 'ttl' (=0)");
       cfg->uid = strdup("0");
    }

    debug(pamh, cfg, "debug => %d",  cfg->debug);
    debug(pamh, cfg, "ldap_uri => %s",   cfg->ldap_uri);
    debug(pamh, cfg, "ldap_basedn => %s",   cfg->ldap_basedn);
    debug(pamh, cfg, "ldap_binddn => %s",   cfg->ldap_binddn);
    debug(pamh, cfg, "ldap_passwd => %s",   cfg->ldap_passwd);
    debug(pamh, cfg, "uid => %s",   cfg->uid);
    debug(pamh, cfg, "ttl => %s",   cfg->ttl);

    *ncfg = cfg;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *user = NULL;
    char *token = NULL;

    module_config *cfg = NULL;

    parse_config(pamh, argc, argv, &cfg);

    if (!cfg) {
        pam_syslog(pamh, LOG_ERR, "configuration invalid");
        return PAM_AUTH_ERR;
    }

    (void) pam_get_user(pamh, (const char **) &user, NULL);

    if (!user) {
        return PAM_USER_UNKNOWN;
    }

    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &token, "%s", "TOKEN: ") != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "Unable to get user input");

        return PAM_AUTH_ERR;
    }

    int result = ldap(pamh, cfg, user, token);

    free(token);

    return (result);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return (PAM_SUCCESS);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return (PAM_SUCCESS);
}
