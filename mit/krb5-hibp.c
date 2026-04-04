#include <krb5/pwqual_plugin.h>
#include <profile.h>
#include <string.h>
#include <hibp.h>

static krb5_error_code pwqual_hibp_check(krb5_context context, 
                                  krb5_pwqual_moddata data,
                                  const char *password, 
                                  const char *policy_name,
                                  krb5_principal princ,
                                  const char **languages) 
{
    krb5_error_code result = 0;
    char *proxy = NULL;
    char *api = NULL;
    char *threshold_str = NULL;
    char *auditonly_str = NULL;
    long long threshold = 0;
    int auditonly = 0;
    struct _profile_t *prof;
    char *princ_name = NULL;
    
    krb5_get_profile(context, &prof);

    krb5_unparse_name(context, princ, &princ_name);
    if (!princ_name) {
        result = KADM5_PASS_Q_GENERIC;
        krb5_set_error_message(context, result, "principal name unknown.");
        goto cleanup;
    }

    profile_get_string(prof, "plugins", "pwqual", "hibp_proxy", NULL, &proxy);
    profile_get_string(prof, "plugins", "pwqual", "hibp_api", NULL, &api);
    profile_get_string(prof, "plugins", "pwqual", "hibp_threshold", NULL, &threshold_str);
    profile_get_string(prof, "plugins", "pwqual", "hibp_auditonly", NULL, &auditonly_str);

    if (threshold_str) {
        threshold = atoll(threshold_str);
    }

    if (threshold < 0) {
        result = KADM5_PASS_Q_GENERIC;
        krb5_set_error_message(context, result, "configuration error: Invalid hibp_threshold value %s", threshold_str);
        goto cleanup;
    }

    if (auditonly_str) {
        if (!strcasecmp(auditonly_str, "true")) {
            auditonly = 1;
        } else if (strcasecmp(auditonly_str, "false")) {
            result = KADM5_PASS_Q_GENERIC;
            krb5_set_error_message(context, result, "configuration error: hibp_auditonly can only be true or false.");
            goto cleanup;
        }
    }

    if (password) {

        long long count = is_pwned_password((char *)password, proxy, api);

        if (count < 0) {
            result = KADM5_PASS_Q_GENERIC;
            krb5_set_error_message(context, result, "error with libhibp. Maybe check values of hibp_api and hibp_proxy? in KDC configuration?");
            goto cleanup;
        }

        if (count > threshold) {
            if (!auditonly) {
                result = KADM5_PASS_Q_GENERIC;
                krb5_set_error_message(context, result, "new password is known to be compromised in %lld breaches.", count);
            } else {
                com_err("", 0, "krb5-hibp.so: new password for %s is known to be compromised in %lld breaches - NOT rejected (hibp_auditonly is true).", princ_name, count);
            }
        }
    }

cleanup:

    if (proxy) krb5_free_string(context, proxy);
    if (api)   krb5_free_string(context, api);
    if (threshold_str)  krb5_free_string(context, threshold_str);
    if (auditonly_str)  krb5_free_string(context, auditonly_str);
    if (princ_name) free(princ_name);

    return(result);
}

krb5_error_code pwqual_hibp_initvt(krb5_context context, int maj_ver,
                                   int min_ver, krb5_plugin_vtable vtable) 
{

    struct krb5_pwqual_vtable_st *vt;

    if (maj_ver != 1)
        return(KRB5_PLUGIN_VER_NOTSUPP);

    vt = (struct krb5_pwqual_vtable_st *)vtable;
    memset(vt, 0, sizeof(vt));
    vt->name = "hibp";
    vt->check = pwqual_hibp_check;
    return(0);
}
