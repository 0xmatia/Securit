#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>

#define PAM_SM_AUTH
#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    char* username = "";
    char* password = "Hey";

    pam_get_user(pamh, &username, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &password , NULL);
    
    if (password == NULL || username == NULL)
        return PAM_CRED_ERR;


    
    printf("%s\n", password);
    printf("%s\n", username);
    return PAM_SUCCESS;
}