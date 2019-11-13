#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>

#define PAM_SM_AUTH

int pam_sm_authenticate(pam_handle_t *pamh, int flags)
{
    printf("Works?\n");
    return PAM_SUCCESS;
}