#define PAM_SM_PASSWORD
#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data
#define CONFIG_FILE_MAX_SIZE 4096
#define MAX_CREDS_LENGTH 1024

int verifyCreds(char** username, char** password);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char* username = NULL;
    const char* password = NULL;

    pam_get_user(pamh, &username, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &password , NULL);

    if (password == NULL || username == NULL)
        return PAM_CRED_ERR;

    return verifyCreds(&username, &password);
}

int verifyCreds(char** username_in, char** password_in)
{
    char username[MAX_CREDS_LENGTH] = "";
    char password[MAX_CREDS_LENGTH] = "";
    
    //Read the file first:
    FILE *dataP = fopen(CONFIG_LOCATION, "r");
    __ssize_t read = 0;
    size_t len = 0;
    char* line = NULL;

    if (!dataP)
        return PAM_SYSTEM_ERR;
    while ((read = getline(&line, &len, dataP)) != -1) {
        int del = (int)(strchr(line, ':') -line);
        memcpy(username, line, del);
        memcpy(password, &line[del+1], strlen(line) - strlen(username));
        password[strlen(password)-1] = 0; //remove enter

        //check:
        if (!strcmp(username, *username_in))
        {
            if (!strcmp(password, *password_in))
            {
                //printf("%s\n", *username_in);
                //printf("%s\n", *password_in);
                return PAM_SUCCESS;
            }
            
        }
        memset(username, 0, MAX_CREDS_LENGTH);
        memset(password, 0, MAX_CREDS_LENGTH);
    }
    
    if (line)
    {
        free(line);
    }
    fclose(dataP);
    return PAM_AUTH_ERR;
}