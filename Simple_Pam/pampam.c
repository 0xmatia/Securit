#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>

#define PAM_SM_AUTH
#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data
#define CONFIG_FILE_MAX_SIZE 4096

int verifyCreds(char** username, char** password);

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
    return verifyCreds(&username, &password);
}

int verifyCreds(char** username, char** password)
{
    //Read the file first:
    FILE* dataP = fopen(CONFIG_LOCATION, 'r');
    char data[CONFIG_FILE_MAX_SIZE] = 0;
    int fileSize = 0;
    if(!dataP)
        return PAM_CRED_ERR;
    //Get the file size


    fclose(dataP); //close file only if opened 
    return PAM_SUCCESS;
}