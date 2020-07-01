#define PAM_SM_PASSWORD
#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data
#define CONFIG_FILE_MAX_SIZE 2048

int verifyCreds(const char **username, const char **password);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *username = NULL;
    const char *password = NULL;
    pam_get_user(pamh, &username, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);
    if (password == NULL || username == NULL)
        return PAM_CRED_ERR;

    return verifyCreds(&username, &password);
}

int verifyCreds(const char **username_in, const char **password_in)
{

    char buffer[CONFIG_FILE_MAX_SIZE] = "";
    size_t numOfCreds = 0;

    //Read the file first:
    FILE *dataP = fopen(CONFIG_LOCATION, "r");
    if (!dataP)
        return PAM_SYSTEM_ERR;

    fread(buffer, CONFIG_FILE_MAX_SIZE, 1, dataP);
    fclose(dataP); //close file only if opened

    //parse the json:
    struct json_object *parsed_json;
    parsed_json = json_tokener_parse(buffer);
    numOfCreds = json_object_array_length(parsed_json);
    FILE *logP = fopen("/home/fl3rk3n/Documents/Securit/log.txt", "w+");
    fprintf(logP, "Num of creds: %d\n", numOfCreds);

    fprintf(logP, "Entered username: %s\nEntered password: %s\n",
            (*username_in),
            (*password_in));
    for (size_t i = 0; i < numOfCreds; i++)
    {
        struct json_object *cred = json_object_array_get_idx(parsed_json, i);
        struct json_object *username_json;
        struct json_object *password_json;
        json_object_object_get_ex(cred, "username", &username_json);
        json_object_object_get_ex(cred, "password", &password_json);
        fprintf(logP, "Username: %s\nPassword: %s\n",
                json_object_get_string(username_json),
                json_object_get_string(password_json));

        if (!strcmp(json_object_get_string(username_json), *username_in))
        {
            if (!strcmp(json_object_get_string(password_json), *password_in))
            {
                fclose(logP);
                return PAM_SUCCESS;
            }
        }
    }
    fclose(logP);

    return PAM_AUTH_ERR;
}