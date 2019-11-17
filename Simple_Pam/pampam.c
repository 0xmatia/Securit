#define PAM_SM_PASSWORD
#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jsmn.h"

#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data
#define CONFIG_FILE_MAX_SIZE 4096
#define MAX_CREDS_LENGTH 1024

int verifyCreds(char** username, char** password);
static int jsoneq(const char *json, jsmntok_t *tok, const char *s);

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
    int result = PAM_AUTH_ERR;
    char username[MAX_CREDS_LENGTH] = "";
    char password[MAX_CREDS_LENGTH] = "";
    jsmn_parser parser;
    jsmntok_t t[128]; /* We expect no more than 128 tokens */

    jsmn_init(&parser);
    //Read the file first:
    FILE *dataP = fopen(CONFIG_LOCATION, "r");
    char *data = 0;
    int fileSize = 0;
    if (!dataP)
        return PAM_SYSTEM_ERR;

    //Get the file size
    fseek(dataP, 0L, SEEK_END);
    fileSize = ftell(dataP);
    rewind(dataP);

    data = (char *)malloc(sizeof(char) * fileSize);
    if (data == NULL)
        return PAM_SYSTEM_ERR; //if allocation wasn't successful

    //read file
    int res = fread((void *)data, 1, fileSize, dataP);
    if (res != fileSize) //if read wasn't successful
    {
        free(data);
         return PAM_SYSTEM_ERR;
    }
    //Now that we have the data, parse it
    int r = jsmn_parse(&parser, data, strlen(data), t,
                       sizeof(t) / sizeof(t[0]));
    if (r < 0)
    {
        printf("Failed to parse JSON: %d\n", r);
         return PAM_SYSTEM_ERR;
    }

    for (int i = 1; i < r && result == PAM_AUTH_ERR; i++)
    {
        if (jsoneq(data, &t[i], "username") == 0)
        {
            memset(username, 0, sizeof(username));
            strncpy(username,
                    data + t[i + 1].start,
                    t[i + 1].end - t[i + 1].start);
        }
        else if (jsoneq(data, &t[i], "password") == 0)
        {
            memset(password, 0, sizeof(password));
            strncpy(password,
                    data + t[i + 1].start,
                    t[i + 1].end - t[i + 1].start);

            printf("Username - %s\nPassword - %s\n", *username_in, *password_in);
            //If we are here it means we have the password and the username
            if (strncmp(username, *username_in, strlen(username)) == 0)
            {
                if (strncmp(password, *password_in, strlen(password)) == 0)
                {
                    result = PAM_SUCCESS;
                }
            }
        }
    }

    free(data);
    fclose(dataP);
    printf("%d\n", result);
    return result;
}

//helper function
static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}
