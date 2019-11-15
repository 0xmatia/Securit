#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "jsmn.h"

#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data

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

int main(void)
{
    char username[1024] = "";
    char password[1024] = "";
    jsmn_parser parser;
    jsmntok_t t[128]; /* We expect no more than 128 tokens */

    jsmn_init(&parser);
    //Read the file first:
    FILE *dataP = fopen(CONFIG_LOCATION, "r");
    char *data = 0;
    int fileSize = 0;
    if (!dataP)
        return 1;

    //Get the file size
    fseek(dataP, 0L, SEEK_END);
    fileSize = ftell(dataP);
    rewind(dataP);

    data = (char *)malloc(sizeof(char) * fileSize);
    if (data == NULL)
        return 1; //if allocation wasn't successful

    //read file
    int res = fread((void *)data, 1, fileSize, dataP);
    if (res != fileSize) //if read wasn't successful
    {
        free(data);
        return 1;
    }
    //Now that we have the data, parse it
    int r = jsmn_parse(&parser, data, strlen(data), t,
                       sizeof(t) / sizeof(t[0]));
    if (r < 0)
    {
        printf("Failed to parse JSON: %d\n", r);
        return 1;
    }

    for (int i = 1; i < r; i++)
    {
        if (jsoneq(data, &t[i], "username") == 0)
        {
            strncpy(username,
                    data + t[i + 1].start,
                    t[i + 1].end - t[i + 1].start);
        }
        else if (jsoneq(data, &t[i], "password") == 0)
        {
            strncpy(password,
                    data + t[i + 1].start,
                    t[i + 1].end - t[i + 1].start);

            //If we are here it means we have the password and the username
            printf("%s\n", username);
            printf("%s\n", password);
        }
    }
    free(data);
    fclose(dataP); //close file only if opened
    return 0;
}