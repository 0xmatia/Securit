#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CONFIG_LOCATION "/etc/pasten.conf" //location of the user data

int main(void)
{
    char username[1024] = "";
    char password[1024] = "";
    __ssize_t read = 0;
    size_t len = 0;
    char * line = NULL;

    //Read the file first:
    FILE *dataP = fopen(CONFIG_LOCATION, "r");

    if (!dataP)
        return 1;

    while ((read = getline(&line, &len, dataP)) != -1) {
        int del = (int)(strchr(line, ':') -line);
        memcpy(username, line, del);
        memcpy(password, &line[del+1], strlen(line) - strlen(username));
        printf("%s\n", username);
        printf("%s", password);


        memset(username, 0, 1024);
        memset(password, 0, 1024);
    }
    
    if (line)
    {
        free(line);
    }
    
    fclose(dataP); //close file only if opened
    return 0;
}