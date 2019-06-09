/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the express written permission of the copyright holder.
 */

/** README
 * This file expects to put in the same directory as a file called "users" that contains a list of 
 * username:password entries, each on a separate line.
 * It generates a file "cookies" to store the valid cookies in.
 *
 * Expected command formats:
 * LOGIN: curl -X POST "http://localhost:<port>/login?username=<username>&password=<password>" -c cookie_file
 * POST: curl -X POST --data-binary @file "http://localhost:<port>/path/to/file/ --cookie cookie_file
    note: the server automatically handles making sure your path is a subdirectory of your
    personal directory, so including your username at the beginning of the filepath is optional
    and any "../" will be deleted from the path without any indication to the client
 * GET: curl "http://localhost:<port>/path/to/file --cookie cookie_file
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define BYTES 2048
#define PORT 80
#define MAX_FNAME_LEN 256   // since UNIX has a max filename length of 255
#define MAX_PATH_LEN 4096   // since UNIX has a max path length of 4096
#define MAX_CRED_LEN 32 // set maximum username and password length to 32
#define MAX_COOKIE_LEN 16
#define COOKIE_NAME "blarg"
#define USERS_FILE "users"
#define COOKIES_FILE "cookies"

unsigned long min(unsigned long a, unsigned long b) {
    return a < b ? a : b;
}

void error505(int sock, char* buffer, char version[]) {
    memset(&buffer, 0, sizeof(buffer));
    strncpy(buffer, version, 9);
    strcat(buffer, " 505 Internal Server Error\r\n");
    strcat(buffer, "Connection: Closed\r\n\r\n");
    strcat(buffer, "505 Internal Server Error\r\n");
    write(sock, buffer, strlen(buffer)+1);
    return;
}
void error400(int sock, char* buffer, char version[]) {
    strcpy(buffer, version);
    strcat(buffer, " 400 Bad Request\r\n");
    strcat(buffer, "Connection: Closed\r\n\r\n");
    strcat(buffer, "400 Bad Request\r\n");
    write(sock, buffer, strlen(buffer)+1);
    return;
}
void error401(int sock, char* buffer, char version[]) {
    strcpy(buffer, version);
    strcat(buffer, " 401 Unauthorized\r\n");
    strcat(buffer, "Connection: Closed\r\n\r\n");
    strcat(buffer, "401 Unauthorized\r\n");
    write(sock, buffer, strlen(buffer)+1);
    return;
}
void error404(int sock, char* buffer, char version[]) {
    strcpy((char*)buffer, version);
    strcat((char*)buffer, " 404 Not Found\r\n");
    strcat((char*)buffer, "Connection: Closed\r\n\r\n");
    strcat((char*)buffer, "404 Not Found\r\n");
    write(sock, buffer, strlen((char*)buffer));
}
static void login(int sock, char *request) {
    // check for malformed requests that could segfault the server
    if(strstr(request, "?") == NULL || strstr(request, "&") == NULL) {
        char buffer[BYTES];
        error400(sock, buffer, "HTTP/1.1");
        return;
    }
    char *target;
    char *end;
    int length;
    char buffer[BYTES]; 
    char username[MAX_CRED_LEN], pass[MAX_CRED_LEN], user[2*MAX_CRED_LEN];

    memset(&buffer, 0, sizeof(buffer));
    memset(&username, 0, sizeof(username));
    memset(&pass, 0, sizeof(pass));
    memset(&user, 0, sizeof(user));

    // get the HTTP version
    char version[9];
    strncpy(version, strstr(request, "HTTP/1."), 8);
    // get the username
    target = strstr(request, "?") + 10; // skips "username="
    end = strstr(request, "&");
    length = min(end - target, MAX_CRED_LEN);
    strncpy(username, target, length);
    // get the password
    target = end + 10;  // skips "password="
    end = strstr(target, " ");
    if(end == NULL) end = strstr(target, "\"");
    if(end == NULL) end = strstr(target, "\r\n");
    if(end == NULL) return; // must be malformed
    length = min(end - target, MAX_CRED_LEN);
    strncpy(pass, target, length);
    // combine the two
    strcpy(user, username);
    strcat(user, ":");
    strcat(user, pass);

    FILE *usersFile;
    if((usersFile = fopen(USERS_FILE, "r")) == NULL) {
        error505(sock, buffer, version);
        return;
    }
    // check if the username + password match a pair in the users file
    while(fgets(buffer, 2*MAX_CRED_LEN + 1, usersFile) != NULL) {
        if(strcmp(user, buffer) == 0) {
            // generate a session cookie
            srand(time(NULL) * getpid());   // hopefully intractable to forge?
            int cookieVal = rand();
            char cookieValStr[MAX_COOKIE_LEN];
            memset(&cookieValStr, 0, sizeof(cookieValStr));
            sprintf(cookieValStr, "%d", cookieVal);
            FILE *cookieFile;
            if((cookieFile = fopen(COOKIES_FILE, "a")) == NULL) {
                error505(sock, buffer, version);
                return;
            }
            fwrite(username, 1, strlen(username), cookieFile);
            fwrite(":", 1, 1, cookieFile);
            fwrite(cookieValStr, 1, strlen(cookieValStr), cookieFile);
            fwrite("\r\n", 1, strlen("\r\n"), cookieFile);
            fclose(cookieFile);
            // send the cookie
            memset(&buffer, 0, sizeof(buffer));
            strcpy(buffer, version);
            strcat(buffer, " 200 OK\r\n");
            strcat(buffer, "Set-Cookie: ");
            strcat(buffer, COOKIE_NAME);
            strcat(buffer, "=");
            strcat(buffer, cookieValStr);
            strcat(buffer, "; HttpOnly;\r\n");
            strcat(buffer, "Connection: Closed\r\n");
            strcat(buffer, "\r\nSuccessfully logged in!\r\n");
            write(sock, buffer, strlen(buffer)+1);
            return;
        }
    }
    // if it reaches this point, the login didn't match. deny access.
    fclose(usersFile);
    memset(&buffer, 0, sizeof(buffer));
    error401(sock, buffer, version);
    return;
}

void verifyCookie(char* request, char* username) {
    char* startOfCookie;
    if((startOfCookie = strstr(request, COOKIE_NAME)) == NULL) {
        return; // no cookie sent -> unauthorized
    }
    startOfCookie += strlen(COOKIE_NAME) + 1;  // the + 1 is for the space character
    char* endOfCookie = strstr(startOfCookie, "\r\n");
    if(endOfCookie == NULL) return; // caller will handle sending error to client
    int cookieLen = endOfCookie - startOfCookie;
    char cookie[MAX_COOKIE_LEN];
    strncpy(cookie, startOfCookie, min(cookieLen, sizeof(cookie)));
    // iterate through cookies file to search for matches
    FILE *cookieFile;
    if((cookieFile = fopen(COOKIES_FILE, "r")) == NULL) {
        return; // caller will handle sending error to client
    }
    char buffer[MAX_CRED_LEN + MAX_COOKIE_LEN], savedCookie[MAX_COOKIE_LEN];
    memset(&buffer, 0, sizeof(buffer));
    while(fgets(buffer, sizeof(buffer), cookieFile) != NULL) {
        if(strstr(buffer, ":") == NULL) return; // caller will handle sending error to client
        strncpy(savedCookie, strstr(buffer, ":") + 1,
                min(cookieLen, sizeof(savedCookie)));
        if(strncmp(savedCookie, cookie, strlen(cookie)) == 0) {
            int usernameLength = min(MAX_CRED_LEN, 
                    strstr(buffer, ":") - buffer);
            strncpy(username, buffer, usernameLength);
            fclose(cookieFile);
            return;
        }
    }
    // if it got here no match was found, so leave username empty
    fclose(cookieFile);
    return;
}

static void httpGet(int sock, char *request) {
    int fd;
    int bytes;
    void *buffer[BYTES];
    char version[9];
    char server_dir[MAX_PATH_LEN];
    memset(&buffer, 0, sizeof(buffer));
    memset(&server_dir, 0, sizeof(server_dir));
    memset(&version, 0, sizeof(version));
    
    // check for malformed requests that could segfault the server
    if(strstr(request, "HTTP/1.") == NULL || 
            strstr(request, " ") == NULL || 
            strstr(request, "/") == NULL) {
        error400(sock, (char*)buffer, "HTTP/1.1");
        return;
    }
    
    // get the HTTP version
    strncpy(version, strstr(request, "HTTP/1."), 8);

    // get the current working directory
    if(getcwd(server_dir, sizeof(server_dir)) == NULL) {
        error505(sock, (char*)buffer, version);
        return;
    }

    char username[MAX_CRED_LEN];
    memset(&username, 0, sizeof(username));
    verifyCookie(request, username);
    if(strcmp(username, "\0") == 0) {
        error401(sock, (char*)buffer, version);
        return;
    }

    // move the request pointer past the "GET " for future ease
    request += 4;

    // put the filepath in a string and append the user's directory to the path
    char filepath[MAX_PATH_LEN];
    memset(&filepath, 0, sizeof(filepath));
    strcpy(filepath, server_dir);
    strcat(filepath, "/webdir/");
    strcat(filepath, username);
    // if user provided <username>/<filename>, trim <username>
    if(!strncmp(username, request + 1, strlen(username))) {
        request += (strlen(username) + 1);
    }
    // append filename to filepath to complete the filepath
    strncat(filepath, request, min(
                strstr(request, " ") - strstr(request, "/"), 
                MAX_FNAME_LEN
                ) 
            );
    // scrub any "../" from the input file
    char *target;
    while((target = strstr(filepath, "../")) != NULL) {
        memmove(target, target + 3, strlen(target + 3) + 3);
    }

    if ((fd = open(filepath, O_RDONLY)) != -1) {
        strcpy((char*)buffer, version);
        strcat((char*)buffer, " 200 OK\r\n");
        strcat((char*)buffer, "Connection: Closed\r\n\r\n");
        write(sock, (char*)buffer, strlen((char*)buffer));
        memset(&buffer, 0, sizeof(buffer));
        while((bytes = read(fd, buffer, BYTES)) > 0) {
            write(sock, buffer, bytes);
        }
    }
    else {
        error404(sock, (char*)buffer, version);
    }
}


static void httpPost(int sock, char *request) {
    // if it's a file upload, proceed with file upload
    FILE *fp;
    void *buffer[BYTES];
    char *target;
    char server_dir[MAX_PATH_LEN];
    memset(&buffer, 0, sizeof(buffer));
    memset(&server_dir, 0, sizeof(server_dir));

    // check for malformed requests that could segfault the server
    if(strstr(request, "HTTP/1.") == NULL || 
            strstr(request, " ") == NULL || 
            strstr(request, "/") == NULL) {
        error400(sock, (char*)buffer, "HTTP/1.1");
        return;
    }
    
    // determine if it's a login request
    if(strncmp(request + 5, "/login?", 7) == 0) {   // request+5 passes "POST "
        login(sock, request);
        return;
    }

    // get the HTTP version
    char version[9];
    strncpy(version, strstr(request, "HTTP/1."), 8);

    // get the current working directory
    if(getcwd(server_dir, sizeof(server_dir)) == NULL) {
        error505(sock, (char*)buffer, version);
        return;
    }

    char username[MAX_CRED_LEN];
    memset(&username, 0, sizeof(username));
    verifyCookie(request, username);
    if(strcmp(username, "\0") == 0) {
        error401(sock, (char*)buffer, version);
        return;
    }
    // move the request pointer past the "POST " for future ease
    request += 5;

    // get the absolute path of the file
    char filepath[MAX_PATH_LEN];
    memset(&filepath, 0, sizeof(filepath));
    strcpy(filepath, server_dir);
    strcat(filepath, "/webdir/");
    strcat(filepath, username);

    // if user provided <username>/<filename>, trim <username>
    if(!strncmp(username, request + 1, strlen(username))) {
        request += (strlen(username) + 1);
    }
    /* now add the filename to filepath.
     * do not copy beyond the the filepath's array, though, hence the min()
     */
    strncat(filepath, request, min(
                strstr(request, " ") - strstr(request, "/"),
                MAX_FNAME_LEN
                ) 
            );
    // scrub any "../" from the input file
    while((target = strstr(filepath, "../")) != NULL) {
        memmove(target, target + 3, strlen(target + 3) + 3);
    }

    // make sure the directory exists and create subdirectories specified
    char subdir[MAX_PATH_LEN];
    memset(subdir, 0, sizeof(subdir));
    strcpy(subdir, "webdir");
    if((mkdir(subdir, S_IRUSR | S_IWUSR) < 0) && (errno != EEXIST)) {
        error505(sock, (char*)buffer, version);
        return;
    }
    strcat(subdir, "/");
    strncat(subdir, username, MAX_CRED_LEN);
    if((mkdir(subdir, S_IRUSR | S_IWUSR) < 0) && (errno != EEXIST)) {
        error505(sock, (char*)buffer, version);
        return;
    }
    strcat(subdir, "/");
    int subdir_len = 0;
    // check if there are more '/' characters before the next ' ' character
    while(strstr(request + subdir_len + 1, "/") != NULL && 
            strstr(request + subdir_len + 1, " ") != NULL &&
            strstr(request + subdir_len + 1, " ") - strstr(request + subdir_len + 1, "/") > 0) {
        strncat(subdir, request + subdir_len + 1, min(
                    strstr(request + subdir_len + 1, "/") - strstr(request + subdir_len, "/"),
                    // -8 in next line for "webdir/" and "/" after username
                    MAX_PATH_LEN - subdir_len - strlen(username) - 8
                    )
               );
        if((mkdir(subdir, S_IRUSR | S_IWUSR) < 0) && (errno != EEXIST)) {
            error505(sock, (char*)buffer, version);
            return;
        }
        subdir_len = strlen(subdir) - strlen(username) - 8; // -8 for "webdir/" and "/" after username
    }

    // see if we can create the file. if not, error out.
    if((fp = fopen(filepath, "w")) == NULL) {
        error505(sock, (char*)buffer, version);
        return;
    }
    // figure out if it expects a 100 Continue
    target = strstr(request, "Expect: 100");
    if(target != NULL) {
        // send 100 continue
        strcpy((char*)buffer, version);
        strcat((char*)buffer, " 100 Continue\r\n");
        write(sock, buffer, strlen((char*)buffer)+1);
        memset(&buffer, 0, sizeof(buffer));
        sleep(2.0);
        // get the content length
        int length;
        target = strstr(request, "Content-Length:");
        sscanf(target, "%*s %d\r\n", &length);
        // get the data and write the content to the file
        int bytesRead, bytesWritten;
        while(bytesWritten < length) {
            bytesRead = read(sock, buffer, BYTES);
            bytesWritten += fwrite(buffer, 1, bytesRead, fp);
        }
    }
    else {  // doesn't expect 100 Continue so the data is all here
        // get the content length
        int length;
        target = strstr(request, "Content-Length:");
        sscanf(target, "%*s %d\r\n", &length);
        // get a pointer to the actual content
        target = strstr(request, "\r\n\r\n") + 4;   // +4 moves past \r\n\r\n
        fwrite(target, 1, length, fp);
    }
    fclose(fp);
    // send the HTTP response
    memset(&buffer, 0, sizeof(buffer));
    strcpy((char*)buffer, version);
    strcat((char*)buffer, " 200 OK\r\n");
    strcat((char*)buffer, "Connection: Closed\r\n\r\n");
    strcat((char*)buffer, "Uploaded successfully!\r\n");
    write(sock, buffer, strlen((char*)buffer));
}

/* NOTE: request contains the first server.c:BYTES bytes of the request */
void httpRequest(int sock, char *request) { 
    char method[16], version[9];
    memset(&method, 0, sizeof(method));
    memset(&version, 0, sizeof(version));
    if(strstr(request, "HTTP/1.") == NULL) {
        char buffer[BYTES];
        memset(buffer, 0, sizeof(buffer));
        error400(sock, buffer, "HTTP/1.1");
        return;
    }
    strncpy(version, strstr(request, "HTTP/1."), 8);

    if(strcmp(version, "HTTP/1.0") && strcmp(version, "HTTP/1.1")) {
        char message[] = "HTTP/1.1 500 HTTP Version Not Supported";
        write(sock, message, sizeof(message));
        return;
    }
    // process the request
    if(strstr(request, " ") == NULL) {
        char buffer[BYTES];
        memset(buffer, 0, sizeof(buffer));
        error400(sock, buffer, "HTTP/1.1");
        return;
    }
    strncpy(method, request, strstr(request, " ") - request);
    if(strcmp(method, "GET") == 0) {
        httpGet(sock, request);
    }
    if(strcmp(method, "POST") == 0) {
        // pass the whole request for more parsing
        httpPost(sock, request);
    }
}
