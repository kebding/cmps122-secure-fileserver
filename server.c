/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the express written permission of the copyright holder.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <locale.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "http.h"

#define USAGE "Usage: %s port\n"
#define BYTES 2048

static int port;

time_t startTime = 0;

static void handleClient(int sock) {
    char request[BYTES];
    memset((void*) request, (int) '\0', BYTES);
    int rcvd = read(sock, request, BYTES);

    if (rcvd < 0)
        perror("socket receive");
    else if (rcvd == 0)
        perror("client disconnected without reason");
    else 
        httpRequest(sock, request);

    shutdown(sock, SHUT_RDWR);
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf(USAGE, argv[0]);
        exit(-1);
    }

    port = atoi(argv[1]);
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("socket create");
        exit(errno);
    }

    time(&startTime);
    setlocale(LC_NUMERIC, "");

    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("socket bind");
        exit(errno);
    }

    if (listen(serverSocket, 5) != 0) {
        perror("socket listen");
        exit(errno);
    }

    int clientSocket;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    printf("Totally Secure HTTP Server (TM) Listening on port %d\n", port);
    printf("Copyright (C) 1991 Totally Smashable Software Inc. All Rights Waived.\n");

    for(;;) {
        clientSocket = accept(serverSocket, (struct sockaddr*)&client_addr, &addrlen);

        switch (fork()) {
        case 0:
            close(serverSocket);
            handleClient(clientSocket);
            return 0;
        case -1:
            perror("fork");
        default:
            close(clientSocket);
            wait(NULL);
            break;
        }
    }
}
