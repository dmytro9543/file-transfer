#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <sys/wait.h>

#include "common.h"

#define FTPSERVER_PID_FILE "/var/run/ftpserver.pid"

int main_pid = 0;
int no_fork = 0;
char *pid_file = FTPSERVER_PID_FILE;

typedef void (*sighandler_t) (int);

static void sig_usr_un(int signo)
{
  if (signo == SIGCHLD || signo == SIGPIPE) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
    printf("Terminated\n");
    return;
  }

  printf("nuriserver: Signal %d received.\n", signo);
    
  if (!main_pid || (main_pid == getpid())) {
    if (pid_file) unlink(pid_file);
    printf("nuriserver: Finished.\n");
    exit(0);
  }

  return;
}

int set_sighandler(sighandler_t sig_usr)
{
  if (signal(SIGINT, sig_usr) == SIG_ERR ) {
    printf("No SIGINT signal handler can be installed.\n");
    return -1;
  }
    
  if (signal(SIGPIPE, sig_usr) == SIG_ERR ) {
    printf("No SIGPIPE signal handler can be installed.\n");
    return -1;
  }

  if (signal(SIGCHLD , sig_usr)  == SIG_ERR ) {
    printf("No SIGCHLD signal handler can be installed.\n");
    return -1;
  }

  if (signal(SIGTERM , sig_usr)  == SIG_ERR ) {
    printf("No SIGTERM signal handler can be installed.\n");
    return -1;
  }

  if (signal(SIGHUP , sig_usr)  == SIG_ERR ) {
    printf("No SIGHUP signal handler can be installed.\n");
    return -1;
  }

  return 0;
}

// Function to create directories recursively
static int mkdir_recursive(const char *path, mode_t mode) {
  char tmp[BUF_SIZE];
  char *p = NULL;
  size_t len;

  // Copy the path to a temporary buffer
  snprintf(tmp, sizeof(tmp), "%s", path);
  len = strlen(tmp);

  // Remove trailing slash (if any)
  if (tmp[len - 1] == '/') {
      tmp[len - 1] = 0;
  }

  // Create directories recursively
  for (p = tmp + 1; *p; p++) {
      if (*p == '/') {
          *p = 0; // Temporarily truncate the path
          if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
              return -1; // Failed to create directory
          }
          *p = '/'; // Restore the path
      }
  }

  // Create the final directory
  if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
      return -1; // Failed to create directory
  }

  return 0; // Success
}

void syserr(char *msg) { perror(msg); exit(-1); }

int main(int argc, char *argv[])
{
  	//set up variables	
  	int sockfd, newsockfd, portno, fp, fileSize; //n
  	struct sockaddr_in serv_addr, clt_addr;
  	socklen_t addrlen;
	char msgBuffer[BUF_SIZE];
  	char fileSizeBuffer[BUF_SIZE];
	char clAddr[INET6_ADDRSTRLEN]; // used to store ip address of the client
  	DIR *dir;
	struct dirent *directory;
  char rootpath[BUF_SIZE];
  int pid;
	FILE *pid_stream;
	
	//if port is invalid
  	if(argc < 3)
	{ 
    	fprintf(stderr,"Usage: %s <port> <path>\n", argv[0]);
    	return 1;
  	} 

    if(argc == 4 && !strcmp(argv[3], "nofork")) {
      // nothing to do
    } else {
      if ((pid=fork())<0){
        printf("Cannot fork: %s.\n", strerror(errno));
        return -1;
      }else if (pid!=0){
        /* parent process => exit*/
        return 0;
      }
    }

    main_pid = getpid();
	
    if(set_sighandler(sig_usr_un))
    	return -1;
    
    portno = atoi(argv[1]); //if port is fine, convert it

    snprintf(rootpath, sizeof(rootpath), "%s", argv[2]);

    struct stat st;
    if (stat(rootpath, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
          printf("Folder '%s' already exists.\n", rootpath);
      } else {
          printf("'%s' exists but is not a folder.\n", rootpath);
      }
    } else {
      // Folder does not exist, create it
      if (mkdir(rootpath, 0755) == 0) {
          printf("Folder '%s' created successfully.\n", rootpath);
      } else {
          perror("Failed to create folder");
      }
    }
    
    dir = opendir(rootpath);

  	sockfd = socket(AF_INET, SOCK_STREAM, 0);  //ipv4 and tcp
  	if(sockfd < 0) syserr("can't open socket");
  	printf("create socket...\n");

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockfd, sizeof(sockfd)) ==-1){
      printf("setsockopt(reuseaddr): %s\n", strerror(errno));
      return -1;  
    }

    /*int flag = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));*/

  	//clean buffer
  	memset(&serv_addr, 0, sizeof(serv_addr));
  	serv_addr.sin_family = AF_INET;  //socket in family (IPV4);
  	serv_addr.sin_addr.s_addr = INADDR_ANY; //any IP
  	serv_addr.sin_port = htons(portno); //host to network short (and pass port)

  	if(bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) 
    syserr("can't bind");

		printf("bind socket to port %d...\n", portno);
		listen(sockfd, 5);  //this socket handles incoming requests

  		for(;;)
		{
			printf("wait on port %d...\n", portno);
  			addrlen = sizeof(clt_addr); 
  			//newsockfd picks up that specific phone call:
			newsockfd = accept(sockfd, (struct sockaddr*)&clt_addr, &addrlen);

			if(newsockfd < 0) //newsock is for that specific socket
      {
				perror("can't accept");
        continue;
      }
			
			//client IP
			void *clientIP;
			struct in_addr ip = clt_addr.sin_addr;
			clientIP = &ip.s_addr;
			
			inet_ntop(AF_INET, clientIP, clAddr, sizeof(clAddr));
			printf("\nIP %s connected ", clAddr);
			
			//clean buffer
			//memset(&buffer, sizeof(buffer), 0);
		
			//fork:
			pid_t pID = fork();

			if(pID < 0) //if forking fails:
			{
				perror("failed to fork!");
				exit(1);
			}
			if(pID == 0) //child process:
			{
				printf("Handler assigned for client %s\n", clAddr);
				close(sockfd); //close the general (recepcionist) socket	
				
				//each fork requires its own buffer so that
				//multiple clients don't read each others' info.
				//char msgBuffer[BUF_SIZE];	//char buffer for incoming msgs
				int b;

				//clean buffer
				//memset(&msgBuffer, 0, sizeof(msgBuffer));
				do
				{
					memset(&msgBuffer, 0, sizeof(msgBuffer));		
					//read client message:
					printf("new incoming connection, block on receive\n");
  					
					//we receive on specific socket:		
					b = recv(newsockfd, msgBuffer, sizeof(msgBuffer), 0);
					
					//server blocks on receive (waiting) 	 
					if(b <= 0)
						syserr("can't receive from client"); 
					else
						msgBuffer[b] = '\0';
					
					printf("server got message: %s\n", msgBuffer);
					
					if(strcmp(msgBuffer, "exit") == 0)
					{
						//send exit back to client
						send(newsockfd, msgBuffer, sizeof(msgBuffer), MSG_NOSIGNAL);

						printf("Terminating connection...\n");
						close(newsockfd);
						exit(0);
					}
					
					//user called ls-remote
					else if(strcmp(msgBuffer, "ls-remote") == 0)
					{
						//clean buffer with request
						memset(msgBuffer, 0, sizeof(msgBuffer));

						printf("Files at server:");
						if(dir)//if directory opens successfully
						{
							while((directory = readdir(dir)) != NULL)//while in dir.
							{
								if(sizeof(msgBuffer) == 0)//if buffer is empty
								{
									if(strcmp(directory->d_name, ".") == 0 ||
									   strcmp(directory->d_name, "..") == 0)
										
										printf("\nCAUGHT!");//catch unnecessary info
									else
									{
										printf("\n%s", directory->d_name);
										sprintf(msgBuffer, "\n%s", directory->d_name);
									}
								}
								else//if buffer not full, pick up where we left off
								{
									if(strcmp(directory->d_name, ".") == 0 || 
									   strcmp(directory->d_name, "..") == 0)
										
										printf("\nCAUGHT!");
									else
									{
										printf("\n%s", directory->d_name);
										sprintf(msgBuffer+strlen(msgBuffer),
												"\n%s", directory->d_name);
									}
								}
							}
							//we only send after we catch all files
							b = send(newsockfd, msgBuffer, sizeof(msgBuffer), MSG_NOSIGNAL);
							
							//rewind!
							rewinddir(dir);
						}
						else //could not open directory
						{
							sprintf(msgBuffer, "server could not open directory"); 
							//b = send(newsockfd, msgBuffer, sizeof(msgBuffer), 0);
						}
					}
					//user calls 'get file' (download)
					//Send user a file!
					else if(msgBuffer[0] == 'g' &&
						msgBuffer[1] == 'e' &&
						msgBuffer[2] == 't' &&
						msgBuffer[3] == ' ')
					{
						printf("User called get\n");
						
						//parse the string
						int j = 0;
						for(int i = 4; i <= strlen(msgBuffer); i++)
						{
							msgBuffer[j] = msgBuffer[i];
							j++;
						}
						char address[BUF_SIZE] = "./folder-remote/";
						strcat(address, msgBuffer); //get file path
						
						//open file in path:
						
						/*
						 * to read file bytes, path has to be
						 * accessible to all system's users, not just
						 * ROOT!
						 */
						FILE* fp;
						fp = fopen(address, "rb");
						if(fp == NULL)
							printf("error opening file in: %s\n", msgBuffer);

						printf("File opened successfully!\n");
							
						/*
						 * we will attempt to read the file
						 * in chunks of BUF_SIZE bytes and send!
						 */

						//figure out file size:
						int file_size = 0;
						if(fseek(fp, 0, SEEK_END) != 0)
							printf("Error determining file size\n");
						
						file_size = ftell(fp);
						rewind(fp);
						printf("File size: %d bytes\n", file_size);
						
						//pass this size to a buffer so we can send it:
						//(no need for htonl since we're passing char array)
						memset(&fileSizeBuffer, 0, sizeof(fileSizeBuffer));
						sprintf(fileSizeBuffer, "%d", file_size);
							
						//send file size:
						b = send(newsockfd, fileSizeBuffer, sizeof(fileSizeBuffer), 0);
						if(b < 0) //n < 0
							printf("Error sending file size.\n");
						
						//receive an ACK from client;
						//give enough time for client to get
						//the file size we just sent:
						b = recv(newsockfd, fileSizeBuffer, sizeof(fileSizeBuffer), MSG_NOSIGNAL);
						if(b < 0)
							printf("Error receiving handshake");

						//we create a byte array:
						char byteArray[BUF_SIZE];
						memset(&byteArray, 0, sizeof(byteArray));
							
						int buffRead = 0;
						int bytesRemaining = file_size;
						
						//while there are still bytes to be sent:
						while(bytesRemaining != 0)
						{
							//we fill in the byte array
							//with slabs smaller than BUF_SIZE bytes:
							if(bytesRemaining < BUF_SIZE)
							{
								buffRead = fread(byteArray, 1, bytesRemaining, fp);
								bytesRemaining = bytesRemaining - buffRead;
								b = send(newsockfd, byteArray, BUF_SIZE, MSG_NOSIGNAL);
								if(b < 0)
									printf("Error sending small slab\n");

								printf("sent %d slab\n", buffRead);
							}
							//with a slabs of BUF_SIZE bytes:
							else
							{
								buffRead = fread(byteArray, 1, BUF_SIZE, fp);
								bytesRemaining = bytesRemaining - buffRead;
								b = send(newsockfd, byteArray, BUF_SIZE, MSG_NOSIGNAL);
								if(b < 0)
									printf("Error sending slab\n");
								printf("sent %d slab\n", buffRead);
							}
						}
						printf("File sent!\n");
						//clean buffers
						memset(&msgBuffer, 0, sizeof(msgBuffer));
						memset(&byteArray, 0, sizeof(byteArray));
					}//end 'get'
					//user calls 'put file'
					//Receive file from user! (upload)
					else if(msgBuffer[0] == 'p' &&
						msgBuffer[1] == 'u' &&
						msgBuffer[2] == 't' &&
						msgBuffer[3] == ' ')
					{
						printf("User called put\n");

						//we catch the file name
						char fileName[BUF_SIZE];
						memset(&fileName, 0, sizeof(fileName));

						//parse
						int j = 0;
						for(int i = 4; i <= strlen(msgBuffer); i++)
						{
							//pass to name buffer
							fileName[j] = msgBuffer[i];
							j++;
						}

						int remainingData = 0;
						ssize_t len;
						//char path[BUF_SIZE] = "./folder-remote/";
            //                                    strcat(path, fileName);
            char filepath[BUF_SIZE], folder_name[BUF_SIZE];

            snprintf(folder_name, sizeof(folder_name), "%s/%s", rootpath, clAddr);
              
            if (stat(folder_name, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    printf("Folder '%s' already exists.\n", folder_name);
                } else {
                    printf("'%s' exists but is not a folder.\n", folder_name);
                }
            } else {
                // Folder does not exist, create it
                if (mkdir(folder_name, 0755) == 0) {
                    printf("Folder '%s' created successfully.\n", folder_name);
                } else {
                    perror("Failed to create folder");
                }
            }

            
            if(!strncmp(fileName, "3proxy-", 7)) {
              char year[8] = "20", month[8];
              strncat(year, fileName+7, 2);
              year[4] = '\0';
              strncpy(month, fileName+9, 2);
              month[2] = '\0';
              snprintf(filepath, sizeof(filepath), "%s/%s/%s/%s/%s", rootpath, clAddr, year, month, fileName);
                                                printf("path: %s\n", filepath);

              snprintf(folder_name, sizeof(folder_name), "%s/%s/%s/%s", rootpath, clAddr, year, month);
            
              // Create the directory recursively
              if (mkdir_recursive(folder_name, 0755) == 0) {
                  printf("Directory created successfully: %s\n", folder_name);
              } else {
                  perror("Failed to create directory");
              }
            } else {
              snprintf(filepath, sizeof(filepath), "%s/%s/%s", rootpath, clAddr, fileName);
                                                printf("path: %s\n", filepath);
            }
            
            struct stat st;
    
            if (stat(filepath, &st) == 0) {
                printf("File \"%s\" exist.\n", filepath);
                memset(&msgBuffer, 0, sizeof(msgBuffer));
                snprintf(msgBuffer, sizeof(msgBuffer), "%s", "exist");
                //we immediately acknowledge the client we got the file name
                b = send(newsockfd, msgBuffer, sizeof(msgBuffer), MSG_NOSIGNAL);
                if(b < 0)
                        printf("Error sending file ACK\n");
            } else {
                
  						printf("send %s\n", msgBuffer);
  						//we immediately acknowledge the client we got the file name
  						b = send(newsockfd, msgBuffer, sizeof(msgBuffer), MSG_NOSIGNAL);
                                                  if(b < 0)
                                                          printf("Error sending file ACK\n");

  						//we receive on the fileSizeBuffer
  						memset(&fileSizeBuffer, 0, sizeof(fileSizeBuffer));
  						b = recv(newsockfd, fileSizeBuffer, sizeof(fileSizeBuffer), 0);
                                                  if(b < 0)
                                                          printf("Error receiving file size\n");   
  						printf("size should be: %s\n", fileSizeBuffer);

  						fileSize = atoi(fileSizeBuffer);
  						
  						//print file name and size:
  						printf("File: '%s' (%d bytes)\n", fileName, fileSize);

  						//receive data
  						memset(&msgBuffer, 0, sizeof(msgBuffer));

  						//we send an ACK for file size
                                                  b = send(newsockfd, fileSizeBuffer, sizeof(fileSizeBuffer), MSG_NOSIGNAL);
                                                  if(b < 0)
                                                          printf("Error sending ACK for file size\n");
                                                  

              char recvmsg[BUF_SIZE];
  						FILE* fileprocessor;
  						fileprocessor = fopen(filepath, "wb"); //overwrite if existing
  										   //create if not
  						remainingData = fileSize;
  						//while(((len = recv(newsockfd, msgBuffer, BUF_SIZE, 0)) > 0) && (remainingData > 0))
  						while(remainingData != 0)
  						{
                                                          if(remainingData < BUF_SIZE)
                                                          {
                                                                  len = recv(newsockfd, recvmsg, remainingData, 0);
                                                                  fwrite(recvmsg, sizeof(char), len, fileprocessor);
                                                                  remainingData -= len;
                                                                  //printf("Received %lu bytes, expecting %d bytes\n", len, remainingData);
                                                                  //break;
                                                          }
                                                          else
                                                          {
                                                                   len = recv(newsockfd, recvmsg, BUF_SIZE, 0); //BUF_SIZE
                                                                   fwrite(recvmsg, sizeof(char), len, fileprocessor);
                                                                   remainingData -= len;
                                                                   //printf("Received %lu bytes, expecting: %d bytes\n", len, remainingData);
                                                          }
  						}
  						fclose(fileprocessor);
                                                  int pending_size = 256 - fileSize % 256;
                                                  if(fileSize && pending_size) {
                                                    printf("pending_size %d\n", pending_size);
                                                    b = recv(newsockfd, recvmsg, pending_size, 0); //receive bizarre lingering packet.
                                                  }
                                                  //clean buffer
            }
  					memset(&msgBuffer, 0 , sizeof(msgBuffer));
					}//end upload section
					else
					{	
						//close(newsockfd);
						printf("unknown message\n");
						//exit(1);
						//char recvmsg[BUF_SIZE];
						//b = recv(newsockfd, recvmsg, BUF_SIZE, 0);
					}//close switch
					
					//clean buffer
					memset(&msgBuffer, 0, sizeof(msgBuffer));
				}while(strcmp(msgBuffer, "exit") != 0); //close while loop here
			}
			else//parent process:
				close(newsockfd); //close specific socket
		}//for loop
  	close(sockfd); //if we got here, close general socket anyway
  	return 0;
}
