#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include "common.h"

#define FTPCLIENT_PID_FILE "/var/run/ftpclient.pid"

int main_pid = 0;
int no_fork = 0;
char *pid_file = FTPCLIENT_PID_FILE;

typedef void (*sighandler_t) (int);

static void sig_usr_un(int signo)
{
  if (signo == SIGCHLD || signo == SIGPIPE) {
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

void syserr(char* msg) { perror(msg); exit(-1); }

static int socket_connect(struct hostent* server, int portno)
{
  struct sockaddr_in serv_addr;

  //socket file descriptor
  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sockfd < 0) {
    perror("can't open socket");
    return -1;
  }
  printf("create socket...\n");

  //once socket is created:
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET; //IPV4
  serv_addr.sin_addr = *((struct in_addr*)server->h_addr);
  serv_addr.sin_port = htons(portno); //port

  if(connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("can't connect to server");
    close(sockfd);
    return -1;
  }
  printf("connect...\n");

  return sockfd;

}

static int handle_cmd(char *buffer, char *path, int sockfd, DIR *dir)
{
  int  n, fileSize;
  char fileSizeBuffer[BUF_SIZE];
  struct dirent *directory;

  struct pollfd fds[1];
  fds[0].fd = sockfd;
  fds[0].events = POLLIN|POLLPRI;
  fds[0].revents = 0;

  // Timeout in milliseconds (5 seconds)
  int timeout = 300;
  
  printf("\nPLEASE ENTER MESSAGE: ");
  //fgets(buffer, 255, stdin);
  n = strlen(buffer);

  if(n > 0 && buffer[n-1] == '\n') //line break
	  buffer[n-1] = '\0';
  
  //send
  n = send(sockfd, buffer, strlen(buffer), 0);
  printf("user sent %s\n", buffer);

  if(n < 0) //couldn't send
  {
	  perror("can't send to server");
    return -2;
  }
  
  //user calls download
  if(buffer[0] == 'g' &&
	 buffer[1] == 'e' &&
	 buffer[2] == 't' &&
	 buffer[3] == ' ')
  {
	  printf("User requested a download.\n");

	  //we catch the file name
	  char fileName[BUF_SIZE];
	  memset(&fileName, 0, sizeof(fileName));
	  
	  //parse
	  int j = 0;
	  for(int i = 4; i <= strlen(buffer); i++)
	  {
		  fileName[j] = buffer[i];
		  j++;
	  }

	  //catch file size:
	  recv(sockfd, buffer, sizeof(buffer), 0);
	  fileSize = atoi(buffer);

	  //send size back as ACK:
	  send(sockfd, buffer, sizeof(buffer), 0);

	  //print file name and size:
	  printf("File: '%s' (%d bytes)\n",fileName, fileSize);
	  

	  //receive data:
	  memset(&buffer, 0, sizeof(buffer));
	  int remainingData = 0;
	  ssize_t len;
	  char path[BUF_SIZE] = "./folder-local/";
	  strcat(path, fileName);
	  printf("path: %s", path);
	  FILE* fp;
	  fp = fopen(path, "wb");//overwrite if existing
	  							//create if not
	  remainingData = fileSize;
	  //while(((len = recv(sockfd, buffer, BUF_SIZE, 0)) > 0) && (remainingData > 0))
	  printf("remainingData: %d", remainingData);
	  while(remainingData != 0)
	  {
		  if(remainingData < BUF_SIZE)
		  {
			  len = recv(sockfd, buffer, remainingData, 0);
			  fwrite(buffer, sizeof(char), len, fp);
			  remainingData -= len;
			  printf("Received %lu bytes, expecting %d bytes\n", len, remainingData);
			  break;
		  }
		  else
		  {
		  	len = recv(sockfd, buffer, BUF_SIZE, 0); //BUF_SIZE
		  	fwrite(buffer, sizeof(char), len, fp);
	      	remainingData -= len;
		  	printf("Received %lu bytes, expecting: %d bytes\n", len, remainingData);
		  }
	  }
	  fclose(fp);
	  n = recv(sockfd, buffer, BUF_SIZE, 0); //receive bizarre lingering packet.

	  //clean buffer
	  memset(&buffer, 0, sizeof(buffer));
  }
  //user calls 'put file'
        //send file to server! (upload)
  else if(buffer[0] == 'p' &&
          buffer[1] == 'u' &&
	  buffer[2] == 't' &&
	  buffer[3] == ' ')
  {
    char msg[BUF_SIZE];
	  printf("User requested an upload\n");

    int ret = poll(fds, 1, timeout);
    
    if (ret == -1) {
        perror("poll");
        return -1;
    } else if (ret == 0) {
        printf("Timeout occurred. No events.\n");
        return -1;
    }

    //we wait for the server's ACK
    n = recv(sockfd, msg, sizeof(msg), 0);
    if(n < 0)
        printf("Server didn't acknowledge name");

    if(!strncmp(msg, "exist", 5)) {
      printf("received <exist>\n");
      return 0;
    }

	  //parse the string
	  int j = 0;
	  for(int i = 4; i <= strlen(msg); i++)
	  {
		  msg[j] = msg[i];
		  j++;
	  }

	  char address[BUF_SIZE];// = "./folder-local/";
    snprintf(address, sizeof(address), "%s/%s", path, msg);
	  //strcat(address, buffer); //get file path

	  //open file path
                FILE* fp;
	  fp = fopen(address, "rb"); //filename, read bytes
	  if(fp == NULL) {
		  printf("error opening file in: %s, %s\n", msg, strerror(errno));
      return 0;
    }
	  printf("File opened successfully!\n");

	  //we will attempt to read the file
	  //in chunks of BUF_SIZE bytes and send!

	  //figure out file size:
	  int file_size = 0;
	  if(fseek(fp, 0, SEEK_END) != 0)
		printf("Error determining file size\n");

	  file_size = ftell(fp);
	  rewind(fp);
	  printf("File size: %lu bytes\n", file_size);
	  
	  //pass this size to a buffer in order to send it:
                //no need for host to network long, we're passing char array
	  memset(&fileSizeBuffer, 0, sizeof(fileSizeBuffer));
	  sprintf(fileSizeBuffer, "%d", file_size);
	  //memset(&buffer, 0, sizeof(buffer));
	  //send file size:
	  n = send(sockfd, fileSizeBuffer, sizeof(fileSizeBuffer), 0);
	  if(n < 0)
		  printf("Error sending file size information\n"); 
	  
	  //receive ACK for file size:
                //give enough time for server to get
                //file size we just sent
                ret = poll(fds, 1, timeout);

                if (ret == -1) {
                    perror("poll");
                    return -1;
                } else if (ret == 0) {
                    printf("Timeout occurred. No events.\n");
                    return -1;
                }
                
                n = recv(sockfd, fileSizeBuffer, sizeof(fileSizeBuffer), 0);
                if(n < 0)
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
                         n = send(sockfd, byteArray, BUF_SIZE, 0);
                         if(n < 0) {
                                 printf("Error sending small slab\n");
                                 return -2;
                         }

                         //printf("sent %d slab\n", buffRead);
                     }
                     //for slabs of BUF_SIZE bytes:
                     else
                     {
                         buffRead = fread(byteArray, 1, BUF_SIZE, fp);
                         bytesRemaining = bytesRemaining - buffRead;
                         n = send(sockfd, byteArray, BUF_SIZE, 0);
                         if(n < 0) {
                                 printf("Error sending slab\n");
                                 return -2;
                          }
                         //printf("sent %d slab\n", buffRead);
                     }
                }
                printf("File sent!\n");
                //clean buffers
                memset(&buffer, 0, sizeof(buffer));
                memset(&byteArray, 0, sizeof(byteArray));
  }
  //user calls ls-local
  else if(strcmp(buffer, "ls-local") == 0)
  {
	  memset(&buffer, 0, sizeof(buffer));
	  printf("running ls-local function:");

	  if(dir)//if directory successfully opens
	  {
	  	while((directory = readdir(dir)) != NULL)//while in dir.
		{
			if(strcmp(directory->d_name, ".") == 0 ||                                        
			   strcmp(directory->d_name, "..") == 0)                                         
			{
				//printf("\n%s", directory->d_name);
			}                                                         
			else	
				printf("\n%s", directory->d_name);
		}
		printf("\n");

	  	//rewind
	  	rewinddir(dir);
	  }
	  else
		  printf("could not open directory");

	  n = recv(sockfd, buffer, sizeof(buffer), 0);

	  if(n < 0) //couldn't receive
		  syserr("can't receive from server");

	  //clean buffer
	  memset(&buffer, 0, sizeof(buffer));
  }
  else if(strcmp(buffer, "ls-remote") == 0)
  {
	 n = recv(sockfd, buffer, sizeof(buffer), 0);

	 if(n < 0) //couldn't receive
		 syserr("can't receive from server");

	 printf("running ls-remote function: %s\n", buffer);

	 //clean buffer
	 memset(&buffer, 0, sizeof(buffer));
  }
  //user exits
  else if(strcmp(buffer, "exit") == 0)
  {
	  return 0;
  }
  else//user sent a normal message
  {	  
    char msg[BUF_SIZE];
	  //echo (receive)
	  //n = recv(sockfd, buffer, sizeof(buffer), 0);
	  //memset(&buffer, 0, sizeof(buffer));
	  n = recv(sockfd, msg, sizeof(msg), 0);

	  if(n < 0) //couldn't receive 
		  syserr("can't receive from server"); 
	  else
		  msg[n] = '\0';
  	  
	  printf("Client received message: %s\n", msg);
	  
	  //clean buffer
	  memset(&buffer, 0, sizeof(buffer));
  }
  //clean buffer here maybe
  memset(&buffer, 0, sizeof(buffer));

  return 0;
}

int main(int argc, char* argv[])
{
  int sockfd = -1, portno;
  struct hostent* server;
  char buffer[BUF_SIZE];
  DIR *dir;
  char path[BUF_SIZE];
  int pid;
	FILE *pid_stream;
  int firstrun = 1;

  if(argc < 4) {
    fprintf(stderr, "Usage: %s <hostname> <port> <path>\n", argv[0]);
    return 1;
  }

  if(argc == 5 && !strcmp(argv[4], "nofork")) {
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
  
  server = gethostbyname(argv[1]);
  if(!server) {
    fprintf(stderr, "ERROR: no such host: %s\n", argv[1]);
    return 2;
  }
  
  portno = atoi(argv[2]);

  snprintf(path, sizeof(path), "%s", argv[3]);

  struct stat st;
  if (stat(path, &st) == 0) {
    if (S_ISDIR(st.st_mode)) {
        printf("Folder '%s' already exists.\n", path);
    } else {
        printf("'%s' exists but is not a folder.\n", path);
    }
  } else {
    // Folder does not exist, create it
    if (mkdir(path, 0755) == 0) {
        printf("Folder '%s' created successfully.\n", path);
    } else {
        perror("Failed to create folder");
    }
  }

  dir = opendir(path);
  
  /*{
  struct in_addr **addr_list; int i;
  printf("Official name is: %s\n", server->h_name);
  printf("    IP addresses: ");
  addr_list = (struct in_addr **)server->h_addr_list;
  for(i = 0; addr_list[i] != NULL; i++) {
    printf("%s ", inet_ntoa(*addr_list[i]));
  }
  printf("\n");
  }*/

  char olddate_buffer[7] = ""; // YYMMDD + null terminator

  while(1) {

    char date_buffer[7]; // YYMMDD + null terminator
    
    // Buffer to store the final string
    char filename[20]; // Adjust size as needed

    struct dirent *directory;

    // Get the current time
    time_t now = time(NULL);
    if (now == -1) {
        perror("time");
        sleep(3);
        continue;
    }
    
    // Convert the time to a struct tm
    struct tm *tm_info = localtime(&now);
    if (tm_info == NULL) {
        perror("localtime");
        sleep(3);
        continue;
    }
    
    // Format the date as YYMMDD
    if (strftime(date_buffer, sizeof(date_buffer), "%y%m%d", tm_info) == 0) {
        fprintf(stderr, "strftime failed\n");
        sleep(3);
        continue;
    }
    

    int ret;
    if(strcmp(olddate_buffer, date_buffer))
    {
      // Construct the final filename
      snprintf(filename, sizeof(filename), "3proxy-%s.log", date_buffer);

      if(!firstrun) {
        if(strlen(olddate_buffer)) {
          char filepath[BUF_SIZE];
          for(int try_olddate=0; try_olddate<5; try_olddate++) {
            snprintf(filename, sizeof(filename), "3proxy-%s.log", olddate_buffer);
            snprintf(filepath, sizeof(filepath), "%s/%s", path, filename);

            struct stat st;
            if (stat(filepath, &st) == 0) {
              if( (sockfd = socket_connect(server, portno)) < 0)
                goto cont;

              sleep(30); // Wait 30 seconds before the server finalizes the log file.
              snprintf(buffer, sizeof(buffer), "put %s", filename);
              for(int retry=0; retry<5; retry++) {
                ret = handle_cmd(buffer, path, sockfd, dir);
                if(ret >= 0)
                  break;
                printf("retry last file %s...\n", filename);
                sleep(3);
              }
              sleep(1);
              close(sockfd);
              break;
            } else {
              printf("file not found %s\n", filepath);
              sleep(30);
            }
          }
        }
      } else {
        if(dir)//if directory successfully opens
        {
          int error;
retry_first:

          if( (sockfd = socket_connect(server, portno)) < 0)
            goto cont;

          error = 0;
        	while((directory = readdir(dir)) != NULL)//while in dir.
          {
          	if(strcmp(directory->d_name, ".") == 0 ||                                        
          	   strcmp(directory->d_name, "..") == 0)                                         
          	{
          		//printf("\n%s", directory->d_name);
          	}                                                         
          	else {
          		printf("\n%s", directory->d_name);
              if(strcmp(filename, directory->d_name)) {
                snprintf(buffer, sizeof(buffer), "put %s", directory->d_name);
                ret = handle_cmd(buffer, path, sockfd, dir);
                if(ret == -2) {
                  error = 1;
                  break;
                } else if(ret < 0) {
                  error = 1;
                }
                usleep(100000);
              }
            }
          }

        //rewind
          rewinddir(dir);

          if(error) {
            printf("retry first ...\n");
            sleep(3);
            close(sockfd);
            goto retry_first;
          }
          
          firstrun = 0;

          sleep(1);
          close(sockfd);
        }
      }

      strcpy(olddate_buffer, date_buffer);
    }

cont:
    sleep(30);

  }
  
  return 0;
}
