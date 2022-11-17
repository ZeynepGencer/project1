#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <linux/module.h>    /* Definition of MODULE_* constants */
#include <sys/syscall.h>     /* Definition of SYS_* constants */
#define ROOT_UID    0
const char *sysname = "shellax";

enum return_codes {
  SUCCESS = 0,
  EXIT = 1,
  UNKNOWN = 2,
};

struct command_t {
  char *name;
  bool background;
  bool auto_complete;
  int arg_count;
  char **args;
  char *redirects[3];     // in/out redirection
  struct command_t *next; // for piping
};

/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
  int i = 0;
  printf("Command: <%s>\n", command->name);
  printf("\tIs Background: %s\n", command->background ? "yes" : "no");
  printf("\tNeeds Auto-complete: %s\n", command->auto_complete ? "yes" : "no");
  printf("\tRedirects:\n");
  for (i = 0; i < 3; i++)
    printf("\t\t%d: %s\n", i,
           command->redirects[i] ? command->redirects[i] : "N/A");
  printf("\tArguments (%d):\n", command->arg_count);
  for (i = 0; i < command->arg_count; ++i)
    printf("\t\tArg %d: %s\n", i, command->args[i]);
  if (command->next) {
    printf("\tPiped to:\n");
    print_command(command->next);
  }
}
/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
  if (command->arg_count) {
    for (int i = 0; i < command->arg_count; ++i)
      free(command->args[i]);
    free(command->args);
  }
  for (int i = 0; i < 3; ++i)
    if (command->redirects[i])
      free(command->redirects[i]);
  if (command->next) {
    free_command(command->next);
    command->next = NULL;
  }
  free(command->name);
  free(command);
  return 0;
}
/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
  char cwd[1024], hostname[1024];
  gethostname(hostname, sizeof(hostname));
  getcwd(cwd, sizeof(cwd));
  printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
  return 0;
}
/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
  const char *splitters = " \t"; // split at whitespace
  int index, len;
  len = strlen(buf);
  while (len > 0 && strchr(splitters, buf[0]) != NULL) // trim left whitespace
  {
    buf++;
    len--;
  }
  while (len > 0 && strchr(splitters, buf[len - 1]) != NULL)
    buf[--len] = 0; // trim right whitespace

  if (len > 0 && buf[len - 1] == '?') // auto-complete
    command->auto_complete = true;
  if (len > 0 && buf[len - 1] == '&') // background
    command->background = true;

  char *pch = strtok(buf, splitters);
  if (pch == NULL) {
    command->name = (char *)malloc(1);
    command->name[0] = 0;
  } else {
    command->name = (char *)malloc(strlen(pch) + 1);
    strcpy(command->name, pch);
  }

  command->args = (char **)malloc(sizeof(char *));

  int redirect_index;
  int arg_index = 0;
  char temp_buf[1024], *arg;
  while (1) {
    // tokenize input on splitters
    pch = strtok(NULL, splitters);
    if (!pch)
      break;
    arg = temp_buf;
    strcpy(arg, pch);
    len = strlen(arg);

    if (len == 0)
      continue; // empty arg, go for next
    while (len > 0 && strchr(splitters, arg[0]) != NULL) // trim left whitespace
    {
      arg++;
      len--;
    }
    while (len > 0 && strchr(splitters, arg[len - 1]) != NULL)
      arg[--len] = 0; // trim right whitespace
    if (len == 0)
      continue; // empty arg, go for next

    // piping to another command
    if (strcmp(arg, "|") == 0) {
      struct command_t *c = malloc(sizeof(struct command_t));
      int l = strlen(pch);
      pch[l] = splitters[0]; // restore strtok termination
      index = 1;
      while (pch[index] == ' ' || pch[index] == '\t')
        index++; // skip whitespaces

      parse_command(pch + index, c);
      pch[l] = 0; // put back strtok termination
      command->next = c;
      continue;
    }

    // background process
    if (strcmp(arg, "&") == 0)
      continue; // handled before

    // handle input redirection
    redirect_index = -1;
    if (arg[0] == '<')
      redirect_index = 0;
    if (arg[0] == '>') {
      if (len > 1 && arg[1] == '>') {
        redirect_index = 2;
        arg++;
        len--;
      } else
        redirect_index = 1;
    }
    if (redirect_index != -1) {
      command->redirects[redirect_index] = malloc(len);
      strcpy(command->redirects[redirect_index], arg + 1);
      continue;
    }

    // normal arguments
    if (len > 2 &&
        ((arg[0] == '"' && arg[len - 1] == '"') ||
         (arg[0] == '\'' && arg[len - 1] == '\''))) // quote wrapped arg
    {
      arg[--len] = 0;
      arg++;
    }
    command->args =
        (char **)realloc(command->args, sizeof(char *) * (arg_index + 1));
    command->args[arg_index] = (char *)malloc(len + 1);
    strcpy(command->args[arg_index++], arg);
  }
  command->arg_count = arg_index;

  // increase args size by 2
  command->args = (char **)realloc(command->args,
                                   sizeof(char *) * (command->arg_count += 2));

  // shift everything forward by 1
  for (int i = command->arg_count - 2; i > 0; --i)
    command->args[i] = command->args[i - 1];

  // set args[0] as a copy of name
  command->args[0] = strdup(command->name);
  // set args[arg_count-1] (last) to NULL
  command->args[command->arg_count - 1] = NULL;

  return 0;
}

void prompt_backspace() {
  putchar(8);   // go back 1
  putchar(' '); // write empty over
  putchar(8);   // go back 1 again
}
/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
  int index = 0;
  char c;
  char buf[4096];
  static char oldbuf[4096];

  // tcgetattr gets the parameters of the current terminal
  // STDIN_FILENO will tell tcgetattr that it should write the settings
  // of stdin to oldt
  static struct termios backup_termios, new_termios;
  tcgetattr(STDIN_FILENO, &backup_termios);
  new_termios = backup_termios;
  // ICANON normally takes care that one line at a time will be processed
  // that means it will return if it sees a "\n" or an EOF or an EOL
  new_termios.c_lflag &=
      ~(ICANON |
        ECHO); // Also disable automatic echo. We manually echo each char.
  // Those new settings will be set to STDIN
  // TCSANOW tells tcsetattr to change attributes immediately.
  tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

  show_prompt();
  buf[0] = 0;
  while (1) {
    c = getchar();
    // printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

    if (c == 9) // handle tab
    {
      buf[index++] = '?'; // autocomplete
      break;
    }

    if (c == 127) // handle backspace
    {
      if (index > 0) {
        prompt_backspace();
        index--;
      }
      continue;
    }

    if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
      continue;
    }

    if (c == 65) // up arrow
    {
      while (index > 0) {
        prompt_backspace();
        index--;
      }

      char tmpbuf[4096];
      printf("%s", oldbuf);
      strcpy(tmpbuf, buf);
      strcpy(buf, oldbuf);
      strcpy(oldbuf, tmpbuf);
      index += strlen(buf);
      continue;
    }

    putchar(c); // echo the character
    buf[index++] = c;
    if (index >= sizeof(buf) - 1)
      break;
    if (c == '\n') // enter key
      break;
    if (c == 4) // Ctrl+D
      return EXIT;
  }
  if (index > 0 && buf[index - 1] == '\n') // trim newline from the end
    index--;
  buf[index++] = '\0'; // null terminate string

  strcpy(oldbuf, buf);

  parse_command(buf, command);

  // print_command(command); // DEBUG: uncomment for debugging

  // restore the old settings
  tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
  return SUCCESS;
}
int process_command(struct command_t *command);
int main() {
  while (1) {
    struct command_t *command = malloc(sizeof(struct command_t));
    memset(command, 0, sizeof(struct command_t)); // set all bytes to 0

    int code;
    code = prompt(command);
    if (code == EXIT)
      break;

    code = process_command(command);
    if (code == EXIT)
      break;

    free_command(command);
  }

  printf("\n");
  return 0;
}

 /* int count_command(struct command_t *command) { The other way to calculate number of process:

  if (command->next) {
      i = i + 1;
      count_command(command->next);
  }
  return i;
} */

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Our second solution for the wiseman question:

  /* void wiseman(struct command_t *command){
     
    int exit_value;
    int infd;
    int pipefd[2];
    // char *crontab_args[] = {"crontab", "-", NULL};
    // char str1[1000] = //*/;
 /*      strcat(str1,command->args[1]);
    char str2[] = " * * * * fortune | espeak";
    strcat(str1,str2);
    // strcat(str1,"\n"); //end of the file ?????
    

      if (pipe(pipefd) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }
        //fork child to handle cmd
        pid_t pid;
        pid = fork();
        if (pid == -1) {
            perror("fork");
            return;
        } else if(pid == 0) { // child process

               close(pipefd[1]);
               dup2(pipefd[0], 0);
	       char *crontab_args[] = {"crontab", "-", NULL};
	       execvp("crontab",crontab_args);
	       printf("errno: %d\f", errno);
	       exit(0);
	       
	}else{

               write(pipefd[1],&str1,strlen(str1)+1);
	       close(pipefd[0]);
	       close(pipefd[1]);
       }
              
 }  */
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



// Question 3 part d starts: our first custom command: last_x_lines // last fileName number_of_lines

// creating stack of lines
struct stack
{
          char strings[100];
};


 void last_x_lines(struct command_t *command){

             // stucture initialization    
              struct stack s[100];

              FILE *file;
              char line[100];
         
              int n,count=0, i=0;

              file  = fopen(command->args[1], "r");
         
              // reading line by line and push to stack
              while(fscanf(file , "%[^\n]\n" , line)!=EOF) {
                             strcpy(s[i].strings , line);
                             i++;
                             n=i; 
               }
               //n = i = total number of lines
               int numberOfLines = atoi(command->args[2]);
               // pop line by line
               for(i=(n-1);i>=0;i--) {
               
                        // last numberOfLines lines  
                         if(count == numberOfLines){
         
                               break;
                         } else {

                               printf("%s\n" , s[i].strings);
                         }
                         count++;                        
               }
}
// Question 3 part d starts: our first custom command: ENDs.


// Question 3 part d starts: our second custom command: first_x_lines // first fileName number_of_lines
 void first_x_lines(struct command_t *command){

             // stucture initialization    
              struct stack s[100];

              FILE *file;
              char line[100];
         
              int count=0, i=0;

              file  = fopen(command->args[1], "r");
         
              // reading line by line and push to stack
              while(fscanf(file , "%[^\n]\n" , line)!=EOF) {
                             strcpy(s[i].strings , line);
                             i++;
               }
               
               int total_numberOfLines = i; //total number of lines
               int numberOfLines = atoi(command->args[2]);
               // pop line by line
               for(int n=0;n < total_numberOfLines;n++) {
                        
                        // last numberOfLines lines  
                         if(count == numberOfLines){                              
                               break;
                         } else {
                               printf("%s\n" , s[n].strings);
                         }
                         count++;                        
               }
}
 
 
// Question 3 part d starts: our second custom command: ENDs.

// Question 3 part d starts: our third custom command
#define MAX_MESSAGE_SIZE 30

void shuffle(char str[]){
    srand(time(NULL));   // Initialization, should only be called once.
    int r1 = rand() % ( strlen(str)-1 ); 
    int r2 = rand() % ( strlen(str)-1 ); 
    char term= str[r1];
    str[r1]=str[r2];
    str[r2]=term;
}
char* shufflepoint(char* str){
   // srand(time(NULL));   // Initialization, should only be called once.
   // int r1 = rand() % ( strlen(str)-1 ); 
   // int r2 = rand() % ( strlen(str)-1 ); 
    char strnew[MAX_MESSAGE_SIZE];
    char *temp = str;
    int i=0;
    while (*temp != '\0') {

        strnew[i]=*temp;
        i++;
        temp++;
    }
    strnew[i]='\0';
    shuffle(strnew);
    str=strnew;
    printf("\n%s\n",str);
    return str;
}

char* reversepoint(char* str){
    char strnew[MAX_MESSAGE_SIZE];
    char *temp = str;
    int i=0;
    while (*temp != '\0') {
        i++;
        temp++;
    }
    int j=i;
    char *temp2 = str;
     while (*temp2 != '\0'){
        strnew[i-1]=*temp2;
        i--;
        temp2++;
    }
    strnew[j]='\0';
    str=strnew;
    printf("\n%s\n",str);
    return str;
}
// Question 3 part d starts: our third custom command ends






void myUniq(struct command_t *command){ // our uniq function

     char buffer[600];
     char **lines = NULL;
     int i = 0;
    
     while (fgets(buffer, sizeof(buffer), stdin)){
     
        lines = realloc(lines, (i + 1) * sizeof (char*));
        lines[i] = strdup(buffer);
        i++;
     }
     
     int fr[i];
     int visited = -1; // to show an element is visited or not.

     for(int c = 0; c < i; c++){
     
        int count = 1;
        for(int j = c+1; j < i; j++){
        
            if(strcmp(lines[c],lines[j])== 0){
            
                count++;
                //To avoid counting same element again
                fr[j] = visited;
            }
        }
        if(fr[c] != visited)
            fr[c] = count; // to determine the number of occurrences of the element.
     }

     if(command->args[1] == NULL){

             for(int c = 0; c < i; c++){
             
                if(fr[c] != visited){
                
                   printf("%s",lines[c]);
                }
             }
     } else if(strcmp(command->args[1],"-c")==0 || strcmp(command->args[1],"-C")==0 ){
     
           for(int c = 0; c < i; c++){
           
               if(fr[c] != visited){
               
                  printf("%d %s",fr[c],lines[c]);      
               }
           }

    } 
  
    for (int c = 0; c < i; c++) {
        free(lines[c]);
    }

    // free() the array itself
   // free(lines);
}




int process_command(struct command_t *command) {
  int r;
  if (strcmp(command->name, "") == 0)
    return SUCCESS;

  if (strcmp(command->name, "exit") == 0)
    return EXIT;

  if (strcmp(command->name, "cd") == 0) {
    if (command->arg_count > 0) {
      r = chdir(command->args[0]);
      if (r == -1)
        printf("-%s: %s: %s\n", sysname, command->name, strerror(errno));
      return SUCCESS;
    }
  }
  // Question 3 part b (CHATROOM) starts:
  struct stat st = {0};
  if (strcmp(command->name, "chatroom") == 0){
   if (command->arg_count > 3) { //change 0 to 3 to check the name folder
        char path[150] = "/tmp/chatroom-";
    	strcat(path, command->args[1]);
   	if (stat(path, &st) == -1) { //if chatroom does not exist create one 
    		mkdir(path, 0700);
	}
	printf("Welcome to %s!\n",command->args[1]);
	
	char dirpath[50];
	strcpy(dirpath, path); //directory path

	strcat(path, "/");
	strcat(path, command->args[2]);
	char  myfifo[150];
	strcpy(myfifo,path);
        mkfifo(path, S_IWUSR | S_IRUSR |S_IRGRP | S_IROTH); // create pipe , S_IWUSR | S_IRUSR |S_IRGRP | S_IROTH

	int fd;
	int fd1;
	char str1[180], str2[185],str3[180];
	pid_t pid;
  	pid=fork();
  	if (pid< 0) 
  	{ 
            	perror("fork error happened");
            	exit(1);
        } 
        else if(pid==0) //child process
        {	
   		while (1)
    		{
    			//read user pipe all the time 
        		fd1 = open(myfifo,O_RDONLY,O_NONBLOCK);
        		
        		int a= read(fd1, str1, 180);
        		printf("\r%s", str1);
        		printf("%s> ", command->args[2]);
        		fflush(stdout);
        		close(fd1);
		}
		
		
	}
	else // write the input you get from terminal PARENT
	{	
		
		while(1){

		fflush(stdout);
   		fgets( str3,180,stdin);
   		printf("\033[A");
   		fflush(stdout);
   		sprintf(str2,"%s: %s",command->args[2],str3);
 
		//GET PIPE COUNT 
		char *arr[50];
    		char **ptr = arr;
		int file_count = 0;
		DIR * dirp;
		struct dirent * entry;      				
		dirp = opendir(dirpath);
       
		while ((entry = readdir(dirp)) != NULL) {
	
   	 		if (entry->d_type == DT_FIFO  ) { /* If the entry is a named pipe */  	 
        			ptr[file_count]=entry->d_name;
         			file_count++;
         		//printf("pipe count %d\n",file_count);
    			}
		}	
		closedir(dirp);
		//PIPE PATH
		int i;
		strcat(dirpath,"/");
		for ( i = 0; i < file_count; i++ ){
	
			char *tmp = strdup(ptr[i]);
			strcpy(ptr[i], dirpath); 
			strcat(ptr[i], tmp);  
			free(tmp);
        		//printf("String %d : %s\n", i+1, ptr[i] );//DEBUG             
 			}
		for( i = 0; i < file_count; i++) // write to all  children
			{
			   		
   			if (pid< 0) 
  				{ 
            			perror("fork error happened");
            			exit(1);
        			} 
        		else if(pid>0) //parent process
        			{
				pid=fork();
				}
			if(pid== 0) // child process 
        			{ 
        			//printf("writing to file %s\n",ptr[i]);//DEBUG
        			fd = open(ptr[i],O_WRONLY,O_NONBLOCK);
        			write(fd, str2, strlen(str2)+1);
        			close(fd);
        			exit(0);
        			}	
			}
		}
	}	
    }
  }
  // Question 3 part b (CHATROOM) ends.
   // Question 3 part c (WISEMAN) starts:
  if (strcmp(command->name, "wiseman") == 0){
       
       // wiseman(command); //Our second solution for the wiseman question.
  	char ptr[100];
  	sprintf(ptr,"echo '*/%s * * * * fortune | espeak -s 125 -v en-uk+m5' | crontab -",command->args[1]); // for clearer voice
	system(ptr);
	//return SUCCESS;
  }
  // Question 3 part c (WISEMAN) ends.
  
  
    // Question 3 part d starts: our first custom command:  //last fileName number_of_lines
  if (strcmp(command->name,"last") == 0) {
         
          last_x_lines(command);
          return SUCCESS;
  }
  
  // Question 3 part d: our first custom command ENDs.
  
  
  // Question 3 part d starts: our second custom command:  // first fileName number_of_lines
   if (strcmp(command->name,"first") == 0) {
         
          first_x_lines(command);
          return SUCCESS;
  }
  // Question 3 part d starts: our second custom command ENDs:
  //Question 3 part d starts: our third custom command:  str = string manipulator//
  
    if (strcmp(command->name, "str") == 0) {
	if (command->arg_count > 2) {

		char *ptr;
      		ptr = command->args[2];
      		if(strcmp(command->args[1], "shuffle") == 0){
		printf("Your new word after shuffle is: ");
      		sprintf(ptr,"%s",shufflepoint(ptr));
		}
		else if(strcmp(command->args[1], "reverse") == 0){
		printf("Your new word after reverse is: ");
      		sprintf(ptr,"%s",reversepoint(ptr));
		}
      		return SUCCESS;
    }
  }
  
    //Question 3 part d starts: our third custom command ENDs:
    
    //Question 5 (PSVIS) starts:
    if (strcmp(command->name, "psvis") == 0){
    if (command->arg_count > 0) {
	uid_t uid;
    	int res;

   	 /* Check if program being run by root */
    	uid = getuid();
    	if (uid != ROOT_UID) {
    		system("sudo -s");
    	}

    	/* Check if module file exists */
    	if (access("./mymodule.ko", F_OK) == -1) {
        	fprintf(stderr, "Error: File doesn't exist\n");
    	}

	if(system("lsmod | grep mymodule")){
	
    	/* Load module */
    	char str[100];
    	sprintf(str,"/sbin/insmod ./mymodule.ko pid=%d",atoi(command->args[1]));

    	res = system(str);
    		if (res != 0) {
        		fprintf(stderr, "Error loading module: %d\n", res);
        		//return EXIT_FAILURE;
    		}
    	printf("Module was successfully loaded\n");
	}
	else{
	printf("Module is already loaded\n");
	}
	
	system("dmesg | grep mymodulePID: > pid");
	system("dmesg | grep mymoduleParentPID: > ppid");
	system("dmesg | grep mymoduleTime > startTime");
	
	
	// READ PID ///
	FILE * fp;
    	char * line = NULL;
    	size_t len = 0;
    	ssize_t read;
	char *pid;
	int pidArr[1000];
    	int i=0;
    	
    	fp = fopen("pid", "r");
    	if (fp == NULL)
        	exit(EXIT_FAILURE);

    	while ((read = getline(&line, &len, fp)) != -1) {
       	 	pid = strtok(line, ":");
       	 	pid = strtok(NULL, ":");
       	 	pidArr[i]=atoi(pid);
       	 	//printf("Retrieved the pid: %d\n", pidArr[i]);
       	 	i++;
   	 }
   	 fclose(fp);

   	 ///  PID READING OVER // 
   	 

   	 // PARENT READ PID ///
	FILE * fp2;
    	char * line2 = NULL;
    	size_t len2 = 0;
    	ssize_t read2;
	char *ppid;
	int ppidArr[1000];
    	i=0;
    	
    	fp2 = fopen("ppid", "r");
    	if (fp2 == NULL)
        	exit(EXIT_FAILURE);

    	while ((read2 = getline(&line2, &len2, fp2)) != -1) {
       	 	ppid = strtok(line2, ":");
       	 	ppid = strtok(NULL, ":");
       	 	ppidArr[i]=atoi(ppid);
       	 	//printf("Retrieved the ppid: %d\n", ppidArr[i]);
       	 	i++;
   	 }
   	 fclose(fp2);

   	 /// PARENT PID READING OVER // 
   	 
   	// TIME READ  ///
	FILE * fp3;
    	char * line3 = NULL;
    	size_t len3 = 0;
    	ssize_t read3;
	char *taym;
	long long int startArr[1000];
    	i=0;
    	
    	fp3 = fopen("startTime", "r");
    	if (fp3 == NULL)
        	exit(EXIT_FAILURE);

    	while ((read3 = getline(&line3, &len3, fp3)) != -1) {
       	 	taym = strtok(line3, ":");
       	 	taym = strtok(NULL, ":");
       	 	startArr[i]=atoll(taym);
       	 	//printf("Retrieved the time: %s\n", startArr[i]);
       	 	i++;
   	 }
   	 fclose(fp3);

   	 /// TIME READING OVER // 
   	 int max=i;
   	 //FIND OLDEST CHILD Uğrascam 
   	 
   	 system("dmesg | grep mymoduleOLD > olds");
   	 FILE * fp4;
    	char * line4 = NULL;
    	size_t len4 = 0;
    	ssize_t read4;
	char *old;
	int oldArr[1000];
    	i=0;
    	
    	fp4 = fopen("olds", "r");
    	if (fp4 == NULL)
        	exit(EXIT_FAILURE);

    	while ((read4 = getline(&line4, &len4, fp4)) != -1) {
       	 	old = strtok(line4, ":");
       	 	old = strtok(NULL, ":");
       	 	oldArr[i]=atoi(old);
       	 	//printf("Retrieved the oldie: %d\n", oldArr[i]);
       	 	i++;
   	 }
   	 fclose(fp4);

	///VISUALIZATION//
	char graphDataLine[100];
	char graphLabel[75];
   	//system("rm graph")
   	 
   	FILE *grp;

   	grp = fopen("graph","w");

   	if(grp == NULL)
   	{
      		printf("Error writing!");   
      		exit(1);             
   	}

   	fprintf(grp,"%s","graph G{\n");
   	//FOR THE FIRST OLDEST CHILD
   	 fprintf(grp,"%d [color=%s]\n",oldArr[0],"red");
   	 //REST OF CHILD NODES
   	 for(i=1; i<max; i++){
   	 
   	 //LABELING THE NODES
   	 sprintf(graphLabel,"pid: %d\nstart time:%lld",pidArr[i],startArr[i] );
   	 //printf("%s\n",graphLabel);
   	 sprintf(graphDataLine,"%d [label=%s%s%s]\n",pidArr[i],"\"",graphLabel,"\"");
   	 fprintf(grp,"%s",graphDataLine);
   	 
   	 if(oldArr[i]==-1){
   	 sprintf(graphDataLine,"%d -- %d\n",ppidArr[i],pidArr[i]);
   	 }else{
   	 sprintf(graphDataLine,"%d -- %d\n%d [color=%s]\n",ppidArr[i],pidArr[i],oldArr[i],"red");
   	 }
   	 fprintf(grp,"%s",graphDataLine);
   	 
   	 }
	fprintf(grp,"%s","}");   	 
   	 
   	 fclose(grp);
	
	system("cat graph | dot -Tpng > out.png");
	
	///REMOVE MODULE 
	
	if(!system("lsmod | grep mymodule")){
	res = system("/sbin/rmmod ./mymodule.ko");
    		if (res != 0) {
        		fprintf(stderr, "Error removing module: %d\n", res);
        		//return EXIT_FAILURE;
    		}
    		else{
    		printf("Removed module\n");
    		}
	}
	else{
    	 	printf("No module to remove\n");
    	}
	system("dmesg -C");
}
  }
  //Question 5 (PSVIS) ends
   // int c = count_command(command); Another way to calculate the number of pipes and processes is to call a function directly.
   // i = 1;
   
// Question 2 Part 2 starts:   

     // Calculating number of process and pipe.
     int child_num = 1; // number of child process
     struct command_t *new = command;
     while (new->next){
	   child_num = child_num + 1;
	  new = new->next;
    }
  
    int pipe_count = child_num - 1 ;
    int exit_value;
    int infd;
    int pipefd[2];
   struct command_t *next_command = command;
   
// when there are pipes:
if(child_num > 1){  //We used if to distinguish whether there are pipes or not. 


    //loop through pipe commands
    for (int i = 0; i <= pipe_count; i++) {
    
        //create new pipe for cmd i
        if (pipe(pipefd) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }
        //fork child to handle cmd
        pid_t pid;
        pid = fork();
        if (pid == -1) {
            perror("fork");
            //return;
        } else if(pid == 0) { // child process
        
            //for all but first cmd, connect stdin with pipefd[0]          
            if(i != 0) {
	
                dup2(infd, 0); //put what you read from pipe in the input of this command
            }


            //for all but last cmd, connect stdout with pipefd[1]
            if (i != pipe_count) {
		
                dup2(pipefd[1], 1);//write the output of this command to pipe
            }
    
            // Question 3 uniq command starts:  
            if(strcmp(next_command->name, "myuniq") == 0){ //Our uniq command.
            
                myUniq(next_command);
            // Question 3 uniq command ends. 
            }else{
		  
                execvp(next_command->name,next_command->args);
	   }
	   	  
            exit(1);
        } else { //parent process
        
            //wait and store pipefd[0] for next iteration
            wait(&exit_value);
            infd = pipefd[0];
            // close(pipefd[0]);
	    close(pipefd[1]);
	    next_command = next_command->next;
        }
    }
     
     return SUCCESS; 
// Question 2 Part 2 ends.

} else if(child_num == 1){ // There are no pipes.



  pid_t pid = fork();
  if (pid == 0) // child
  {
    /// This shows how to do exec with environ (but is not available on MacOs)
    // extern char** environ; // environment variables
    // execvpe(command->name, command->args, environ); // exec+args+path+environ

    /// This shows how to do exec with auto-path resolve
    // add a NULL argument to the end of args, and the name to the beginning
    // as required by exec

    // TODO: do your own exec with path resolving using execv()
    // do so by replacing the execvp call below
    
    
// Question 2 part 1: I/O redirection problem starts:
     if(command->redirects[0] != NULL){
     
       int in = open(command->redirects[0], O_RDONLY);
       dup2(in, STDIN_FILENO);         // duplicate stdin to input file
       close(in);                      // close after use
     }
     if(command->redirects[1] != NULL){
    
       int out =open(command->redirects[1], O_WRONLY | O_CREAT | O_TRUNC,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // open(command->redirects[1],O_CREAT | O_TRUNC | O_WRONLY);
       dup2(out, STDOUT_FILENO);         // duplicate stdout to output file
       close(out);                      // close after use
     }

     if(command->redirects[2] != NULL){
     
         int out2 = open(command->redirects[2], O_CREAT | O_RDWR | O_APPEND);
         dup2(out2, STDOUT_FILENO);         // duplicate stdout to output file
         close(out2);
    }
// Question 2 part 1: I/O redirection problem ends.


    
    
    
    // Question 1: execv() problem starts:
    char *pathVar = getenv("PATH");
    char * token = strtok(pathVar, ":");
    char czg[] = "/";
    char path[100];
    strcat(czg,command->args[0]); 
    
    // loop through the string to extract all other tokens
    while( token != NULL ) {
     
          strcpy(path,token);
          strcat(path,czg); // add command name to the end of path.
          if(execv(path,command->args) != -1){
            //perror("execv");
              break;
          }
          token = strtok(NULL, ":");
   }
  //Question 1:  execv() problem ends.
  
  
  
    //execvp(command->name, command->args); // exec+args+path
    exit(0);
  } else { // Parent Process
  
// Question 1: ampersand (&) problem starts:
    // TODO: implement background processes here
    
      int status;
      if(command->background == false){

	   waitpid(pid, &status, 0);

      }
      return SUCCESS;
// Question 1: ampersand (&) problem ends.
  }
  }

  // TODO: your implementation here

  printf("-%s: %s: command not found\n", sysname, command->name);
  return UNKNOWN;
}
