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
  
   // Question 3 part c (WISEMAN) starts:
  if (strcmp(command->name, "wiseman") == 0){
       
       // wiseman(command); //Our second solution for the wiseman question.
  	char ptr[100];
  	sprintf(ptr,"echo '*/%s * * * * fortune | espeak -s 125 -v en-uk+m5' | crontab -",command->args[1]); // for clearer voice
	system(ptr);
	//return SUCCESS;
  }
  // Question 3 part c (WISEMAN) ends.
  
  
  
  
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
