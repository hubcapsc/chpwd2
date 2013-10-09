/*  hpux           cc -o chpwd pam_tester.c -lsec -lpam */
/*  others         cc -o chpwd pam_tester.c -lpam */

/* pam-enabled command line password resetter */

/* usage: chpwd userid passwd */

#include <stdio.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>

static int tester_conv();
struct pam_conv pc={tester_conv,NULL};
pam_handle_t *ph;
char pass[100];

int main(int argc, char** argv){
  int rc;
  char *hostname=NULL;
  const void *vu;

  strcpy(pass,argv[2]);

  /* Years ago, when I wrote this program, I believed it helped (on
     some OSes) to lie about who we are... I think it was HPUX... 
   */
  if ((rc = pam_start("passwd",argv[1],&pc,&ph))) {
    printf("pam_start failed, rc:%d:\n",rc);
    exit(0);
  }

  if ((rc = pam_chauthtok(ph,0))) {
    printf("pam_chauthtok failed, rc:%d:\n",rc);
    exit(0);
  }

  pam_end(ph,rc);

}

static int tester_conv(int num_msg, struct pam_message **msg,
                    struct pam_response **response, void *appdata_ptr)
{
  *response = 
     (struct pam_response *) malloc(sizeof (struct pam_response));
  if (*response == NULL) return (PAM_BUF_ERR);
  (*response)->resp = strdup(pass);
  (*response)->resp_retcode = 0;
  return (PAM_SUCCESS);
}
