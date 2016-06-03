/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <sys/types.h>
#include <crypt.h>
#include <security/pam_appl.h>

int pamconv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
  if (num_msg != 1 || msg[0]->msg_style != PAM_PROMPT_ECHO_OFF) {
		fprintf(stderr, "ERROR: Unexpected PAM conversation '%d/%s'\n", msg[0]->msg_style, msg[0]->msg);
		return PAM_CONV_ERR;
  }
  if (!appdata_ptr) {
		fprintf(stderr, "ERROR: No password available to conversation!\n");
		return PAM_CONV_ERR;
  }
	*resp = calloc(num_msg, sizeof(struct pam_response));
	if (!*resp) {
		fprintf(stderr, "ERROR: Out of memory!\n");
		return PAM_CONV_ERR;
  }
  (*resp)[0].resp = strdup((char *) appdata_ptr);
  (*resp)[0].resp_retcode = 0;

	return ((*resp)[0].resp ? PAM_SUCCESS : PAM_CONV_ERR);
}

int isPAMEnabled() {
	if( access("/etc/pam.d/ranger-remote", F_OK ) != -1 ) {
	  return 1;
	} else {
	  /* file doesn't exist */
   	  return 0;
   	}
}


struct pam_conv conv = { pamconv, NULL };

int main(int ac, char **av, char **ev)
{
	char username[64] ;
	char password[64] ;
	char line[512] ;
	struct passwd *pwp;
	struct spwd *spwd ; 
    int retval;
	pam_handle_t *pamh = NULL;

	fgets(line,512,stdin) ;

	sscanf(line, "LOGIN:%s %s",username,password) ;

	if (isPAMEnabled()) {
		/* PAM Authentication */
		
		conv.appdata_ptr = (char *) password;

		retval = pam_start("ranger-remote", username, &conv, &pamh);
		if (retval != PAM_SUCCESS) {
			/* why expose this? */
			fprintf(stdout, "FAILED: [%s] does not exists.\n", username) ;
			exit(1);
		}

		retval = pam_authenticate(pamh, 0);
		if (retval != PAM_SUCCESS) {
			fprintf(stdout, "FAILED: Password did not match.\n") ;
			exit(1);
		}

		/* authorize */
		retval = pam_acct_mgmt(pamh, 0);
		if (retval != PAM_SUCCESS) {
			fprintf(stdout, "FAILED: [%s] is not authorized.\n", username) ;
			exit(1);
		}

		/* establish the requested credentials */
		if ((retval = pam_setcred(pamh, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
			fprintf(stdout, "FAILED: Error setting credentials for [%s].\n", username) ;
    		exit(1);
		}

		/* not opening a session, as logout has not been implemented as a remote service */
		fprintf(stdout, "OK:\n") ;

		if (pamh) {
			pam_end(pamh, retval);
		}
	} else {
      /* crypt Authentication */
      	pwp = getpwnam(username) ;

		if (pwp == (struct passwd *)NULL) {
			fprintf(stdout, "FAILED: [%s] does not exists.\n", username) ;
			exit(1) ;
		}
	
		spwd = getspnam(pwp->pw_name) ;

		if (spwd == (struct spwd *)NULL) {
			fprintf(stdout, "FAILED: unable to get (shadow) password for %s\n", username) ;
			exit(1) ;
		}
		else {
			char *gen = crypt(password,spwd->sp_pwdp) ;
			if (strcmp(spwd->sp_pwdp,gen) == 0) {
				fprintf(stdout, "OK:\n") ;
				exit(0);
			}
			else {
				fprintf(stdout, "FAILED: Password did not match.\n") ;
				exit(1) ;
			}
		}
	}
   exit(0);
}

