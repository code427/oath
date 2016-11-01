#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oauth.h>

/**
 * split and parse URL parameters replied by the test-server
 * into <em>oauth_token</em> and <em>oauth_token_secret</em>.
 */
int parse_reply(const char *reply, char **token, char **secret) {
  int rc;
  int ok=1;
  char **rv = NULL;
  rc = oauth_split_url_parameters(reply, &rv);
  qsort(rv, rc, sizeof(char *), oauth_cmpstringp);
  if( rc==2 
      && !strncmp(rv[0],"oauth_token=",11)
      && !strncmp(rv[1],"oauth_token_secret=",18) ) {
    ok=0;
    if (token)  *token =strdup(&(rv[0][12]));
    if (secret) *secret=strdup(&(rv[1][19]));
    printf("	key:    '%s'\n	secret: '%s'\n",*token, *secret); // XXX token&secret may be NULL.
  }
  if(rv) free(rv);
  return ok;
}

/** 
 * an example requesting a request-token from an OAuth service-provider
 * exchaning it with an access token
 * and make an example request.
 * exercising either the oauth-HTTP GET or POST function.
 */
int oauth_consumer_example(int use_post) {
  const char *request_token_uri = "http://term.ie/oauth/example/request_token.php";
  const char *access_token_uri = "http://term.ie/oauth/example/access_token.php";
  const char *test_call_uri = "http://term.ie/oauth/example/echo_api.php?method=foo%20bar&bar=baz";
  const char *c_key         = "key"; //< consumer key
  const char *c_secret      = "secret"; //< consumer secret

  char *t_key    = NULL; //< access token key
  char *t_secret = NULL; //< access token secret

  char *req_url = NULL;
  char *postarg = NULL;
  char *reply   = NULL;

  printf("Step 1: Terminal Request token, send request to OAuth Server..\n");
	sleep(1);
	printf("Step 2: OAuth Server got request, then requesting credential from authorizer..\n");
	sleep(1);
	printf("Step 3: Authorizer provides the following credential to OAuth Server.. \n");
  if (use_post) { // HTTP POST 
    req_url = oauth_sign_url2(request_token_uri, &postarg, OA_HMAC, NULL, c_key, c_secret, NULL, NULL);
    reply = oauth_http_post(req_url,postarg);
  } else { // HTTP GET
    req_url = oauth_sign_url2(request_token_uri, NULL, OA_HMAC, NULL, c_key, c_secret, NULL, NULL);
    reply = oauth_http_get(req_url,postarg);
  }
  if (req_url) free(req_url);
  if (postarg) free(postarg);
  if (!reply) return(1);
  if (parse_reply(reply, &t_key, &t_secret)) return(2);
  free(reply);

  // The Request Token provided above is already authorized, for this test server
  // so we may use it to request an Access Token right away.
	sleep(1);
printf("Step 4: OAuth Server got the credential, and performs verification..\n");
sleep(1);  
printf("Step 5: Verification Success, OAuth Server Grant the following Access token to Terminal..\n");

  if (use_post) {
    req_url = oauth_sign_url2(access_token_uri, &postarg, OA_HMAC, NULL, c_key, c_secret, t_key, t_secret);
    reply = oauth_http_post(req_url,postarg);
  } else {
    req_url = oauth_sign_url2(access_token_uri, NULL, OA_HMAC, NULL, c_key, c_secret, t_key, t_secret);
    reply = oauth_http_get(req_url,postarg);
  }
  if (req_url) free(req_url);
  if (postarg) free(postarg);
  if (!reply) return(3);
  if(t_key) free(t_key);
  if(t_secret) free(t_secret);
  if (parse_reply(reply, &t_key, &t_secret)) return(4);
  free(reply);
sleep(1);

  printf("Step 6: Terminal got the Token, and use the Token to make some request to Cloud Server..\n");

  if (use_post) {
    req_url = oauth_sign_url2(test_call_uri, &postarg, OA_HMAC, NULL, c_key, c_secret, t_key, t_secret);
    reply = oauth_http_post(req_url,postarg);
  } else {
    req_url = oauth_sign_url2(test_call_uri, NULL, OA_HMAC, NULL, c_key, c_secret, t_key, t_secret);
    reply = oauth_http_get(req_url,postarg);
  }
  printf("	query:'%s'\n",req_url);
   if(req_url) free(req_url);
  if(postarg) free(postarg);
sleep(1);
printf("Step 7: The Cloud Server got the request, along with the Token..\n");
printf("Step 8: The Cloud Server send the Token to OAuth for verification..\n");
printf("Step 9: OAuth Server got Token, and verify it is authentic, send the verfication result back to Cloud Server..\n");
printf("	In this case, If the Cloud Server got the verification, it will reply the same value as we send out in the request..\n");

  if (strcmp(reply,"bar=baz&method=foo+bar")) return (5);

sleep(1);
printf("Step 10: Cloud Server receives the results, the identity of the Terminal is verified.. \n");
printf("	reply:'%s'\n",reply);
 
  if(reply) free(reply);
  if(t_key) free(t_key);
  if(t_secret) free(t_secret);

  return(0);
}


/**
 * Main Test and Example Code.
 * 
 * compile:
 *  gcc -lssl -loauth -o oauthexample oauthexample.c
 */

int main (int argc, char **argv) {
  switch(oauth_consumer_example(0)) {
    case 1:
      printf("HTTP request for an oauth request-token failed.\n");
      break;
    case 2:
      printf("did not receive a request-token.\n");
      break;
    case 3:
      printf("HTTP request for an oauth access-token failed.\n");
      break;
    case 4:
      printf("did not receive an access-token.\n");
      break;
    case 5:
      printf("test call 'echo-api' did not respond correctly.\n");
      break;
    default:
      printf("	request ok.\n");
	sleep(1);
	printf("	In the future, whenver terminal communicate with Cloud Server, it reuses the Token to performs Step 6 - Step 10\n 	Unless it need to Update the Token\n"); 
      break;
  }
  return(0);
}
