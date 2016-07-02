#ifndef __SIGN_H__
#define __SIGN_H__


int verify(char *message, int len, char *n, char *e, char *signature);
char * sign(char *message, int len, char *n, char *d);


#endif
