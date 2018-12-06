#ifndef __DES_INTERFACE__H
#define __DES_INTERFACE__H


#ifdef __cplusplus
extern "C"{
#endif

int TDESEncryptWithECB(unsigned char *key, int keylen,unsigned char *data,int datalen,unsigned char *outdata);


int TDESDecryptWithECB(unsigned char *key, int keylen,unsigned char *data,int datalen,unsigned char *outdata);







#ifdef __cplusplus
}
#endif





#endif
