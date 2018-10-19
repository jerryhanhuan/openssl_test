#ifndef __SM_API_H
#define  __SM_API_H


#ifdef __cplusplus
extern "C"{
#endif


	int SoftSM3(unsigned char *input,int ilen,unsigned char *out);

	int SoftHMAC_SM3(unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *hmacVal);


	int SoftHMAC_SM32(unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *hmacVal);




#ifdef __cplusplus
}
#endif

#endif