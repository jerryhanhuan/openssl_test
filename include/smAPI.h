#ifndef __SM_API_H
#define  __SM_API_H


#ifdef __cplusplus
extern "C"{
#endif




	int SoftSM4EncryptWithECB(unsigned char *key,unsigned char *data,int datalen,unsigned char *out);

	int SoftSM4DecryptWithECB(unsigned char *key,unsigned char *data,int datalen,unsigned char *out);

	int SoftSM4EncryptWithCBC(unsigned char *key,unsigned char *iv,unsigned char *data,int datalen,unsigned char *out);

	int SoftSM4DecryptWithCBC(unsigned char *key,unsigned char *iv,unsigned char *data,int datalen,unsigned char *out);



	int SoftSM3(unsigned char *input,int ilen,unsigned char *out);

	int SoftHMAC_SM3(unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *hmacVal);


	int SoftHMAC_SM32(unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *hmacVal);




#ifdef __cplusplus
}
#endif

#endif