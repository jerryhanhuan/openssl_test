#ifndef __ASN1_INTERFACE__H
#define __ASN1_INTERFACE__H


#ifdef __cplusplus
extern "C"{
#endif

	int NumOid2Hex(const char *oid,unsigned char *encode,int *encode_len);

	int OidHex2Num(unsigned char *in,int inlen,char *out);




#ifdef __cplusplus
}
#endif





#endif




