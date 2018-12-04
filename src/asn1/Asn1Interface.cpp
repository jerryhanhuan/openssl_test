#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif


#include "str.h"
#include "asn1.h"
#include "Asn1Interface.h"


int NumOid2Hex(const char *oid,unsigned char *encode,int *encode_len)
{
	return Asn1EncodeOid(oid,encode,encode_len);
}

int OidHex2Num(unsigned char *in,int inlen,char *out)
{
	int len =0;
	return Asn1DecodeOid(in,inlen,out,&len);
}
