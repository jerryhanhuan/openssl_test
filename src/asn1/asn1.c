#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>

#include "asn1.h"


/*

	0x02(INTEGER)
	0x03(BIT STRING)
	0x06(OBJECT IDENTIFIER)
	0x30(SEQUENCE)
	openssl 的 ASN1 函数
	new  用于生成一个新得数据结构
	free 释放该结构
	i2d  将该内部数据结构转换位der编码
	d2i  将der编码转换位内部数据结构
	i2a  将内部数据结构转为ASCII码
	a2i  将ASCII码转为内部数据结构
*/


/*
	Asn1EncodeOid: OID 编码为der 1.2.840.10045.2.12 ==> 0x(06072A8648CE3D020C)
	oid[in]: oid numerical form eg:1.2.840.10045.2.12
	encode[out]: oid der form eg: 06072A8648CE3D020C
	encode_len[out]:encode byte
*/

int Asn1EncodeOid(const char *oid,unsigned char *encode,int *encode_len)
{

	int ret = 0;
	int i = 0;
	int len = 0;
	ASN1_OBJECT obj;
	unsigned char *ptr = NULL;
	unsigned char *tmp = NULL;
	if ((len = a2d_ASN1_OBJECT(NULL,0,oid,-1))<=0)
	{
		printf("get ASN.1 encode byte length failed at %s, line %d!\n", __FILE__, __LINE__);
		ret = -1;
		goto endfree;
	}
	ptr = (unsigned char *)malloc(len);
	if (!ptr)
	{
		printf("malloc failed at %s,line %d!\n",__FILE__,__LINE__);
		ret = -2;
		goto endfree;
	}
	if ((len = a2d_ASN1_OBJECT(ptr,len,oid,-1))<=0)
	{
		printf("get ASN.1 encode byte length failed at %s, line %d!\n", __FILE__, __LINE__);
		ret = -3;
		goto endfree;
	}
	obj.data = ptr;
	obj.length = len;

	tmp = encode;
	if ((ret = i2d_ASN1_OBJECT(&obj,&tmp))<=0)
	{
		 printf("ASN.1 encode OID failed at %s, line %d!\n", __FILE__, __LINE__);
		 ret = -4;
		 goto endfree;
	}
	*encode_len = ret;

endfree:
	if(ptr){
		free(ptr);
		ptr = NULL;
	}
	return ret;
}




/* 
	Asn1DecodeOid:OID der decode  to numerical 0x(06072A8648CE3D020C)==>"1.2.840.10045.2.12"
	in[in]: oid der  form eg:0x(06072A8648CE3D020C)
	inlen[in]: the byte of in
	out[out]: the oid numerical form 
	outlen[out]:the bytes of out
*/


int Asn1DecodeOid(unsigned char *in,int inlen,char *out,int *outlen)
{
	int ret = 0;
	int len = 0;
	ASN1_OBJECT *obj = NULL;
	unsigned char *ptr = NULL;
	char buf[1024] = {0};
	ptr = in;
	if ((obj = d2i_ASN1_OBJECT(NULL,(const unsigned char **)&ptr,inlen)) == NULL)
	{
		printf("in Asn1DecodeOid::d2i_ASN1_OBJECT failed at %s,line %d\n",__FILE__,__LINE__);
		ret = -1;
		goto endfree;
	}
	/*
		int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
		OBJ_obj2txt() converts the ASN1_OBJECT a into a textual representation.  The representation is written as a null terminated string to buf at most buf_len bytes are written, truncating the result if necessary.  The total
		amount of space required is returned. If no_name is 0 then if the object has a long or short name then that will be used, otherwise the numerical form will be used. If no_name is 1 then the numerical form will always be
		used.
	*/
	if ((ret = OBJ_obj2txt(buf,sizeof(buf),obj,-1))<=0)
	{
		printf("in Asn1DecodeOid::OBJ_obj2txt failed at %s,line %d\n",__FILE__,__LINE__);
		ret = -2;
		goto endfree;
	}
	*outlen = ret;
	memcpy(out,buf,ret);
	
endfree:
	if(obj)
	{
		ASN1_OBJECT_free(obj);
		obj = NULL;
	}
	return ret;
}



