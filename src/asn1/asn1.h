#ifndef __T_ASN1__H
#define __T_ASN1__H


#ifdef __cplusplus
extern "C"{
#endif


/*
	Asn1EncodeOid: OID 编码为der 1.2.840.10045.2.12 ==> 0x(06072A8648CE3D020C)
	oid[in]: oid numerical form eg:1.2.840.10045.2.12
	encode[out]: oid der form eg: 06072A8648CE3D020C
	encode_len[out]:encode byte
*/

int Asn1EncodeOid(const char *oid,unsigned char *encode,int *encode_len);


/* 
	Asn1DecodeOid:OID der decode  to numerical 0x(06072A8648CE3D020C)==>"1.2.840.10045.2.12"
	in[in]: oid der  form eg:0x(06072A8648CE3D020C)
	inlen[in]: the byte of in
	out[out]: the oid numerical form 
	outlen[out]:the bytes of out
*/


int Asn1DecodeOid(unsigned char *in,int inlen,char *out,int *outlen);





#ifdef __cplusplus
}
#endif

#endif


