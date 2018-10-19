#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smAPI.h"
#include "sm3.h"
#include "str.h"


int SoftSM3(unsigned char *input,int ilen,unsigned char *out)
{
	sm3(input,ilen,out);
	return 32;
}


/*
Function hmac
Inputs:
key:        Bytes     //array of bytes
message:    Bytes     //array of bytes to be hashed
hash:       Function  //the hash function to use (e.g. SHA-1)
blockSize:  Integer   //the block size of the underlying hash function (e.g. 64 bytes for SM3)
outputSize: Integer   //the output size of the underlying hash function (e.g. 32 bytes for SM3)

//Keys longer than blockSize are shortened by hashing them
if (length(key) > blockSize) then
	key ¡û hash(key) //Key becomes outputSize bytes long

//Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
if (length(key) < blockSize) then
	key ¡û Pad(key, blockSize) //pad key with zeros to make it blockSize bytes long

o_key_pad = key xor [0x5c * blockSize]     //Outer padded key
i_key_pad = key xor [0x36 * blockSize]    //Inner padded key

return hash(o_key_pad || hash(i_key_pad||  message)) //Where || is concatenation
*/

int SoftHMAC_SM3(unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *hmacVal)
{
	int ret = 0;
	unsigned char keybuf[128]={0};
	int tlen = 0;
	int block_size = 64;
	int outsize = 32;
	unsigned char buf[128]={0};
	unsigned char tmp[32]={0};

	if (keylen > block_size)
	{
		tlen = SoftSM3(key,keylen,keybuf);
	}else{
		memcpy(keybuf,key,keylen);
		tlen = block_size;
	}
	unsigned char opad[128]={0};
	unsigned char ipad[128]={0};
	unsigned char o_key_pad[128]={0};
	unsigned char i_key_pad[128]={0};
	memset(opad,0x5c,block_size);
	memset(ipad,0x36,block_size);

	XorData(keybuf,opad,block_size,o_key_pad);
	XorData(keybuf,ipad,block_size,i_key_pad);

	sm3_context ctx;
	sm3_starts( &ctx );
	sm3_update(&ctx,i_key_pad,block_size);
	sm3_update(&ctx,data,datalen);
	sm3_finish(&ctx,tmp);

	memset(&ctx,0,sizeof(ctx));
	memset(buf,0,sizeof(buf));
	sm3_starts(&ctx);
	sm3_update(&ctx,o_key_pad,block_size);
	sm3_update(&ctx,tmp,outsize);
	sm3_finish(&ctx,buf);

	memcpy(hmacVal,buf,outsize);
	return outsize;
}


int SoftHMAC_SM32(unsigned char *key,int keylen,unsigned char *data,int datalen,unsigned char *hmacVal)
{
	sm3_hmac(key,keylen,data,datalen,hmacVal);
	return 32;
}