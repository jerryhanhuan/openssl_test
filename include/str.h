#ifndef __STR_H 
#define __STR_H

#ifdef __cplusplus
extern "C" {
#endif


	int aschex_to_bcdhex(char *aschex,int len,char *bcdhex);

	int bcdhex_to_aschex(char *bcdhex,int len,char *aschex);

	int ToUpperCase(char *str);

	void XorData(unsigned char *a, unsigned char *b, int len, unsigned char *out);

#ifdef __cplusplus
}
#endif


#endif