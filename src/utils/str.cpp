#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#ifndef WIN32
	#include <unistd.h>
#endif

#include "str.h"

char hextoasc(int hex)
{
	char ch = 0;
	hex &= 0x0f;
	if(hex<0x0a)
		ch = hex+'0';
	else
		ch = hex + 0x37;
	return ch;
}

char hexlowtoasc(int hex)
{
	char ch = 0;
	hex &= 0x0f;
	if(hex<0x0a)
		ch = hex+'0';
	else
		ch = hex + 0x37;
	return ch;

}

char hexhightoasc(int hex)
{
	char ch = 0;
	hex &= 0xf0;
	hex = hex>>4;
	if(hex<0x0a)
		ch = hex+'0';
	else
		ch = hex + 0x37;
	return ch;
}



char asctohex(char ch1,char ch2)
{
	char ch = 0;
	if(ch1 >= 'A')
		ch = (char)((ch1-0x37)<<4);
	else
		ch = (char)((ch1-'0')<<4);
	if(ch2 >= 'A')
		ch |= (ch2-0x37);
	else
		ch |= (ch2-'0');
	return ch;
}


int aschex_to_bcdhex(char *aschex,int len,char *bcdhex)
{
	int i,j = 0;
	if(len % 2 ==0)
		j = len/2;
	else
		j = len/2+1;
	for (i=0;i<j;i++)
	{
		bcdhex[i] = asctohex(aschex[2*i],aschex[2*i+1]);
	}
	return j;
}


int bcdhex_to_aschex(char *bcdhex,int len,char *aschex)
{
	int i = 0;
	for (i=0;i<len;i++)
	{
		aschex[2*i] = hexhightoasc(bcdhex[i]);
		aschex[2*i+1] = hexlowtoasc(bcdhex[i]);
	}
	return len*2;
}



int ToUpperCase(char *str)
{
	int	i = 0;

	while (str[i])
	{
		if ((str[i] >= 'a') && (str[i] <= 'z'))
			str[i] = str[i] + 'A' - 'a';
		i++;
	}
	return(0);
}



void XorData(unsigned char *a, unsigned char *b, int len, unsigned char *out)
{
	int	i = 0;

	for(i=0;i<len;i++)
	{
		*out = (*a)^(*b);
		a++;
		b++;
		out++;
	}
}


