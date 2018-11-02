#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<errno.h>
#include "shamir.h"


char hextoasc(int xxc)
{
    xxc&=0x0f;
    if (xxc<0x0a) xxc+='0';
    else xxc+=0x37;
    return (char)xxc;
}

char hexlowtoasc(int xxc)
{
    xxc&=0x0f;
    if (xxc<0x0a) xxc+='0';
    else xxc+=0x37;
    return (char)xxc;
}

char hexhightoasc(int xxc)
{
    xxc&=0xf0;
    xxc = xxc>>4;
    if (xxc<0x0a) xxc+='0';
    else xxc+=0x37;
    return (char)xxc;
}

char asctohex(char ch1,char ch2)
{
    char ch;
    if (ch1>='A') ch=(char )((ch1-0x37)<<4);
    else ch=(char)((ch1-'0')<<4);
    if (ch2>='A') ch|=ch2-0x37;
    else ch|=ch2-'0';
    return ch;
}
 
int aschex_to_bcdhex(char aschex[],int len,char bcdhex[])
{
    int i,j;

	if (len % 2 == 0)
		j = len / 2;
	else
		j = len / 2 + 1;

    for (i = 0; i < j; i++)
        bcdhex[i] = asctohex(aschex[2*i],aschex[2*i+1]);

    return(j);
}

int bcdhex_to_aschex(char bcdhex[],int len,char aschex[])
{
    int i;

    for (i=0;i<len;i++)
    {
        aschex[2*i]   = hexhightoasc(bcdhex[i]);
        aschex[2*i+1] = hexlowtoasc(bcdhex[i]);
    }

    return(len*2);
}


int main(int argc,char **argv)
{
    if(argc<4)
    {
        printf("usage with key\n");
        return -1;
    }
    char keyHex[128]={0};
    strcpy(keyHex,argv[1]);
    int n=5;
    int t=3;
    char key[64]={0};
    char sharekey[5][1024]={0};
    int keylen = 0;
   // int keylen = aschex_to_bcdhex(keyHex,strlen(keyHex),(char*)key);
    keylen = strlen(keyHex);
    GenerateShareKey(keyHex,keylen,n,t,sharekey);
    int i = 0;

    for(i=0;i<n;i++)
    {
        printf("%s\n",sharekey[i]);
    }
    char combinedKey[64]={0};
    CombineKey(sharekey,t,combinedKey);
    printf("key::%s\n",combinedKey);
    return 0;
}


