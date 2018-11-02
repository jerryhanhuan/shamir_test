#ifndef SHAMIRS_SECRET_SHARING_H
#define SHAMIRS_SECRET_SHARING_H

#ifdef __cplusplus
extern "C" {
#endif
//输出的字符串中含有字母G，若需要转为HEX表示，则需要再转一次
/*
    secret[in]:key
    lenofsecret[in]:keylen
    n[in]:divide key parts
    t[in]:combined key parts
    shares[out]:out key,num match n
*/

int  GenerateShareKey(char * secret, int lenofsecret,int n, int t,char shares [][8192*2]) ;


/*
    shares[in]:share key
    t[in]:combined key parts
    secret[out]:combined key
*/
int  CombineKey(char shares [][8192*2],int t,char *secret);

#ifdef __cplusplus
}
#endif

#endif