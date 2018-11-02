#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include "shamir.h"


static int prime = 257;	



char* strtok_rr(char *str, const char *delim,char **nextp)
{
	char *ret;

	if (str == NULL)
	{
		str = *nextp;
	}

	if (str == NULL) {
		return NULL;
	}

	str += strspn(str, delim);

	if (*str == '\0')
	{
		return NULL;
	}

	ret = str;

	str += strcspn(str, delim);

	if (*str)
	{
		*str++ = '\0';
	}

	*nextp = str;

	return ret;
}

unsigned long mix(unsigned long a, unsigned long b, unsigned long c)
{
    a=a-b;  a=a-c;  a=a^(c >> 13);
    b=b-c;  b=b-a;  b=b^(a << 8);
    c=c-a;  c=c-b;  c=c^(b >> 13);
    a=a-b;  a=a-c;  a=a^(c >> 12);
    b=b-c;  b=b-a;  b=b^(a << 16);
    c=c-a;  c=c-b;  c=c^(b >> 5);
    a=a-b;  a=a-c;  a=a^(c >> 3);
    b=b-c;  b=b-a;  b=b^(a << 10);
    c=c-a;  c=c-b;  c=c^(b >> 15);
    return c;
}

int modular_exponentiation(int base,int exp,int mod)
{
    if (exp == 0)
        return 1;
	else if (exp%2 == 0) {
        int mysqrt = modular_exponentiation(base, exp/2, mod);
        return (mysqrt*mysqrt)%mod;
    }
    else
        return (base * modular_exponentiation(base, exp-1, mod))%mod;
}



/*
	split_number() -- Split a number into shares
	n = the number of shares
	t = threshold shares to recreate the number
*/

int * split_number(int number, int n, int t) {
	int * shares = (int *)malloc(sizeof(int)*n);

	int coef[t];
	int x;
	int i;

	coef[0] = number;

	for (i = 1; i < t; ++i)
	{
		/* Generate random coefficients -- use arc4random if available */
#if defined (HAVE_ARC4RANDOM)
		coef[i] = arc4random_uniform(prime - 1);
#else
		coef[i] = rand() % (prime - 1);
#endif
	}

	for (x = 0; x < n; ++x)
	{
		int y = coef[0];

		/* Calculate the shares */
		for (i = 1; i < t; ++i)
		{
			int temp = modular_exponentiation(x+1, i, prime);

			y = (y + (coef[i] * temp % prime)) % prime;
		}

		/* Sometimes we're getting negative numbers, and need to fix that */
		y = (y + prime) % prime;

		shares[x] = y;
	}

	return shares;
}

/*
	Math stuff
*/

int * gcdD(int a, int b) {
	int * xyz = (int *)malloc(sizeof(int) * 3);

	if (b == 0) {
		xyz[0] = a;
		xyz[1] = 1;
		xyz[2] = 0;
	} else {
		int n = floor(a/b);
		int c = a % b;
		int *r = gcdD(b,c);

		xyz[0] = r[0];
		xyz[1] = r[2];
		xyz[2] = r[1]-r[2]*n;

		free(r);
	}

	return xyz;
}


/*
	More math stuff
*/

int modInverse(int k) {
	k = k % prime;

	int r;
	int * xyz;

	if (k < 0) {
		xyz = gcdD(prime,-k);
		r = -xyz[2];
	} else {
		xyz = gcdD(prime, k);
		r = xyz[2];
	}

	free(xyz);

	return (prime + r) % prime;
}


/*
	join_shares() -- join some shares to retrieve the secret
	xy_pairs is array of int pairs, first is x, second is y
	n is number of pairs submitted
*/

int join_shares(int *xy_pairs, int n) {
	int secret = 0;
	long numerator;
	long denominator;
	long startposition;
	long nextposition;
	long value;
	int i;
	int j;

	for (i = 0; i < n; ++i)
	{
		numerator = 1;
		denominator = 1;
		for (j = 0; j < n; ++j)
		{
			if(i != j) {
				startposition = xy_pairs[i*2];
				nextposition = xy_pairs[j*2];
				numerator = (numerator * -nextposition) % prime;
				denominator = (denominator * (startposition - nextposition)) % prime;
				//fprintf(stderr, "Num: %lli\nDen: %lli\n", numerator, denominator);
			}
		}

		value = xy_pairs[i * 2 + 1];

		secret = (secret + (value * numerator * modInverse(denominator))) % prime;
	}

	/* Sometimes we're getting negative numbers, and need to fix that */
	secret = (secret + prime) % prime;

	return secret;
}


/*
	split_string() -- Divide a string into shares
	return an array of pointers to strings;
*/
#ifdef SHAMIR_HEX
char ** split_string(char * secret, int n, int t) {
	int len = strlen(secret);

	char ** shares = (char **)malloc (sizeof(char *) * n);
	int i;

	for (i = 0; i < n; ++i)
	{
		/* need two characters to encode each character */
		/* Need 4 character overhead for share # and quorum # */
		/* Additional 2 characters are for compatibility with:
		*/
		shares[i] = (char *) malloc(2*len + 6 + 1);

		sprintf(shares[i], "%02X%02XAA",(i+1),t);
	}

	/* Now, handle the secret */

	for (i = 0; i < len; ++i)
	{
		// fprintf(stderr, "char %c: %d\n", secret[i], (unsigned char) secret[i]);
		int letter = secret[i]; // - '0';

		if (letter < 0)
			letter = 256 + letter;


		int * chunks = split_number(letter, n, t);
		int j;

		for (j = 0; j < n; ++j)
		{
			if (chunks[j] == 256) {
				sprintf(shares[j] + 6+ i * 2, "G0");	/* Fake code */
			} else {
				sprintf(shares[j] + 6 + i * 2, "%02X", chunks[j]);				
			}
		}

		free(chunks);
	}

	return shares;
}
#else
char ** split_string(char * secret, int lenofsecret,int n, int t) {
	int len = lenofsecret;

	char ** shares = (char **)malloc (sizeof(char *) * n);
	int i;

	for (i = 0; i < n; ++i)
	{
		/* need two characters to encode each character */
		/* Need 4 character overhead for share # and quorum # */
		/* Additional 2 characters are for compatibility with:
		*/
		shares[i] = (char *) malloc(2*len + 6 + 1);

		sprintf(shares[i], "%02X%02XAA",(i+1),t);
	}

	/* Now, handle the secret */

	for (i = 0; i < len; ++i)
	{
		// fprintf(stderr, "char %c: %d\n", secret[i], (unsigned char) secret[i]);
		int letter = secret[i]; // - '0';

		if (letter < 0)
			letter = 256 + letter;


		int * chunks = split_number(letter, n, t);
		int j;

		for (j = 0; j < n; ++j)
		{
			if (chunks[j] == 256) {
				sprintf(shares[j] + 6+ i * 2, "G0");	/* Fake code */
		} else {
				sprintf(shares[j] + 6 + i * 2, "%02X", chunks[j]);				
			}
		}

		free(chunks);
	}

	return shares;
}
#endif

void free_string_shares(char ** shares, int n) {
	int i;

	for (i = 0; i < n; ++i)
	{
		free(shares[i]);
	}

	free(shares);
}

#ifdef SHAMIR_HEX
char * join_strings(char shares[][8192*2], int n) {
	/* TODO: Check if we have a quorum */

	if (n == 0)
		return NULL;

	int len =strlen(shares[0]);

	char * result = (char*)malloc(len + 1);
	char codon[3];
	codon[2] = '\0';	// Must terminate the string!

	int x[n];
	int i;
	int j;

	for (i = 0; i < n; ++i)
	{
		codon[0] = shares[i][0];
		codon[1] = shares[i][1];

		x[i] = strtol(codon, NULL, 16);
	}

	for (i = 0; i < len; ++i)
	{
		int *chunks = (int *)malloc(sizeof(int) * n  * 2);

		for (j = 0; j < n; ++j)
		{
			chunks[j*2] = x[j];

			codon[0] = shares[j][6 + i * 2];
			codon[1] = shares[j][6 + i * 2 + 1];

			if (memcmp(codon,"G0",2) == 0) {
				chunks[j*2 + 1] = 256;
			} else {
				chunks[j*2 + 1] = strtol(codon, NULL, 16);
			}
		}

		//unsigned char letter = join_shares(chunks, n);
		char letter = join_shares(chunks, n);

		free(chunks);

		// fprintf(stderr, "char %c: %d\n", letter, (unsigned char) letter);

		sprintf(result + i, "%c",letter);
	}

	return result;
}

#else
char * join_strings(char shares[][8192*2], int n,int *lenofsecret) {
	/* TODO: Check if we have a quorum */

	if (n == 0)
		return NULL;

	int len =strlen(shares[0]);

	char * result = (char*)malloc(len + 1);
	char codon[3];
	codon[2] = '\0';	// Must terminate the string!

	int x[n];
	int i;
	int j;

	for (i = 0; i < n; ++i)
	{
		codon[0] = shares[i][0];
		codon[1] = shares[i][1];

		x[i] = strtol(codon, NULL, 16);
	}

	for (i = 0; i < len; ++i)
	{
		int *chunks = (int *)malloc(sizeof(int) * n  * 2);

		for (j = 0; j < n; ++j)
		{
			chunks[j*2] = x[j];

			codon[0] = shares[j][6 + i * 2];
			codon[1] = shares[j][6 + i * 2 + 1];

			if (memcmp(codon,"G0",2) == 0) {
				chunks[j*2 + 1] = 256;
			} else {
				chunks[j*2 + 1] = strtol(codon, NULL, 16);
			}
		}

		//unsigned char letter = join_shares(chunks, n);
		char letter = join_shares(chunks, n);

		free(chunks);

		// fprintf(stderr, "char %c: %d\n", letter, (unsigned char) letter);
		
		result[i] = letter;
	}
	*lenofsecret = (len-6)/2;	//输出的字符串长度为2len+6
	return result;
}
#endif

#ifdef SHAMIR_HEX
int  GenerateShareKey(char * secret, int n, int t,char shares [][8192*2]) {

	char ** result = split_string(secret, n, t);
	int i;
	for(i=0;i<n;i++)
	{
		strcpy(shares[i],result[i]);
	}
	free_string_shares(result, n);
	return 0;	
}
#else
int  GenerateShareKey(char * secret, int lenofsecret,int n, int t,char shares [][8192*2]) {

	char ** result = split_string(secret, lenofsecret,n, t);
	int i;
	for(i=0;i<n;i++)
	{
		strcpy(shares[i],result[i]);
	}
	free_string_shares(result, n);
	return 0;	
}
#endif

#ifdef SHAMIR_HEX
int CombineKey(char shares [][8192*2],int t,char *secret)
{
	char * ptr = join_strings(shares,t);
	strcpy(secret,ptr);
	if(ptr)
		free(ptr);
	return 0;
}
#else
int CombineKey(char shares [][8192*2],int t,char *secret)
{
	int lenofsecret = 0;
	char * ptr = join_strings(shares,t,&lenofsecret);
	memcpy(secret,ptr,lenofsecret);
	if(ptr)
		free(ptr);
	return lenofsecret;
}
#endif


#if 0
int main(int argc, char **argv)
{
	if(argc<2)
	{
		printf("usage key .\n");
		return -1;
	}
	int ret=0;
	char keyHex[8192]={0};
	strcpy(keyHex,argv[1]);
	int n=3;
	int t=2;
	char shares[3][8192*2]={0};
	GenerateShareKey(keyHex, n, t,shares);
	int i=0;
	for (i=0;i<n;i++)
	{
		printf("%s .\n",shares[i]);
	}
	
	char secret[8192]={0};

	
	 CombineKey(shares,t,secret);
	 fprintf(stdout, "%s\n", secret);
	
	
	return 0;
		
}


#endif



