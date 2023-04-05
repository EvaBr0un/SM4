#ifndef SM4
#define SM4

#include <stdio.h>
#include <dirent.h> 
#include <sys/stat.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>

typedef union
{	
	uint64_t halfs[2];
    	uint32_t words[4];
    	uint8_t bytes[16];
} vector128_t;

//BLOCK ENCRYPTION:

	uint32_t MixerSubstitutionT(uint32_t);

	uint32_t roundF(vector128_t*, uint32_t);

	uint32_t* roundKeysExpansion(vector128_t*);

	void encryptionBlock(vector128_t*, uint32_t *);

	void decryptionBlock(vector128_t*, uint32_t*);

//MODES:
	
	uint32_t getLen(FILE*);
	
	void reverseWord(vector128_t*, int);
	
	vector128_t* additionBLock(uint32_t, FILE*);

	int deadditionBLock(vector128_t*);

	void encryptionFileByECB(FILE*, FILE*, FILE*);

	void decryptionFileByECB(FILE*, FILE*, FILE*);
	
	void addOne(vector128_t*);

	void encryptionFileByCTR(FILE*, FILE*, FILE*);

	void decryptionFileByCTR(FILE*, FILE*, FILE*);

#endif