#include "SM4.h"

uint32_t getLen(FILE* inputData){
    	int result;

    	fseek(inputData, 0, SEEK_END);

    	result = ftell(inputData);

    	fseek(inputData, 0, SEEK_SET);

    	return result;
}
void reverseWord(vector128_t* vec, int wordNum){
	
	uint32_t buf = 0;
	for (int i = 4*wordNum; i < 4*(wordNum + 1); i++){
		buf = (buf << 8) | vec->bytes[i];
	}

	vec->words[wordNum] = buf;
}

void reverseHalf(vector128_t* vec, int halfNum){
	
	uint64_t buf = 0;
	for (int i = 8*halfNum; i < 8*(halfNum + 1); i++){
		buf = (buf << 8) | vec->bytes[i];
	}

	vec->halfs[halfNum] = buf;
}
vector128_t* additionBLock(uint32_t blockSize, FILE* targetFile){

    	vector128_t* dataBlock = (vector128_t*)malloc(sizeof(vector128_t*));
	dataBlock->words[0], dataBlock->words[1], dataBlock->words[2], dataBlock->words[3] = 0;
	
	fread(&dataBlock->bytes, blockSize, 1, targetFile);  
	
    	dataBlock->words[blockSize/8] = ( (dataBlock->words[blockSize/8] << 8) | 0x80) << 8 * (3 - (blockSize % 4));

    	return dataBlock;

}
int deadditionBLock(vector128_t* dataBlock){	
	for(int i = 3; i >= 0; i--){
		for (int j = 0; j < 4; j++){
			if ( ((dataBlock->words[i] << 8*j) & 0xffffffff) == 0x80000000 ){
				
				if(dataBlock->words[i] == 0x80000000) return i*4;

				dataBlock->words[i] = (dataBlock->words[i] >> 32 - 8*j) & 0xffffffff;
		
				return i*4 + j;	
			}
		}
	}
	return 16;
}
void encryptionFileByECB(FILE* targetFile, FILE* cipherFile, FILE* masterKeysFile){

	vector128_t* dataBlock  = (vector128_t*)malloc(sizeof(vector128_t));
    	vector128_t* masterKeys = (vector128_t*)malloc(sizeof(vector128_t));
    	uint32_t*    roundKeys 	= (uint32_t*)malloc(sizeof(uint32_t) * 32);

	int 	       fLen 	= getLen(targetFile);
    	int    blocksNumber   	= fLen / 16;
	int lastBlockNumber 	= fLen % 16;

	fread(&masterKeys->halfs, 2, 8, masterKeysFile);
    	roundKeys = roundKeysExpansion(masterKeys);
	
    	for (int i = 0; i < blocksNumber; ++i){
		fread(&dataBlock->halfs, 2, 8, targetFile);
      
		for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);
        	encryptionBlock(dataBlock, roundKeys);
		for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);

	        fwrite(&dataBlock->halfs, 2, 8, cipherFile);

    	}
	if (lastBlockNumber != 0){
		
		dataBlock = additionBLock(lastBlockNumber, targetFile);

    		encryptionBlock(dataBlock, roundKeys);
		
		for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);
    		fwrite(&dataBlock->halfs, 2, 8, cipherFile);

	}
	free(masterKeys);	
	free(roundKeys);
	free(dataBlock);
}	
void decryptionFileByECB(FILE* targetFile, FILE* decryptedFile, FILE* masterKeysFile){
    	int fLen 	 	= getLen(targetFile);
    	int blocksNumber 	= fLen / 16;

    	vector128_t* masterKeys = (vector128_t*)malloc(sizeof(vector128_t));
    	uint32_t* roundKeys 	= (uint32_t*)malloc(sizeof(uint32_t) * 32);
    	vector128_t* dataBlock  = (vector128_t*)malloc(sizeof(vector128_t));

	fread(&masterKeys->halfs, 2, 8, masterKeysFile);
    	roundKeys = roundKeysExpansion(masterKeys);

    	for (int i = 0; i < blocksNumber-1; i++){

        	fread(&dataBlock->halfs, 2, 8, targetFile);

		for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);
        	decryptionBlock(dataBlock, roundKeys);
		for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);

        	fwrite(&dataBlock->halfs, 2, 8, decryptedFile);
		
    	}
	
       	fread(&dataBlock->halfs, 2, 8, targetFile);

	for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);
    	decryptionBlock(dataBlock, roundKeys);
	
	int ComletedBytesNum = deadditionBLock(dataBlock);
	
	if (ComletedBytesNum == 16){
		for (int i = 0; i < 4; i++) reverseWord(dataBlock, i);
	}
	fwrite(&dataBlock->bytes, ComletedBytesNum, 1, decryptedFile);
	free(masterKeys);	
	free(roundKeys);
	free(dataBlock);
}

void addOne(vector128_t*){


}

void encryptionFileByCTR(FILE* targetFile, FILE* cipherFile, FILE* masterKeysFile){

	vector128_t* masterKeys 	= (vector128_t*)malloc(sizeof(vector128_t)); 
	vector128_t* dataBlock 		= (vector128_t*)malloc(sizeof(vector128_t)); 
	vector128_t* gamma 		= (vector128_t*)malloc(sizeof(vector128_t)); 
	vector128_t* gamma_for_encrypt 	= (vector128_t*)malloc(sizeof(vector128_t));

	uint32_t* roundKeys 		= (uint32_t*)malloc(sizeof(uint32_t) * 32);
	int fLen 	    		= getLen(targetFile);
    	int blocksNumber    		= fLen / 16;
	int lastBlockNumber 		= fLen % 16;

	fread(&masterKeys->halfs, 2, 8, masterKeysFile);
    	roundKeys = roundKeysExpansion(masterKeys);
	
	gamma->halfs[1] = masterKeys->halfs[1];

	for (int i = 0; i < 2; i++) reverseHalf(gamma, i);
	for (int i = 0; i < 4; i++) reverseWord(gamma, i);
	encryptionBlock(gamma, roundKeys);
	for (int i = 0; i < 4; i++) reverseWord(gamma, i);
	for (int i = 0; i < 2; i++) reverseHalf(gamma, i);
			
	gamma->halfs[0] = 0;

	for (int i = 0; i < blocksNumber; ++i){
		gamma_for_encrypt->halfs[0] = gamma->halfs[0];
		gamma_for_encrypt->halfs[1] = gamma->halfs[1];

		for (int j = 0; j < 2; j++) reverseHalf(gamma_for_encrypt, j);
		for (int j = 0; j < 4; j++) reverseWord(gamma_for_encrypt, j);
		encryptionBlock(gamma_for_encrypt, roundKeys);
		for (int j = 0; j < 4; j++) reverseWord(gamma_for_encrypt, j);
		for (int j = 0; j < 2; j++) reverseHalf(gamma_for_encrypt, j);		
		
		fread(&dataBlock->halfs, 2, 8, targetFile); 
		
		gamma->halfs[0]++;
		
		for (int j = 0; j < 2; j++) reverseHalf(gamma_for_encrypt, j);
        	dataBlock->halfs[0] ^= gamma_for_encrypt->halfs[0];
		dataBlock->halfs[1] ^= gamma_for_encrypt->halfs[1];
		for (int j = 0; j < 2; j++) reverseHalf(gamma_for_encrypt, j);
	
	        fwrite(&dataBlock->halfs, 2, 8, cipherFile);
    	}

	for (int i = 0; i < 2; i++) reverseHalf(gamma, i);
    	for (int i = 0; i < 4; i++) reverseWord(gamma, i);
	encryptionBlock(gamma, roundKeys);
	for (int i = 0; i < 4; i++) reverseWord(gamma, i);
	for (int i = 0; i < 2; i++) reverseHalf(gamma, i);		
	
	fread(&dataBlock->bytes, lastBlockNumber, 1, targetFile);      

	gamma->halfs[0]++;
	
	for (int i = 0; i < lastBlockNumber; i++){
		dataBlock->bytes[i] ^= gamma->bytes[i];
	}

	fwrite(&dataBlock->bytes, lastBlockNumber, 1, cipherFile);

	free(roundKeys);   
	free(masterKeys);
	free(dataBlock);
	free(gamma);
	free(gamma_for_encrypt);
}
void decryptionFileByCTR(FILE* targetFile, FILE* decryptedFile, FILE* masterKeysFile){
	encryptionFileByCTR(targetFile, decryptedFile, masterKeysFile);

}
