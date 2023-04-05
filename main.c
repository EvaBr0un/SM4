#include "SM4.h"

int checkName(char* inputDataName, char* keyName){
	FILE *k, *in;
	DIR *di;

	if ((k = fopen(keyName, "rb")) == NULL){
		printf("\033[41mIncorrect input key!!!\033[0m");
		fclose(k);
  	      	exit(-1);
	}
	if ((di = opendir(inputDataName)) != NULL){
		printf("\033[41mDirectory %s was\033[0m", inputDataName);
		closedir(di);
		return 0;
	}
	if ((in = fopen(inputDataName, "rb")) != NULL){
		printf("\033[41mFile %s was\033[0m", inputDataName);
		fclose(in);
  	      	return 1;
	}
	else{
		exit(-1);
		printf("\033[31m;1;42m Incorrect input data!!! \033[0m\n");
	}
}

void SM_4(int flag, FILE* in, FILE* out, FILE* key){
	switch (flag){
		case 1: 
			printf("\033[41m encrypted with SM4 algorithm with ECB encryption regime.\033[0m\n\n");
			encryptionFileByECB(in, out, key);
			break;
		case 2: 
			printf("\033[41m encrypted with SM4 algorithm with CTR encryption regime.\033[0m\n\n");
			encryptionFileByCTR(in, out, key);
			break;
		case 3: 
			printf("\033[41m decrypted with SM4 algorithm with ECB encryption regime.\033[0m\n\n");
			decryptionFileByECB(in, out, key);
			break;
		case 4: 
			printf("\033[41m decrypted with SM4 algorithm with CTR encryption regime.\033[0m\n\n");
			decryptionFileByCTR(in, out, key);
			break;
	
	}
	printf("\033[37;1;42m Completed!\033[0m \n");
}

void dir_handler(int flag, char* d_name, char* keyName){
	int nameLen = strlen(d_name);

	char* outfName = (char*)malloc(nameLen + 5); 		
	strcpy(outfName, d_name); strcat(outfName, ".sm4"); 		
	
	char* pname = (char*)malloc(13 + 2*nameLen); 		
	strcpy(pname, "tar -cf "); strcat(pname, outfName); pname[12 + nameLen] = 0x20; strcat(pname, d_name);

	FILE *tar = popen(pname, "r");
	pclose(tar);
	
	FILE * in = fopen(outfName, "rb");
	FILE * key = fopen(keyName, "rb");
	
	outfName[nameLen + 4] = 'd';
	outfName[nameLen + 5] = '\0';

	FILE * out = fopen(outfName, "wb");

	SM_4(flag, in, out, key);
	
	outfName[nameLen] = '\0';
	remove(outfName);

	free(pname);
	free(outfName);
	fclose(out);
	fclose(in);
	fclose(key);
}

void fhandler(int flag, char* fname, char* keyName){
	FILE * in = fopen(fname, "rb");
	FILE * key = fopen(keyName, "rb");
	FILE *out;
	char* outfName;
	int nameLen = strlen(fname);	

	if ( (fname[nameLen-1] == 'd') && (flag > 2) ){
		char* decrfName = (char*)malloc(nameLen-1);
		strncpy(decrfName, fname, nameLen-1);

		outfName = (char*)malloc(nameLen-5);
		strncpy(outfName, fname, nameLen-5);

		out = fopen(decrfName, "wb");
		SM_4(flag, in, out, key);

		char* pname = (char*)malloc(3 + 2*nameLen);
		strcpy(pname, "tar -xf "); strcat(pname, decrfName); pname[7 + nameLen] = 0x20; strcat(pname, outfName);
		
		FILE *tar = popen(pname, "r");
		pclose(tar);
		
		remove(decrfName);
		free(pname);
	}
	else if (flag < 3){	
		outfName = (char*)malloc(sizeof(char)*(nameLen+5));
		strcpy(outfName, fname);

		outfName[nameLen+4] = '\0'; outfName[nameLen+3] = '4'; outfName[nameLen+2] = 'm'; outfName[nameLen+1] = 's'; outfName[nameLen] = '.';
		out = fopen(outfName, "wb");

		SM_4(flag, in, out, key);
	}
	else{
		outfName = (char*)malloc(sizeof(char)*(nameLen-4));

		out = fopen(strncpy(outfName, fname, nameLen-4), "wb");

		SM_4(flag, in, out, key);
	}
	free(outfName);
	fclose(out);
	fclose(in);
	fclose(key);
	
}

void base_handler(char* mode, char* reg,  char *inputDataName, char* keyName){
	int flag = 0;
	if(strcmp(mode, "-e") == 0){
		if (strcmp(reg, "-ecb") == 0){
			flag = 1;
		}
		else if (strcmp(reg, "-ctr") == 0){
			flag = 2;
	}	}
	else if(strcmp(mode, "-d") == 0){
		if (strcmp(reg, "-ecb") == 0){
			flag = 3;
		}
		else if (strcmp(reg, "-ctr") == 0){
			flag = 4;
		}
	}
	else{ 
	 	printf("Incorrect args!\n");
		exit(-1);
	}	

	int dataType = checkName(inputDataName, keyName);

	if (dataType) fhandler(flag, inputDataName, keyName);  
	else if (!dataType) dir_handler(flag, inputDataName, keyName);  
}

int main(int argc, char* argv[]){
	
	if (argc == 5){		
		base_handler(argv[1], argv[2], argv[3], argv[4]);	
	}
	else{
	   	printf("Error! Not enough arguments\n");
		return -1;
	}

	return 0;
}