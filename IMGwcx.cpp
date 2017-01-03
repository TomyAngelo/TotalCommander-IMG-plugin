
#include "stdafx.h"
#include "wcxhead.h"
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#define BLOCK_SIZE 16
#define SECTOR_SIZE 512
#define SECTOR_SHIFT 9

// The DLL entry point

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
	return TRUE;
}

//----------------IMG Definitions-------------

typedef struct
{ 
	char archname[MAX_PATH]; 
	HANDLE hArchFile; 

	tChangeVolProc pLocChangeVol;
	tProcessDataProc pLocProcessData;
} tArchive;

typedef tArchive *myHANDLE;

//--------End of  IMG Definitions-------------

//------------------=[ Global Varailables ]=-------------

tChangeVolProc pGlobChangeVol;
tProcessDataProc pGlobProcessData;


static int int_log2(unsigned int x)
{
	int r = 0;
	for (x >>= 1; x > 0; x >>= 1)
		r++;
	return r;
}

void increaseVector32(unsigned char * initialVector, int sector) {
	for (int i = 0; i != BLOCK_SIZE / 2 - 1; ++i) {
		initialVector[i] = sector & 0xFF;
		sector = sector >> 8;
	}
}

void increaseVector64(unsigned char * initialVector, int sector) {
	for (int i = 0; i != BLOCK_SIZE - 1; ++i) {
		initialVector[i] = sector & 0xFF;
		sector = sector >> 8;
	}
}

void setBenbiIV(unsigned char * initialVector, int sector) {
	for (int i = BLOCK_SIZE - 1; i != 0; --i) {
		initialVector[i] = sector & 0xFF;
		sector = sector >> 8;
	}
}

void SHA256hashing(unsigned char * keyStr, int size, AES_KEY *key_hash) {
	unsigned char hash_key[2 * BLOCK_SIZE];
	SHA256_CTX sha_key;
	SHA256_Init(&sha_key);
	SHA256_Update(&sha_key, keyStr, size);
	SHA256_Final(hash_key, &sha_key);
	AES_set_encrypt_key(hash_key, 256, key_hash);
}

int loadKey(unsigned char* key, char* keyFile, int size) {
	FILE * file_key = fopen(keyFile, "rb");
	if (file_key == NULL) {
		return E_EOPEN;
	}
	if (fread(key, size, 1, file_key) != 1) {
		return E_EREAD;
	}	

	fclose(file_key);	
	return 0;
}

bool loadParameters(char * pathToParameters, char* keyPath, char* encryption, char* mode, char* vector, int* from, int* to) {
	FILE * file = fopen(pathToParameters, "r");
	if (file == NULL) return false;

	char string[256];
	memset(string, 0, 256);
	fgets(string, 256, file);
	string[strlen(string) -1] = '\0';
	strcpy(keyPath, string);

	memset(string, 0, 256);
	fgets(string, 256, file);
	if (strlen(string) != 2) return false;
	string[strlen(string) -1] = '\0';
	strncpy(encryption, string, 1);

	memset(string, 0, 256);
	fgets(string, 256, file);
	if (strlen(string) != 4) return false;
	string[strlen(string) -1] = '\0';
	strncpy(mode, string,3);

	memset(string, 0, 256);
	fgets(string, 256, file);
	if (strlen(string) != 5 && strlen(string) != 6 && strlen(string) != 8) return false;
	string[strlen(string) -1] = '\0';
	strncpy(vector, string,7);

	memset(string, 0, 256);
	fgets(string, 256, file);
	string[strlen(string) -1] = '\0';
	*from = atoi(string);

	memset(string, 0, 256);
	fgets(string, 256, file);
	string[strlen(string) -1] = '\0';
	*to = atoi(string);
	
	fclose(file);
	return true;
}

void setInitialVector(char * nameOfIV, unsigned char * initialVector, int sector, AES_KEY *key_hash, int benbi_shift) {
	if (strcmp(nameOfIV, "plain") == 0) {
		memset(initialVector, 0, BLOCK_SIZE / 2);
	}
	else {
		memset(initialVector, 0, BLOCK_SIZE);
	}

	if (strcmp(nameOfIV, "plain") == 0) {
		increaseVector32(initialVector, sector);
	}
	if (strcmp(nameOfIV, "plain64") == 0) {
		increaseVector64(initialVector, sector);
	}
	if (strcmp(nameOfIV, "essiv") == 0) {
		increaseVector64(initialVector, sector);
		AES_ecb_encrypt(initialVector, initialVector, key_hash, AES_ENCRYPT);
	}
	if (strcmp(nameOfIV, "benbi") == 0) {
		setBenbiIV(initialVector, (sector << benbi_shift) + 1);
	}
}

int cbcEncryption(HANDLE inputFile, HANDLE output, unsigned char* keyStr, char enc, char *iv, int sizeFrom, int sizeTo) {
	unsigned char *block = (unsigned char*)malloc(SECTOR_SIZE);
	unsigned char *out_block = (unsigned char*)malloc(SECTOR_SIZE);
	unsigned char* initialVector;

	if (strcmp(iv, "plain") == 0) {
		initialVector = (unsigned char*)malloc(BLOCK_SIZE / 2);
		memset(initialVector, 0, BLOCK_SIZE / 2);
	}
	else {
		initialVector = (unsigned char*)malloc(BLOCK_SIZE);
		memset(initialVector, 0, BLOCK_SIZE);
	}

	AES_KEY key;
	AES_KEY key_hash;

	if (enc == 'e') {
		AES_set_encrypt_key(keyStr, 256, &key);
	}
	if (enc == 'd') {
		AES_set_decrypt_key(keyStr, 256, &key);
	}

	if (strcmp(iv, "essiv") == 0) {
		SHA256hashing(keyStr, 2 * BLOCK_SIZE, &key_hash);
	}
	int benbi_shift=0;
	if (strcmp(iv, "benbi") == 0) {
		int log = int_log2(BLOCK_SIZE);
		if (log > SECTOR_SHIFT) {
			return E_BAD_DATA;
		}
		benbi_shift = SECTOR_SHIFT - log;
	}
	int sector = 0;
	DWORD numberOfBytes;
	while (sector < sizeFrom) {
		ReadFile(inputFile, block, SECTOR_SIZE, &numberOfBytes, NULL);
		++sector;
	}

	setInitialVector(iv, initialVector, sector, &key_hash, benbi_shift);
	while (ReadFile(inputFile, block, SECTOR_SIZE, &numberOfBytes, NULL) != 0 && numberOfBytes == SECTOR_SIZE ) {

		setInitialVector(iv, initialVector, sector, &key_hash, benbi_shift);

		if (enc == 'e') {
			AES_cbc_encrypt(block, out_block, SECTOR_SIZE, &key, initialVector, AES_ENCRYPT);
		}
		else if (enc == 'd') {
			AES_cbc_encrypt(block, out_block, SECTOR_SIZE, &key, initialVector, AES_DECRYPT);
		}
		
		if (WriteFile(output, out_block, SECTOR_SIZE, &numberOfBytes, 0) != true) break;
		++sector;
		if (sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;

	}
	free(block);
	free(out_block);
	free(initialVector);
	CloseHandle(output);
	return 0;
}

int xtsEncryption(HANDLE inputFile, HANDLE output, unsigned char* keyStr, char enc, char *iv, int sizeFrom, int sizeTo) {
	unsigned char *block = (unsigned char*)malloc(SECTOR_SIZE);
	unsigned char *out_block = (unsigned char*)malloc(SECTOR_SIZE);
	unsigned char* initialVector;

	if (strcmp(iv, "plain") == 0) {
		initialVector = (unsigned char*)malloc(BLOCK_SIZE / 2);
		memset(initialVector, 0, BLOCK_SIZE / 2);
	}
	else {
		initialVector = (unsigned char*)malloc(BLOCK_SIZE);
		memset(initialVector, 0, BLOCK_SIZE);
	}

	AES_KEY key_hash;
	if (strcmp(iv, "essiv") == 0) {
		SHA256hashing(keyStr, 2 * BLOCK_SIZE, &key_hash);
	}

	int benbi_shift=0;
	if (strcmp(iv, "benbi") == 0) {
		int log = int_log2(BLOCK_SIZE);
		if (log > SECTOR_SHIFT) {
			return E_BAD_DATA;
		}
		benbi_shift = SECTOR_SHIFT - log;
	}

	EVP_CIPHER_CTX *ctx;
	int len;

	int sector = 0;
	DWORD numberOfBytes;
	while (sector < sizeFrom) {
		ReadFile(inputFile, block, SECTOR_SIZE, &numberOfBytes, NULL);
		++sector;
	}

	setInitialVector(iv, initialVector, sector, &key_hash, benbi_shift);

	while (ReadFile(inputFile, block, SECTOR_SIZE, &numberOfBytes, NULL) != 0 && numberOfBytes == SECTOR_SIZE) {
		ctx = EVP_CIPHER_CTX_new();

		setInitialVector(iv, initialVector, sector, &key_hash, benbi_shift);
		if (enc == 'e') {
			EVP_EncryptInit(ctx, EVP_aes_128_xts(), keyStr, initialVector);
			EVP_EncryptUpdate(ctx, out_block, &len, block, SECTOR_SIZE);
			EVP_EncryptFinal(ctx, out_block + len, &len);
		}
		else if (enc == 'd') {
			EVP_DecryptInit(ctx, EVP_aes_128_xts(), keyStr, initialVector);
			EVP_DecryptUpdate(ctx, out_block, &len, block, SECTOR_SIZE);
			EVP_DecryptFinal(ctx, out_block + len, &len);
		}
		if (WriteFile(output, out_block, SECTOR_SIZE, &numberOfBytes, 0) != true) break;

		++sector;
		if (sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;
	}

	EVP_CIPHER_CTX_free(ctx);
	free(initialVector);
	free(block);
	free(out_block);
	return 0;
}



// OpenArchive by mala vykonat vsetky potrebne operacie ked ma byt archiv otvoreny
myHANDLE __stdcall OpenArchive(tOpenArchiveData *ArchiveData)
{	
	tArchive *arch = NULL;

	ArchiveData->CmtBuf = 0;
	ArchiveData->CmtBufSize = 0;
	ArchiveData->CmtSize = 0;
	ArchiveData->CmtState = 0;

	ArchiveData->OpenResult = E_NO_MEMORY; 
	if ((arch = new tArchive) == NULL)
	{
		return NULL;
	}

	memset(arch, 0, sizeof(tArchive));
	strcpy(arch->archname, ArchiveData->ArcName);
	arch->hArchFile = CreateFile(arch->archname, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	if (!arch->hArchFile || arch->hArchFile == INVALID_HANDLE_VALUE) {
		delete arch;
		return NULL;
	}

	ArchiveData->OpenResult = 0;// ok
	return arch;
}

// Total Commander vola ReadHeader aby zistil ake subory sa nachadzaju v archive
int __stdcall ReadHeader(myHANDLE hArcData, tHeaderData *HeaderData)
{	
	if (!hArcData || !HeaderData) {
		return E_BAD_DATA;
	}
	tArchive *arch = (tArchive *)(hArcData);

	char path[256] = "";
	strcpy(path, arch->archname);
	for (int i = strlen(path); i != 0;--i) {
		if (path[i] == '.') {
			for (int j = i; j > 0; --j) {
				if (path[j] == '\\') {
					path[j] = '\0';
					break;
				}
			}
			break;
		}
	}

	char pathToParameters[256];	
	strcpy(pathToParameters, path);	
	strcat(pathToParameters, "\\parameters.txt");

	char pathToErrorFile[256];
	strcpy(pathToErrorFile, path);
	strcat(pathToErrorFile, "\\ErrorFile.txt");	
	FILE* errorFile = fopen(pathToErrorFile, "w");	
		
	strcat(path, "\\output.img");

	char keyPath[256] = { 0 };
	char encryption = 'x';
	char mode[4] = { 0 };
	char vector[10] = { 0 };
	int from = 0;
	int to = 0;
	
	if (!loadParameters(pathToParameters, keyPath, &encryption, mode, vector, &from, &to)) {
		fprintf(errorFile, "Parametre sa zle nacitali. Skontrolujte subor parameters.txt\n");
		fclose(errorFile);
		return E_BAD_DATA;
	}
	
	unsigned char key[2 * BLOCK_SIZE];
	int checkKey = loadKey(key, keyPath, 2 * BLOCK_SIZE);
	
	if ( checkKey != 0 ) {
		fprintf(errorFile, "Kluc sa nenacital spravne\n");	
		fclose(errorFile);
		return checkKey;
	}
	HANDLE file = CreateFile(path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, 0);

	if (file == INVALID_HANDLE_VALUE) {
		fprintf(errorFile, "Novy subor sa nevytvoril\n");
		fclose(errorFile);
		return E_ECREATE;
	}

	if (strcmp(mode, "cbc") == 0) {		
		int check = cbcEncryption(arch->hArchFile, file, key, encryption, vector, from, to);
		if ( check != 0 ) {
			fprintf(errorFile, "Chyba pri sifrovani/desifrovani\n");
			fclose(errorFile);
			return check;
		}
	}
	if (strcmp(mode, "xts") == 0) {
		int check = xtsEncryption(arch->hArchFile, file, key, encryption, vector, from, to);
		if ( check != 0 ) {
			fprintf(errorFile, "Chyba pri sifrovani/desifrovani\n");
			fclose(errorFile);
			return check;
		}
	}

	strcpy(HeaderData->FileName, "output.img");
	HeaderData->FileAttr = 0x3F;
	HeaderData->PackSize = 32768;
	HeaderData->UnpSize = HeaderData->PackSize;
	HeaderData->FileTime = (2016 - 1980) << 25 | 11 << 21 | 20 << 16 | 14 << 11 | 52 << 5 | 30 / 2;
	HeaderData->CmtBuf = 0;
	HeaderData->CmtBufSize = 0;
	HeaderData->CmtSize = 0;
	HeaderData->CmtState = 0;
	HeaderData->UnpVer = 0;
	HeaderData->Method = 0;
	HeaderData->FileCRC = 0;
	CloseHandle(file);
	fclose(errorFile);
	return E_END_ARCHIVE;
}

// ProcessFile by mala rozbalit specificky subor alebo otestovat integritu archivu
int __stdcall ProcessFile(myHANDLE hArcData, int Operation, char *DestPath, char *DestName)
{	
	if (Operation == PK_EXTRACT || PK_TEST) {
		return E_NOT_SUPPORTED;
	}
	return 0;
}

// CloseArchive by mala vykonat vsetky potrebne operacie ked ma byt archiv zatvoreny
int __stdcall CloseArchive(myHANDLE hArcData)
{
	tArchive *arch = hArcData;
	CloseHandle(hArcData->hArchFile);
	delete arch;	

	return 0; // ok
}

// Tato funkcia povoluje oznamit pouzivatelovi menenu jednotku ked zabaluje subory
void __stdcall SetChangeVolProc(myHANDLE hArcData, tChangeVolProc pChangeVolProc)
{
	tArchive *arch = (tArchive *)(hArcData);

	arch->pLocChangeVol = pChangeVolProc;
}

// Tato funkcia povoluje oznamit pouzivatelovi progres pri zabalovani a rozbalovani suborov
void __stdcall SetProcessDataProc(myHANDLE hArcData, tProcessDataProc pProcessDataProc)
{
	tArchive *arch = (tArchive *)(hArcData);

	arch->pLocProcessData = pProcessDataProc;
}
