// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")



#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)

#define KEYSIZE				32
#define IVSIZE				16


typedef struct _AES {

	PBYTE	pPlainText;			// Base address of the plaintext data 
	DWORD	dwPlainSize;			// Size of the plaintext data

	PBYTE	pCipherText;			// Base address of the encrypted data	
	DWORD	dwCipherSize;			// Size of it (this can change from dwPlainSize in case there was padding)

	PBYTE	pKey;				// The 32 byte key
	PBYTE	pIv;				// The 16 byte IV

}AES, * PAES;



// generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}


// print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}



// the decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

	BOOL				bSTATE = TRUE;

	BCRYPT_ALG_HANDLE		hAlgorithm = NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle = NULL;

	ULONG				cbResult = NULL;
	DWORD				dwBlockSize = NULL;
	DWORD				cbKeyObject = NULL;
	PBYTE				pbKeyObject = NULL;

	PBYTE				pbPlainText = NULL;
	DWORD				cbPlainText = NULL,

	// Intializing "hAlgorithm" as AES algorithm Handle
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	
	// Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Checking if block size is 16 bytes
	if (dwBlockSize != 16) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Allocating enough memory for the output buffer, cbPlainText
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (pbPlainText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Running BCryptDecrypt again with pbPlainText as the output buffer
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Clean up
_EndOfFunc:
	if (hKeyHandle) {
		BCryptDestroyKey(hKeyHandle);
	}
	if (hAlgorithm) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	if (pbKeyObject) {
		HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
	if (pbPlainText != NULL && bSTATE) {
		// if everything went well, we save pbPlainText and cbPlainText
		pAes->pPlainText = pbPlainText;
		pAes->dwPlainSize = cbPlainText;
	}
	return bSTATE;

}




// Wrapper function for InstallAesDecryption that makes things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// intializing the struct
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pCipherText = pCipherTextData,
		.dwCipherSize = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}



// The key printed to the screen
unsigned char pKey[] = {
		0x49, 0x08, 0x28, 0x61, 0xDA, 0x33, 0x4D, 0x3C, 0xAC, 0xD7, 0x51, 0x9F, 0x75, 0xE4, 0x35, 0x16,
		0xE4, 0x5C, 0xBF, 0xE2, 0x84, 0xAC, 0x7A, 0xEF, 0xE4, 0x3C, 0xFE, 0x06, 0xF5, 0x45, 0x71, 0x44 };

// The IV printed to the screen
unsigned char pIv[] = {
		0x31, 0x09, 0xAC, 0x30, 0x88, 0x41, 0x85, 0x5F, 0x0F, 0xB7, 0x4C, 0xD6, 0x89, 0xE9, 0x11, 0xB2 };

// Encrypted x64 calc shellcode 
unsigned char EncShellcode[] = {
		0xE1, 0x2E, 0x25, 0xC7, 0x06, 0x2B, 0x75, 0x44, 0x3C, 0xD7, 0x01, 0xCE, 0xAA, 0x81, 0x87, 0x80,
		0x5A, 0x1E, 0x4D, 0x0F, 0x51, 0xAE, 0xE8, 0xA7, 0x1E, 0x22, 0x0E, 0x3A, 0xA2, 0x09, 0x23, 0x20,
		0x4B, 0x5E, 0x0A, 0x3E, 0x7D, 0x8D, 0x3C, 0xEE, 0x31, 0xBE, 0x1B, 0xD9, 0xC7, 0xFE, 0x9A, 0x49,
		0x67, 0x24, 0x57, 0x59, 0x6B, 0x13, 0xE3, 0xC1, 0x4E, 0xFA, 0x76, 0x10, 0xF1, 0xF6, 0x84, 0xE3,
		0x41, 0xA7, 0xC4, 0x0F, 0xB4, 0x32, 0x7B, 0x8B, 0x84, 0xD5, 0x57, 0x80, 0x18, 0x1F, 0xF6, 0xD1,
		0xE3, 0x0B, 0x5B, 0x8D, 0x4E, 0x74, 0x4C, 0xB1, 0xF5, 0x4B, 0xFB, 0xA8, 0x6D, 0x65, 0x6B, 0xA5,
		0x2B, 0xB8, 0xDE, 0x63, 0xC4, 0xFA, 0x0D, 0x20, 0x5C, 0x0A, 0x08, 0x17, 0x90, 0x95, 0x22, 0xB9,
		0xE1, 0xF3, 0xB2, 0xC3, 0x24, 0xDC, 0x39, 0xDB, 0x52, 0x3E, 0xFA, 0xE0, 0x01, 0x3B, 0x3A, 0xD2,
		0x0B, 0xB7, 0x50, 0xA5, 0x62, 0xE9, 0x9F, 0x45, 0xA1, 0x03, 0xAC, 0xBB, 0x07, 0xF3, 0x30, 0x5A,
		0x31, 0xFC, 0x1B, 0x6E, 0x8B, 0x60, 0x8C, 0x26, 0x9E, 0x0E, 0x09, 0x76, 0xF8, 0x87, 0x47, 0x65,
		0x30, 0x10, 0xAF, 0xBA, 0x14, 0x37, 0x31, 0x84, 0x2A, 0xA1, 0x85, 0xB0, 0xEF, 0xB9, 0xFA, 0x63,
		0x09, 0x24, 0xCD, 0x51, 0x59, 0xAC, 0xA0, 0xC4, 0x0A, 0xBF, 0xB5, 0x1D, 0x37, 0xF7, 0x14, 0xE8,
		0x81, 0xA5, 0x84, 0xB3, 0x21, 0x68, 0xA8, 0x36, 0x59, 0xC2, 0xAB, 0x4E, 0x7C, 0x27, 0x04, 0xD6,
		0x8B, 0xC9, 0xF4, 0x55, 0x35, 0x06, 0x57, 0x2C, 0x49, 0xE1, 0xEA, 0x64, 0x7A, 0x25, 0x8E, 0x52,
		0xC5, 0x18, 0xCE, 0x98, 0x4F, 0xBE, 0xE0, 0xF4, 0xE0, 0xB0, 0xC5, 0x5C, 0x3C, 0x16, 0x93, 0x25,
		0x08, 0xD7, 0x10, 0x46, 0xCA, 0xE0, 0xD0, 0xB1, 0xF6, 0xD1, 0x39, 0x5C, 0x1E, 0x84, 0x00, 0x76,
		0x59, 0xF1, 0xA0, 0x86, 0xB3, 0x01, 0x6D, 0x27, 0xD1, 0x88, 0xCE, 0xA5, 0x1F, 0x03, 0x57, 0xB7,
		0x9F, 0x1E, 0xA2, 0xFD, 0x00, 0x75, 0x6E, 0x8A, 0xC2, 0xC8, 0xC5, 0x69, 0xDA, 0xA0, 0x7C, 0xDC };



int main() {

	// Defining two variables that will be used in SimpleDecryption (the output buffer and its size)
	PVOID	pPlaintext = NULL;
	DWORD	dwPlainSize = NULL;


	// Printing the address of our shellcode
	printf("[i] shellcode : 0x%p \n", EncShellcode);
	printf("[#] Press <Enter> To Decrypt ...");
	getchar();


	// Decryption
	if (!SimpleDecryption(EncShellcode, sizeof(EncShellcode), pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}

	// Printing the decrypted buffer
	PrintHexData("Shellcode", pPlaintext, dwPlainSize);


	// Freeing
	HeapFree(GetProcessHeap(), 0, pPlaintext);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}


