// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <time.h>

#pragma comment(lib, "Bcrypt.lib")



#define NT_SUCCESS(status)	        (((NTSTATUS)(status)) >= 0)

#define KEYSIZE				32
#define IVSIZE				16


typedef struct _AES {

	PBYTE	pPlainText;				// Base address of the plaintext data 
	DWORD	dwPlainSize;			// Size of the plaintext data

	PBYTE	pCipherText;			// Base address of the encrypted data	
	DWORD	dwCipherSize;			// Size of the encrypted data. This can vary from dwPlainSize when there is padding involved.

	PBYTE	pKey;					// The 32 byte key
	PBYTE	pIv;					// The 16 byte IV

}AES, * PAES;



// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}


// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("%0.2X ", Data[i]);
		}
		else {
			printf("%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}



// The encryption implementation
BOOL InstallAesEncryption(PAES pAes) {

	BOOL 			bSTATE			= TRUE;

	BCRYPT_ALG_HANDLE	hAlgorithm		= NULL;
	BCRYPT_KEY_HANDLE	hKeyHandle		= NULL;

	ULONG 			cbResult		= 0;
	DWORD 			dwBlockSize		= 0;
	
	DWORD 			cbKeyObject		= 0;
	PBYTE 			pbKeyObject		= NULL;

	PBYTE 			pbCipherText		= NULL;
	DWORD 			cbCipherText		= 0,


	// Intializing "hAlgorithm" as AES algorithm Handle
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8lX \n", STATUS);
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

	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Allocating enough memory for the output buffer, cbCipherText
	pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
	if (pbCipherText == NULL) {
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptEncrypt again with pbCipherText as the output buffer
	STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8lX \n", STATUS);
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
	if (pbCipherText != NULL && bSTATE) {
		// If everything worked, save pbCipherText and cbCipherText 
		pAes->pCipherText = pbCipherText;
		pAes->dwCipherSize = cbCipherText;
	}
	return bSTATE;

}





// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

	BOOL				bSTATE			= TRUE;

	BCRYPT_ALG_HANDLE		hAlgorithm		= NULL;
	BCRYPT_KEY_HANDLE		hKeyHandle		= NULL;

	ULONG				cbResult		= 0;
	DWORD				dwBlockSize		= 0;
	DWORD				cbKeyObject		= 0;
	PBYTE				pbKeyObject		= NULL;

	PBYTE				pbPlainText		= NULL;
	DWORD				cbPlainText		= 0,

	// Intializing "hAlgorithm" as AES algorithm Handle
	STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
	STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8lX \n", STATUS);
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
	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptSetProperty Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}
	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
	STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8lX \n", STATUS);
		bSTATE = FALSE; goto _EndOfFunc;
	}

	// Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
	STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8lX \n", STATUS);
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
		printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8lX \n", STATUS);
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



// Wrapper function for InstallAesEncryption that makes things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == 0 || pKey == NULL || pIv == NULL)
		return FALSE;
	
	// Intializing the struct
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pPlainText = pPlainTextData,
		.dwPlainSize = sPlainTextSize
	};

	if (!InstallAesEncryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pCipherTextData = Aes.pCipherText;
	*sCipherTextSize = Aes.dwCipherSize;

	return TRUE;
}


// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == 0 || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey = pKey,
		.pIv = pIv,
		.pCipherText = pCipherTextData,
		.dwCipherSize = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}




// THE ENCRYPTION PART


// "This is a plain text string, we'll try to encrypt/decrypt !" in hex
unsigned char Data[] = {
	0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x70, 0x6C,
	0x61, 0x69, 0x6E, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x72,
	0x69, 0x6E, 0x67, 0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74,
	0x72, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x2F, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x21
};

int main() {

	BYTE pKey [KEYSIZE];// = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 
						//0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x61, 0x62, 0x63, 
						//0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 
						//0x6d, 0x6e, 0x6f, 0x70};					// KEYSIZE is 32
	BYTE pIv [IVSIZE];// = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 
						//0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70};						// IVSIZE is 16
	BYTE pIvCopy[IVSIZE];

	srand(time(NULL));						// the seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);		// generating the key bytes

	srand(time(NULL) ^ pKey[0]);			// the seed to generate the iv (using the first byte from the key to add more spice)
	GenerateRandomBytes(pIv, IVSIZE);		// generating the iv

	for (int i = 0; i < IVSIZE; i++) {
		pIvCopy[i] = pIv[i];
	}

	// printing both on the screen
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// defining two variables, that will be used in SimpleEncryption, (the output buffer and its size)
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = 0;

	printf("Data: %s \n\n", Data);

	// encrypting
	if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
		return -1;
	}

	// print the encrypted buffer as a hex array
	PrintHexData("CipherText", pCipherText, dwCipherSize);


	// ================================================================== \\


	// defining two variables, that will be used in SimpleDecryption, (the output buffer and its size)
	PVOID	pPlaintext	 = NULL;
	DWORD	dwPlainSize  = 0;

	// decryption
	if (!SimpleDecryption(pCipherText, dwCipherSize, pKey, pIvCopy, &pPlaintext, &dwPlainSize)) {
		return -1;
	}
	// printing the decrypted data to the screen as hex, this will look the same as the variable "Data" from the encryption snippet
	PrintHexData("PlainText", pPlaintext, dwPlainSize);

	// this will print: "This is a plain text string, we'll try to encrypt/decrypt !"
	printf("Data: %s \n", (unsigned char*)pPlaintext);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	// freeing
	HeapFree(GetProcessHeap(), 0, pPlaintext);
	HeapFree(GetProcessHeap(), 0, pCipherText);
	return 0;
}

