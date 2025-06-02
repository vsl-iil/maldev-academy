// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// the Visual Studio project should include:
// aes.h - https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// aes.c - https://github.com/kokke/tiny-AES-c/blob/master/aes.c

#define KEYSIZE				32
#define IVSIZE				16

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
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}



// Function that will take a buffer, and copy it to another buffer that is a multiple of 16 in size
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer	= NULL;
	SIZE_T	PaddedSize		= NULL;

	// Calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// Allocating buffer of size PaddedSize
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer){
		return FALSE;
	}
	// Cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// Copying old buffer to a new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	// Saving results
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;
}

// DECRYPTION //

unsigned char pKey[] = {
		0xFA, 0x9C, 0x73, 0x6C, 0xF2, 0x3A, 0x47, 0x21, 0x7F, 0xD8, 0xE7, 0x1A, 0x4F, 0x76, 0x1D, 0x84,
		0x2C, 0xCB, 0x98, 0xE3, 0xDC, 0x94, 0xEF, 0x04, 0x46, 0x2D, 0xE3, 0x33, 0xD7, 0x5E, 0xE5, 0xAF };


unsigned char pIv[] = {
		0xCF, 0x00, 0x86, 0xE1, 0x6D, 0xA2, 0x6B, 0x06, 0xC4, 0x8B, 0x1F, 0xDA, 0xB6, 0xAB, 0x21, 0xF1 };


unsigned char CipherText[] = {
		0xD8, 0x9C, 0xFE, 0x68, 0x97, 0x71, 0x5E, 0x5E, 0x79, 0x45, 0x3F, 0x05, 0x4B, 0x71, 0xB9, 0x9D,
		0xB2, 0xF3, 0x72, 0xEF, 0xC2, 0x64, 0xB2, 0xE8, 0xD8, 0x36, 0x29, 0x2A, 0x66, 0xEB, 0xAB, 0x80,
		0xE4, 0xDF, 0xF2, 0x3C, 0xEE, 0x53, 0xCF, 0x21, 0x3A, 0x88, 0x2C, 0x59, 0x8C, 0x85, 0x26, 0x79,
		0xF0, 0x04, 0xC2, 0x55, 0xA8, 0xDE, 0xB4, 0x50, 0xEE, 0x00, 0x65, 0xF8, 0xEE, 0x7C, 0x54, 0x98,
		0xEB, 0xA2, 0xD5, 0x21, 0xAA, 0x77, 0x35, 0x97, 0x67, 0x11, 0xCE, 0xB3, 0x53, 0x76, 0x17, 0xA5,
		0x0D, 0xF6, 0xC3, 0x55, 0xBA, 0xCD, 0xCF, 0xD1, 0x1E, 0x8F, 0x10, 0xA5, 0x32, 0x7E, 0xFC, 0xAC };



int main() {
	// Struct needed for tiny-AES library
	struct AES_ctx ctx;
	// Initilizing the Tiny-Aes Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// Decrypting
	AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));
	 
	// Printing the decrypted buffer to the console
	PrintHexData("PlainText", CipherText, sizeof(CipherText));

	// Printing the string
	printf("Data: %s \n", CipherText);


	// Exit
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}


// ENCRYPTION //

/*
// "this is plain text sting, we'll try to encrypt... lets hope everythign go well :)" in hex
// since the upper string is 82 byte in size, and 82 is not mulitple of 16, we cant encrypt this directly using tiny-aes
unsigned char Data[] = {
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E,
	0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67,
	0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20,
	0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E,
	0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20,
	0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67,
	0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00
};



int main() {
	// Struct needed for tiny-AES library
	struct AES_ctx ctx;


	BYTE pKey[KEYSIZE];				// KEYSIZE is 32
	BYTE pIv[IVSIZE];				// IVSIZE is 16
		

	srand(time(NULL));				// The seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);		// Generating the key bytes

	srand(time(NULL) ^ pKey[0]);			// The seed to generate the iv (using the first byte from the key to add more spice)
	GenerateRandomBytes(pIv, IVSIZE);		// Generating the IV

	// Printing key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Initilizing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address and its size in case padding is required
	PBYTE	PaddedBuffer	= NULL;
	SIZE_T	PAddedSize		= NULL;

	// Padding buffer, if needed
	if (sizeof(Data) % 16 != 0){
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
	}
	else {
		// No padding is required, encrypt Data directly
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
	}


	// Freeing PaddedBuffer, if needed
	if (PaddedBuffer != NULL){
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;

}
*/