// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

// Example invocation: XorByOneKey(shellcode, sizeof(shellcode), 0xFA);
// Here the shellcode is a char array and 0xFA is the one byte key used
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {
	
	for (size_t i = 0; i < sShellcodeSize; i++){
		
		pShellcode[i] = pShellcode[i] ^ bKey;
	}

}


// Example invocation: XorByOneKey(shellcode, sizeof(shellcode), 0xFA);
// Here the shellcode is a char array and 0xFA is the one byte key used
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {

	for (size_t i = 0; i < sShellcodeSize; i++) {

		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}

}


// Example invocation: Check the main function
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {

	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		// if end of the key, start again 
		if (j > sKeySize)
		{
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
		
	}

}


unsigned char shellcode[] = { 
	"This is very spooky stuff" 
};

unsigned char key[] = { 
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05
};

int main() {
	// Printing some data
	printf("[i] shellcode : 0x%p \n", shellcode);

	// Encryption
	XorByInputKey(shellcode, sizeof(shellcode), key, sizeof(key));

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption
	XorByInputKey(shellcode, sizeof(shellcode), key, sizeof(key));

	// Printing the shellcode's string
	printf("[i] shellcode : \"%s\" \n", (char*)shellcode);


	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;

}

/*

// "XorByiKeys" usage example, the same thing goes for "XorByOneKey" usage

int main() {
	// Printing some data
	printf("[i] shellcode : 0x%p \n", shellcode);

	// Encryption, 0xF4 is the key
	XorByiKeys(shellcode, sizeof(shellcode), 0xF4);

	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Decryption, 0xF4 is the key
	XorByiKeys(shellcode, sizeof(shellcode), 0xF4);

	// Printing the shellcode's string
	printf("[i] shellcode : \"%s\" \n", (char*)shellcode);


	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;

}

*/