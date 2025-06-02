#include <stdio.h>

char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output [32];

	// Creating the IPv4 address and saving it to the 'Output' variable 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}

int main() {
    char* ohno = GenerateIpv4(1, 2, 3, 4);
    printf("%s", ohno);
}