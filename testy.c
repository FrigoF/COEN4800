// testy.c - enter a hex value and print as decimal
// 
// Fred J. Frigo
// 12-Sep-2024
// 25-Feb-2025 - enter long string to cause a cresh
// 
// To compile:  gcc -g testy.c -o testy
//

#include <stdio.h>

int main() {

    unsigned int value;
    char myvalue[4]; // very small string to cause crash

    printf("Input your 8 bit byte in hex : ");
    scanf( "%s", myvalue);
    sscanf( myvalue, "%x", &value);
    printf("Decimal Value = %d\n", value);
    printf("Hex value = %x\n", value);
    return 0;
}
