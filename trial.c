#include <stdio.h>
#include <string.h>

// 29 A's will lead to the buffer being overflowed

int main(void){
    
    int another_one = 92329;
    int authorised = 0;
    char usr_pass[16];

    printf("Enter your name: ");
    scanf("%s", usr_pass);

    printf("user_pass: %s\n", usr_pass);
    printf("auth val: %i\n", authorised);
    printf("user_pass addr: %p\n", (void *)usr_pass);
    printf("auth val addr: %p\n", (void *)&authorised);

    printf("Welcome user! Currently, you are a guest!\n");


    if(authorised){
        printf("password is correct!\n");
    }
}

// int authorised 0x7fffffffd9e8
// char *usr_pass 0x7fffffffd9d0
 