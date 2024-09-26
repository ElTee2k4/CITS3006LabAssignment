#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>

#define SIZE 150  // Number of decimal values
#define XOR_KEY 0xAA  // Define XOR key for encryption

int handle_password_check(char const* input_string, int arg_count, char *arguments[]);
int validate_sum(char const* input_string, size_t str_len);
int xor_hex_values(long hex_val1, long hex_val2);
void (*init_random_seed)(unsigned int) = srand;
int verify_member(const char *input_string, char *arguments[]);
void encrypt_decrypt(const char *input, char *output, int length);
bool password_component_check(const char *password);
int calculate_digit_sum(char *word);
int first_dummy_function(const char *password);

bool security = false;


int offsets[] = { 
    (0x74 - 'a') ^ 0xFF, (0x68 - 'a') ^ 0xFF, (0x69 - 'a') ^ 0xFF,
    (0x73 - 'a') ^ 0xFF, (0x20 - 'a') ^ 0xFF, (0x69 - 'a') ^ 0xFF,
    (0x73 - 'a') ^ 0xFF, (0x20 - 'a') ^ 0xFF, (0x68 - 'a') ^ 0xFF,
    (0x69 - 'a') ^ 0xFF, (0x64 - 'a') ^ 0xFF, (0x64 - 'a') ^ 0xFF,
    (0x65 - 'a') ^ 0xFF, (0x6e - 'a') ^ 0xFF, (0x20 - 'a') ^ 0xFF
};

typedef struct{
    int upper_case_count;
    int lower_case_count;
    int digit_count;
    int special_char_count;
    int sum_var;
}PASSWORD_VALIDATION_VARS;

PASSWORD_VALIDATION_VARS password_vars;


typedef struct{
    int user_id;
    char *name;
    int size_of_name;
}USERLIST;

int num_users = 3;

USERLIST *users;

int initial_construction(){
    users = (USERLIST *)malloc(num_users * sizeof(USERLIST));
    // User 1
    users[0].user_id = 1;
    users[0].size_of_name = strlen("Alice") + 1; // +1 for null terminator
    users[0].name = (char *)malloc(users[0].size_of_name);
    strcpy(users[0].name, "Alice");

    // User 2
    users[1].user_id = 2;
    users[1].size_of_name = strlen("Bob") + 1;
    users[1].name = (char *)malloc(users[1].size_of_name);
    strcpy(users[1].name, "Bob");

    // User 3
    users[2].user_id = 3;
    users[2].size_of_name = strlen("Charlie") + 1;
    users[2].name = (char *)malloc(users[2].size_of_name);
    strcpy(users[2].name, "Charlie");
    return 0;
}

int secret_function() {
    asm("jmp %esp");
}

int new_user()
{
    num_users++;

    char buffer[64];

    puts("Please enter your name new user!:\n");
    gets(buffer);

    users[num_users - 1].user_id = num_users;
    users[num_users - 1].size_of_name = strlen(buffer); 
    users[num_users - 1].name = (char *)malloc(64);

    strcpy(users[num_users - 1].name, buffer);

    return 0;

}

int main(int argc, char *argv[])
{
    setuid(0);
    setgid(0);

    initial_construction();

    new_user();

    printf("\n");

    int user_choice;

    printf("Welcome to the Hackermen Command Interface %s!\nPlease log in or browse:\nChoose an option\n(1): Log in\n(2): Look at our members!\n-> ", users[num_users - 1].name);
    scanf("%d", &user_choice);
    
    if(user_choice == 1){

        char password_input[100];

        printf("Please enter a password...\n");
        scanf("%s", password_input);

        handle_password_check(password_input, argc, argv);
    }
    else if (user_choice == 2){
        printf("Would you like to add a new user or look through the current user database?\n(1): Search for current users\n(2): Create a new user\n-> ");
        scanf("%d", &user_choice);

        if(user_choice==1){
            printf("Initial users:\n");
            for (int i = 0; i < num_users; i++) {
                printf("User ID: %d, Name: %s\n", users[i].user_id, users[i].name);
            }
        }
        else if(user_choice == 2){
            printf("You will be taken to the sign-up form!\n");
            int result = new_user();
            int admin_num = 0;
            if (admin_num < 0) {
                printf("Security mode activated");
                //func secret_security_password
                printf("\nOffsets:\n");
                for (int i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
                    printf("%d ", offsets[i] ^ 0xFF);  // Unobfuscate before printing
                }
                printf("\n");
            }
            if(result == 0){
                printf("User creation successful!\n");
                for (int i = 0; i < num_users; i++) {
                    printf("User ID: %d, Name: %s\n", users[i].user_id, users[i].name);
                }
            }
        }
    }

    return 0;
}


int handle_password_check(char const* input_string, int arg_count, char *arguments[]){
    
    init_random_seed(10);
    size_t str_len = strlen(input_string);

    // Check if the sum is correct
    if (str_len == 5){
        validate_sum(input_string, str_len);
    }
    else if (str_len == 4) {
        if (arg_count == 3){
            int result = verify_member(input_string, arguments);
            if(result == 1){
                printf("You have logged in using our emergency security login\n");
                security = true;
            }
            else{
                printf("Incorrect password\n");
            }
        }
        else{
            //password_component_check(input_string, arguments);
        }
    } else {
        printf("Incorrect password\n");
    }

    return 0;
}

int validate_sum(char const* input_string, size_t str_len){
    int sum = 0;
    for (size_t i = 0; i < str_len; i++) {
        sum += (int)input_string[i];
    }

    long hex_val1 = 0x2B9; 
    long hex_val2 = 0XAA; 


    if(sum == (xor_hex_values(hex_val1, hex_val2))){
        int decimal_values[SIZE] = {
            97, 71, 70, 111, 89, 83, 69, 103, 101, 87, 57, 49, 73, 72, 100, 108, 99, 109, 85, 103, 100, 72, 74, 112, 89, 50, 116, 108, 90, 67, 66, 115, 98, 50, 119, 61
        };

        char result_string[SIZE + 1]; 

        for (int i = 0; i < SIZE; i++) {
            result_string[i] = (char) decimal_values[i];
        }
        result_string[SIZE] = '\0';

    }

    return 0;

}

void encrypt_decrypt(const char *input, char *output, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = input[i] ^ XOR_KEY;
    }
    output[length] = '\0'; // Null-terminate the output string
}

int xor_hex_values(long hex_val1, long hex_val2){
    return 0x2B9 ^ 0xAA;
}

int verify_member(const char *input_string, char *arguments[]) {
    // Check if arguments is not NULL and has at least 2 elements
    if (arguments != NULL && arguments[1] != NULL && arguments[2] != NULL) {
        if(arguments[2][0] == 'L'){

            char *first_argument = strdup(arguments[1]);
            int first_argument_sum = calculate_digit_sum(first_argument);

            int random_number = rand(); // Get a random number
            char comparison[12]; // Buffer to hold the string representation of the number (enough for a large integer and null terminator)
            snprintf(comparison, sizeof(comparison), "%d", random_number); // Convert the number to a string
            int comparison_sum = calculate_digit_sum(comparison);
            printf("%i\n", comparison_sum);

            if(first_argument_sum == comparison_sum){
                bool result = password_component_check(input_string);
                if (result == 1){
                    return 1;
                } else {
                    return 0;
                }
                
            }
        }
    } else {
        printf("No member found.\n"); // Fallback if arguments[1] is not accessible
        return 0;
    }
}

bool password_component_check(const char *password) {
    int checks[4] = {0};
    const char *ptr = password;

    long sum = 0;

    while (*ptr) {
        switch (*ptr) {
            case 'A' ... 'Z':
                while(*ptr != ' '){
                    sum++;
                    if (sum > 80){
                        password_vars.sum_var++;
                        break;
                    }
                }
                password_vars.upper_case_count++;
                break;
            case 'a' ... 'z':
                password_vars.lower_case_count++;
                break;
            case '0' ... '9':
                password_vars.digit_count++;
                break;
            default:
                if (ispunct(*ptr)) {
                    password_vars.special_char_count++;
                }
                break;
        }
        ptr++;
    }
    if((password_vars.upper_case_count > 0 && password_vars.lower_case_count > 0 && password_vars.digit_count > 0 && password_vars.special_char_count > 0) == 1){
        int result = first_dummy_function(password);
        if(result){
            return 1;
        }
    }
    else{
        //another_dummy_function;
        return 0;
    }
}

int calculate_digit_sum(char *word){
    int summation = 0;
    size_t str_len = strlen(word);

    for (size_t i = 0; i < str_len; i++) {
        int current_digit;
        char current_char = word[i];

        // Convert the current character to an integer (digit)
        sscanf(&current_char, "%d", &current_digit);
        summation += current_digit;
    }

    return summation;

}

int first_dummy_function(const char *password){
    
    int sum = 0;
    size_t size_of_password = strlen(password);

    char *new_password = malloc(size_of_password * sizeof(char));
    bool result;

    if (size_of_password > 0){
        bool result = false;
        if (result == false){
            for(int i = 0; i < size_of_password; i++){
                sprintf(new_password, "%s%c", new_password, password);

                int dummy_var = i % 7;
                if (dummy_var == 0) {
                    sum += dummy_var * 10;
                } else {
                    sum -= dummy_var * 2;
                }


            }
        }
    }

    if (sum == 10 && strlen(new_password) == size_of_password){
        free(new_password);
        return 2;
    }

    else{
        free(new_password);
        return 1;
    }
    

}
