#include <stdio.h>
#include <string.h>

#include "password_manager.h"

int main_choice_ui()
{
char choice;
    char input[10];

    printf("Please select an option:\n");
    printf("1. (O)pen existing password archive\n");
    printf("2. (C)reate new password archive\n");
    printf("3. (R)estore password archive\n");
    printf("4. (E)xit\n");
    printf("Enter your choice: ");

    if (fgets(input, sizeof(input), stdin) != NULL)
    {
        choice = input[0];
    }
    else
    {
        return INVALID_CHOICE; 
    }

	switch(choice)
	{
		case 'O':
		case 'o':
		case '1':
			return OPEN_EXISTING_ARCHIVE;
		case 'C':
		case 'c':
		case '2':
			return CREATE_NEW_ARCHIVE;
		case 'R':
		case 'r':
		case '3':
			return RESTORE_ARCHIVE;
		case 'E':
		case 'e':
		case '4':
			return EXIT;
		default:
			printf("Invalid choice, please try again.\n");
			return INVALID_CHOICE;
	}

	return INVALID_CHOICE;
}