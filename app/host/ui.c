#include <stdio.h>
#include <string.h>

#include "password_manager.h"

int main_choice_ui()
{
char choice;
    char input[10];

	printf("\nMain Menu\n");

    printf("Please select an option:\n");
    printf("1. (O)pen existing password archive\n");
    printf("2. (C)reate new password archive\n");
    printf("3. (R)estore password archive\n");
    printf("4. (D)elete archive\n");
	printf("5. (E)xit\n");
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
		case 'D':
		case 'd':
		case '4':
			return DELETE_ARCHIVE;
		case 'E':
		case 'e':
		case '5':
			return EXIT;
		default:
			printf("Invalid choice, please try again.\n");
			return INVALID_CHOICE;
	}

	return INVALID_CHOICE;
}

int open_archive_choice_ui(char *archive_name, char *password)
{
	char input[256];

	printf("Enter the archive name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(archive_name, input, MAX_ARCHIVE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the password: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(password, input, MAX_PWD_LEN);
	}
	else
	{
		return -1;
	}

	printf("Do you want to add a new entry or get an existing one?\n");
	printf("1. (A)dd new entry\n");
	printf("2. (G)et existing entry\n");
	printf("3. (D)elete entry\n");
	printf("Enter your choice: ");

	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		if (input[0] == 'A' || input[0] == 'a' || input[0] == '1')
		{
			return ADD_ENTRY;
		}
		else if (input[0] == 'G' || input[0] == 'g' || input[0] == '2')
		{
			return GET_ENTRY;
		}
		else if (input[0] == 'D' || input[0] == 'd' || input[0] == '3')
		{
			return DELETE_ENTRY;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

int add_entry_ui(struct pwd_entry *entry)
{
	char input[256];

	printf("Enter the site URL: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(entry->site_url, input, MAX_SITE_URL_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the site name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(entry->site_name, input, MAX_SITE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the username: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(entry->username, input, MAX_USERNAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the password: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(entry->password, input, MAX_PWD_LEN);
	}
	else
	{
		return -1;
	}

	return 0;
}

int get_entry_ui(char *site_name)
{
	char input[256];

	printf("Enter the site name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(site_name, input, MAX_SITE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	return 0;
}

int create_archive_ui(char *archive_name, char *password)
{
	char input[256];

	printf("Enter the archive name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(archive_name, input, MAX_ARCHIVE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the password: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(password, input, MAX_PWD_LEN);
	}
	else
	{
		return -1;
	}

	return 0;
}

int delete_archive_ui(char *archive_name, char *password)
{
	char input[256];

	printf("Enter the archive name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(archive_name, input, MAX_ARCHIVE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the password: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(password, input, MAX_PWD_LEN);
	}
	else
	{
		return -1;
	}

	printf("Are you sure you want to delete the archive? (Y/N): ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		if (input[0] == 'Y' || input[0] == 'y')
		{
			return 0;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

int delete_entry_ui(char *site_name)
{
	char input[256];

	printf("Enter the site name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(site_name, input, MAX_SITE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Are you sure you want to delete the entry? (Y/N): ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		if (input[0] == 'Y' || input[0] == 'y')
		{
			return 0;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

int restore_archive_ui(char *archive_name, char *recovery_key, char *password)
{
	char input[256];

	printf("Enter the archive name: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(archive_name, input, MAX_ARCHIVE_NAME_LEN);
	}
	else
	{
		return -1;
	}

	printf("Enter the recovery key 8 characters at a time without the '-' (e.g. 12345678): ");
	for (int i = 0; i < 8; i++)
	{
		if (fgets(input, sizeof(input), stdin) != NULL)
		{
			input[strcspn(input, "\n")] = 0;
			strncpy(recovery_key + i * 8, input, 8);
		}
		else
		{
			return -1;
		}
	}

	printf("Enter the new password: ");
	if (fgets(input, sizeof(input), stdin) != NULL)
	{
		input[strcspn(input, "\n")] = 0;
		strncpy(password, input, MAX_PWD_LEN);
	}
	else
	{
		return -1;
	}

	return 0;
}