/** Copyright (c) 2022/05/12, Peter Boettcher, Germany/NRW, Muelheim Ruhr
 * Urheber: 2022/05/12, Peter Boettcher, Germany/NRW, Muelheim Ruhr

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *)

*/



/*
	Frontend for Linux SYSCALL Extension <execve>

	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.05.12

	Program		: csafer.c
			: Simple Frontend

			: Control Program for Extension <SYSCALL execve>
			: It only works as ROOT

			: If you use binary search, a sorted list ist required.

	List		: ALLOW and DENY list
			: a: = ALLOW, d: = DENY
			: a:USER;FILE-SIZE;Path
			: d:USER;Path


	Control		:  0 = safer ON
			:  1 = safer OFF
			:  2 = State
			:  3 = Log ON
			:  4 = Log OFF

			:  5 = Clear FILE List
			:  6 = Clear FOLDER List

			:  7 = ROOT LIST IN KERNEL ON
			:  8 = ROOT LIST IN KERNEL OFF

			:  9 = LOCK changes

			: 10 = learning ON
			: 11 = learning OFF

			: 20 = Set FILE List
			: 21 = Set FOLDER List

	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

			: string = allow:USER-ID;FILE-SIZE;PATH
			: string = deny:GROUP-ID;PATH

			: a:USER-ID;Path
			: d:USER-ID;Path

			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path

			: Example:
			: a:100;1224;/bin/test		= allow file
			: a:100;1234;/bin/test1		= allow file
			: a:100;/usr/sbin/		= allow Folder

			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny folder

			: ga:100;/usr/sbin/		= allow group folder
			: gd:100;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;1234;/usr/bin/mc	= allow group file


			: It is up to the ADMIN to keep the list reasonable according to these rules!




	I would like to remember ALICIA ALONSO and MAYA PLISETSKAYA. Two admirable ballet dancers.
*/



#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>




typedef signed long long int s64;
typedef unsigned long long int u64;



typedef int bool;
#define true 1
#define false 0









//--------------------------------------------------------------------------------------------------------------------
typedef struct {
	//public
	char	**TStringList;
	s64	COUNT_BYTES_FILE;
	s64	COUNT_LINES_FILE;

	s64	TStringList_Length_Max;
	s64	TStringList_Lines;

	bool	DelDUP;
	bool	SORT;

	//public Funktionen
	s64 (*CountBytesFile)	(void *self, char *file_name);
	s64 (*CountLinesFile)	(void *self, char *file_name);
	s64 (*SetLines)		(void *self, s64 numbers);
	s64 (*DynStrcpy)	(void *self, s64 number, char *newstring);
	s64 (*DynStrcat)	(void *self, s64 number, char *newstring);
	s64 (*Del)		(void *self, s64 number);
	s64 (*CountLines)	(void *self);
	s64 (*StringLengthMax)	(void *self);
	s64 (*LoadFromFile)	(void *self, char *file_name);
	s64 (*DelDup)		(void *self);
	s64 (*DynFree)		(void *self);
	s64 (*MaxStr)		(void *self);
	s64 (*Add)		(void *self, char *newstring);
	s64 (*Sort)		(void *self);
	s64 (*SetSort)		(void *self, bool b);
	s64 (*SetDelDUP)	(void *self, bool b);



} TStringList;





int TryStrToInt64 (char *STRING_NUMBER, s64 *NUMBER, int ZAHLEN_SYSTEM) {

	char *ERROR;

	if (strlen(STRING_NUMBER) == 0) return (-1);

	*NUMBER = strtoll(STRING_NUMBER, &ERROR, ZAHLEN_SYSTEM);
	if (strlen(ERROR) != 0) return (-1);

	if (*NUMBER == 9223372036854775807) {
		if (strncmp(STRING_NUMBER, "9223372036854775807", 19) != 0) return(-1);
		else return(0);
	}

	/* Warning gcc: -922337203685477588 */
	if (*NUMBER + 1 == -9223372036854775807) {
		if (strncmp(STRING_NUMBER, "-9223372036854775808", 20) != 0) return(-1);
		else return(0);
	}

	return(0);
}





int str_compare(const void *a, const void *b)
{
	const char **pa = (const char **)a;
	const char **pb = (const char **)b;
	return strcmp(*pa, *pb);
}





s64 Sort (void *self) {

	TStringList *struct_tstringlist = self;

	qsort(struct_tstringlist->TStringList, struct_tstringlist->TStringList_Lines, sizeof(char *), str_compare);

	return(0);

}





s64 SetSort (void *self, bool b) {

	TStringList *struct_tstringlist = self;

	if (b == true) struct_tstringlist->SORT = true;
	else struct_tstringlist->SORT = false;

	return(0);

}





s64 SetDelDUP (void *self, bool b) {

	TStringList *struct_tstringlist = self;

	if (b == true) struct_tstringlist->DelDUP = true;
	else struct_tstringlist->DelDUP = false;

	return(0);

}





s64 Add(void *self, char *newstring)
{
	TStringList *struct_tstringlist = self;

	//New
	if (struct_tstringlist->TStringList_Lines == -1) {
		struct_tstringlist->TStringList = malloc(1 * sizeof(char *));
		if (struct_tstringlist->TStringList == NULL) return(-1);

		struct_tstringlist->TStringList[0] = malloc((strlen(newstring) + 1) * sizeof(char));

		if (struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines] == NULL) {
			//former state
			free(struct_tstringlist->TStringList);
			return(-1);
		}


		strcpy(struct_tstringlist->TStringList[0], newstring);
		struct_tstringlist->TStringList_Lines = 1;

		return(0);
	}

	//backup pointer
	char **backup_ptr = struct_tstringlist->TStringList;
	s64 lines = struct_tstringlist->TStringList_Lines + 1;

	//New LINE
	backup_ptr = realloc(backup_ptr, lines * sizeof(char *));
	if (backup_ptr == NULL) return(-1);
	else struct_tstringlist->TStringList = backup_ptr;

	//MEM Columns
	struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines] = malloc((strlen(newstring) + 1) * sizeof(char));
	if (struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines] == NULL) {
		//former state
		struct_tstringlist->TStringList = realloc(struct_tstringlist->TStringList, (lines - 1) * sizeof(char *));
		return(-1);
	}

	strcpy(struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines], newstring);
	struct_tstringlist->TStringList_Lines++;

	return(0);
}





s64 MaxStr (void *self)
{
	TStringList *struct_tstringlist = self;

	s64 MAX;
	for (s64 n = 0; n < struct_tstringlist->TStringList_Lines; n++) {
		if (struct_tstringlist->TStringList[n] != NULL) {
			MAX = strlen(struct_tstringlist->TStringList[n]);
			if (MAX > struct_tstringlist->TStringList_Length_Max) struct_tstringlist->TStringList_Length_Max = MAX;
		}
	}

	return(0);
}





s64 DynFree (void *self)
{
	TStringList *struct_tstringlist = self;

	if (struct_tstringlist->TStringList_Lines == -1) return(-1);

	for (s64 n = 0; n < struct_tstringlist->TStringList_Lines; n++) {
		if (struct_tstringlist->TStringList[n] != NULL) free(struct_tstringlist->TStringList[n]);
	}

	free(struct_tstringlist->TStringList);
	struct_tstringlist->TStringList = NULL;


	struct_tstringlist->TStringList_Lines = -1;
	struct_tstringlist->TStringList_Length_Max = -1;
	struct_tstringlist->COUNT_BYTES_FILE = -1;
	struct_tstringlist->COUNT_LINES_FILE = -1;

	return(0);

}





s64 CountLinesFile(void *self, char *file_name)
{
	long long n = 1;
	int c;
	FILE *fp;

	fp = fopen(file_name, "r");
	if (!fp) return(-1);

	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n') n++;
	}

	if (ferror(fp)) return(-1);

	fclose(fp);

	TStringList *struct_tstringlist = self;
	struct_tstringlist->COUNT_LINES_FILE = n;


	return(n);
}





s64 CountBytesFile(void *self, char *file_name)
{
	long n = 1;
	int c;
	FILE *fp;

	fp = fopen(file_name, "r");
	if (!fp) return(-1);


	while ((c = fgetc(fp)) != EOF) {
		n++;
	}

	if (ferror(fp)) { fclose(fp); return(-1); }

	fclose(fp);

	TStringList *struct_tstringlist = self;
	struct_tstringlist->COUNT_BYTES_FILE = n;

	return(n);
}





s64 SetLines(void *self, s64 numbers)
{
	TStringList *struct_tstringlist = self;

	if (numbers < 1) return(-1);
	if (numbers == struct_tstringlist->TStringList_Lines) return(0); //do nothing


	//New
	if (struct_tstringlist->TStringList_Lines == -1) {
		struct_tstringlist->TStringList = calloc(numbers, sizeof(char *));
		if (struct_tstringlist->TStringList == NULL) return(-1);
		struct_tstringlist->TStringList_Lines = numbers;

		//malloc
		//for (s64 n = 0; n < numbers; n++) struct_tstringlist->TStringList[n] = NULL;

		return(0);
	}

	//resize <
	if (numbers < struct_tstringlist->TStringList_Lines) {
		s64 diff = struct_tstringlist->TStringList_Lines - numbers;

		for (s64 n = diff - 1; n < struct_tstringlist->TStringList_Lines; n++) free(struct_tstringlist->TStringList[n]);

		struct_tstringlist->TStringList = realloc(struct_tstringlist->TStringList, numbers * sizeof(char *));
		struct_tstringlist->TStringList_Lines = numbers;

		return(0);
	}

	//resize >
	if (numbers > struct_tstringlist->TStringList_Lines) {
		s64 diff = numbers - struct_tstringlist->TStringList_Lines;

		char **tmp_ptr = struct_tstringlist->TStringList;
		tmp_ptr = realloc(tmp_ptr, numbers * sizeof(char *));
		if (tmp_ptr == NULL) return(-1);

		struct_tstringlist->TStringList = tmp_ptr;
		struct_tstringlist->TStringList_Lines = numbers;

		for (s64 n = diff - 1; n < struct_tstringlist->TStringList_Lines; n++) {
			struct_tstringlist->TStringList[n] = NULL;
		}


		return(0);
	}

	return(0);
}





s64 DynStrcpy (void *self, s64 number, char *newstring)
{
	TStringList *struct_tstringlist = self;

	if (number < 0 ) return(-1);
	if (struct_tstringlist->TStringList_Lines == -1) return(-1);
	if (struct_tstringlist->TStringList == NULL) return(-1);
	if (number >= struct_tstringlist->TStringList_Lines) return(-1);


	if (struct_tstringlist->TStringList[number] != NULL) free(struct_tstringlist->TStringList[number]);


	s64 len = strlen(newstring) + 1;
	struct_tstringlist->TStringList[number] = malloc(len * sizeof(char *));
	strcpy(struct_tstringlist->TStringList[number], newstring);

	return(0);

}





s64 DynStrcat (void *self, s64 number, char *newstring)
{
	TStringList *struct_tstringlist = self;

	if (number < 0 ) return(-1);
	if (number >= struct_tstringlist->TStringList_Lines) return(-1);
	if (struct_tstringlist->TStringList == NULL) return(-1);

	s64 len = strlen(struct_tstringlist->TStringList[number]) +  strlen(newstring) + 1;

	struct_tstringlist->TStringList[number] = realloc(struct_tstringlist->TStringList[number], len * sizeof(char *));
	strcat(struct_tstringlist->TStringList[number], newstring);

	return(0);

}





s64 Del(void *self, s64 number)
{
	TStringList *struct_tstringlist = self;
	s64 lines_max = struct_tstringlist->TStringList_Lines;

	if (number < 0) return(-1);
	if (number >= struct_tstringlist->TStringList_Lines) return(-1);


	//if number = last line
	if (number == struct_tstringlist->TStringList_Lines - 1) {
		//delete
		free(struct_tstringlist->TStringList[number]);
		struct_tstringlist->TStringList = realloc(struct_tstringlist->TStringList, (struct_tstringlist->TStringList_Lines - 1) * sizeof(char *));
		struct_tstringlist->TStringList_Lines--;
		return(0);
	}

	//delete
	free(struct_tstringlist->TStringList[number]);

	//address last line -> delete line
	struct_tstringlist->TStringList[number] = struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines - 1];

	struct_tstringlist->TStringList = realloc(struct_tstringlist->TStringList, (struct_tstringlist->TStringList_Lines - 1) * sizeof(char *));
	struct_tstringlist->TStringList_Lines--;

	return(0);
}





s64 CountLines(void *self)
{
	TStringList *struct_tstringlist = self;
	return(struct_tstringlist->TStringList_Lines);
}






s64 DelDup(void *self)
{
	TStringList *struct_tstringlist = self;

	qsort(struct_tstringlist->TStringList, struct_tstringlist->TStringList_Lines, sizeof(char *), str_compare);

	s64 counter = 0;
	for (s64 n = struct_tstringlist->TStringList_Lines - 1; n > 0; n--) {
		if (strcmp(struct_tstringlist->TStringList[n - 1], struct_tstringlist->TStringList[n]) == 0) {
			free(struct_tstringlist->TStringList[n]);
			struct_tstringlist->TStringList[n] = struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines - 1 - counter];
			counter++;
		}
	}


	struct_tstringlist->TStringList_Lines -= counter;
	struct_tstringlist->TStringList = realloc(struct_tstringlist->TStringList, struct_tstringlist->TStringList_Lines * sizeof(char *));

	return(0);
}





s64 StringLengthMax(void *self)
{
	TStringList *struct_tstringlist = self;
	return(struct_tstringlist->TStringList_Length_Max);
}





s64 LoadFromFile(void *self, char *file_name)
{
	long max_bytes = 0;
	int c;
	FILE *fp;
	long max_lines = 0;
	char *TEXT;
	long str_length = 0;



	fp = fopen(file_name, "r");
	if (!fp) return(-1);

	while ((c = fgetc(fp)) != EOF) {
		max_bytes++;
	}

	if (ferror(fp)) { fclose(fp); return(-1); }

	fseek(fp, 0, SEEK_SET);

	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n') max_lines++;
	}

	fseek(fp, 0, SEEK_SET);


	TEXT = calloc(max_bytes, sizeof(char));
	if (TEXT == NULL) { fclose(fp); return(-1); }

	fread(TEXT, max_bytes, sizeof(char), fp);

	if (ferror(fp)) { fclose(fp); return(-1); }

	fclose(fp);

	//Zeilen reservieren
	TStringList *struct_tstringlist = self;

	struct_tstringlist->COUNT_LINES_FILE = max_lines;
	struct_tstringlist->COUNT_BYTES_FILE = max_bytes;

	struct_tstringlist->TStringList = calloc(max_lines, sizeof(char *));
	if (struct_tstringlist->TStringList == NULL) return(-1);

	long lines = 0;
	long start = 0;
	long len = 0;


	for (int n = 0; n < max_bytes; n++) {
		if (TEXT[n] == '\n') {
			if (n > start) {
				struct_tstringlist->TStringList[lines] = malloc((n - start + 1) * sizeof(char));
				strncpy(struct_tstringlist->TStringList[lines], &TEXT[start], n - start);

				struct_tstringlist->TStringList[lines][n - start] = '\0';
				len = n - start;
				if (len > struct_tstringlist->TStringList_Length_Max) struct_tstringlist->TStringList_Length_Max = len;

				start = n + 1;
				lines++;
			}
			else start++;
		}
	}



	struct_tstringlist->TStringList_Lines = lines;

	if (struct_tstringlist->DelDUP == true) {
		qsort(struct_tstringlist->TStringList, struct_tstringlist->TStringList_Lines, sizeof(char *), str_compare);

		s64 counter = 0;
		for (s64 n = struct_tstringlist->TStringList_Lines - 1; n > 0; n--) {
			if (strcmp(struct_tstringlist->TStringList[n - 1], struct_tstringlist->TStringList[n]) == 0) {
				free(struct_tstringlist->TStringList[n]);
				struct_tstringlist->TStringList[n] = struct_tstringlist->TStringList[struct_tstringlist->TStringList_Lines - 1 - counter];
				counter++;
			}
		}

		struct_tstringlist->TStringList_Lines -= counter;
		struct_tstringlist->TStringList = realloc(struct_tstringlist->TStringList, struct_tstringlist->TStringList_Lines * sizeof(char *));
	}

	if (struct_tstringlist->SORT == true) {
		qsort(struct_tstringlist->TStringList, struct_tstringlist->TStringList_Lines, sizeof(char *), str_compare);
	}


	return(0);
}





//--------------------------------------------------------------------------------------------------------------------
s64 TStringListCreate(void *self) {


	TStringList *struct_tstringlist = self;


	struct_tstringlist->CountBytesFile = &CountBytesFile;
	struct_tstringlist->CountLinesFile = &CountLinesFile;
	struct_tstringlist->SetLines = &SetLines;
	struct_tstringlist->DynStrcpy = &DynStrcpy;
	struct_tstringlist->DynStrcat = &DynStrcat;
	struct_tstringlist->Del = &Del;
	struct_tstringlist->CountLines = &CountLines;
	struct_tstringlist->StringLengthMax = &StringLengthMax;
	struct_tstringlist->LoadFromFile = &LoadFromFile;
	struct_tstringlist->DelDup = &DelDup;
	struct_tstringlist->DynFree = &DynFree;
	struct_tstringlist->MaxStr = &MaxStr;
	struct_tstringlist->Add = &Add;
	struct_tstringlist->Sort = &Sort;
	struct_tstringlist->SetSort = &SetSort;
	struct_tstringlist->SetDelDUP = &SetDelDUP;


	struct_tstringlist->COUNT_BYTES_FILE = -1;
	struct_tstringlist->COUNT_LINES_FILE = -1;
	struct_tstringlist->TStringList_Length_Max = -1;
	struct_tstringlist->TStringList_Lines = -1;
	struct_tstringlist->DelDUP = false;
	struct_tstringlist->SORT = false;
	//(*struct_tstringlist).DelDUP = false;		//geht auch so

	return(0);
}


int ErrorMessage()
{
	printf("csafer, 2022/05 Peter Boettcher, Germany, Muelheim Ruhr\n");
	printf("VERSION            : C, LINUX VERSION\n");
	printf("\n");
	printf("\n");
	printf("Parameter   :  0 Safer ON\n");
	printf("Parameter   :  1 Safer OFF\n");
	printf("Parameter   :  3 Safer Printk ON\n");
	printf("Parameter   :  4 Safer Printk OFF\n");
	printf("\n");
	printf("Parameter   :  5 Safer CLEAR FILE LIST\n");
	printf("Parameter   :  6 Safer CLEAR FOLDER LIST\n");
	printf("\n");
	printf("Parameter   :  7 Safer ROOT LIST IN KERNEL ON\n");
	printf("Parameter   :  8 Safer ROOT LIST IN KERNEL OFF\n");
	printf("\n");
	printf("Parameter   :  9 Safer DO NOT allowed any more changes\n");
	printf("\n");
	printf("Parameter   : 10 Safer MODE: LEARNING ON\n");
	printf("Parameter   : 11 Safer MODE: LEARNING OFF\n");
	printf("\n");
	printf("Parameter   : 20 Safer SET FILE LIST\n");
	printf("            :    <safer list>\n");
	printf("\n");
	printf("Parameter   : 21 Safer SET FOLDER LIST\n");
	printf("            :    <safer list>\n");
	printf("\n");
	printf("Parameter   : 30 Safer LIST SORT\n");
	printf("            :    <safer list>\n");

	printf("\n");
	printf("\n");
	exit(0);
}







	TStringList all_list;
	TStringList folder_list;
	TStringList file_list;
	TStringList work_list;



//--------------------------------------------------------------------------------------------------
void main(int argc, char *argv[]) {

/* #define VERSION_SYSCALL */
#ifdef VERSION_SYSCALL
#define SYSCALL_NR 459
#else
#define SYSCALL_NR 59
#endif


	s64 NUMBER = 0;


	if (argc == 2) {
		if (TryStrToInt64 (argv[1], &NUMBER, 10) != 0) ErrorMessage();
		if (NUMBER < 0 || NUMBER > 11) ErrorMessage();


#ifdef VERSION_SYSCALL
		printf("%ld\n", syscall(SYSCALL_NR, 999900 + NUMBER));
#else
		printf("%ld\n", syscall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER));
#endif
		exit(0);
	}


	if (argc == 3) {
		if (TryStrToInt64 (argv[1], &NUMBER, 10) != 0) ErrorMessage();

		switch(NUMBER) {
			case 20:	TStringListCreate(&all_list);
					TStringListCreate(&file_list);
					all_list.SetDelDUP(&all_list, true);
					all_list.LoadFromFile(&all_list, argv[2]);

					if (all_list.TStringList_Lines == -1) ErrorMessage();

					for (s64 n = 0; n < all_list.TStringList_Lines; n++) {
						if (strncmp(all_list.TStringList[n], "a:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "d:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "ga:", 3) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "gd:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
						}
					}

					if (file_list.TStringList_Lines == -1 ) { printf("ERROR: NO ELEMENT IN LIST\n"); exit(1); }

					file_list.Sort(&file_list);
					TStringListCreate(&work_list);
					char str_len [19];
					sprintf(str_len, "%u", file_list.TStringList_Lines);	/* int to string */
					work_list.Add(&work_list, str_len);
					for (s64 n = 0; n < file_list.TStringList_Lines; n++) {
						work_list.Add(&work_list, file_list.TStringList[n]);
					}

					for (s64 n = 0; n < work_list.TStringList_Lines; n++) {
						printf("%s\n", work_list.TStringList[n]);
					}

#ifdef VERSION_SYSCALL
					printf("%ld\n", syscall(SYSCALL_NR, 999900 + NUMBER, work_list.TStringList));
#else
					printf("%ld\n", syscall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER, work_list.TStringList));
#endif

					exit(0);


			case 21:	TStringListCreate(&all_list);
					TStringListCreate(&folder_list);
					all_list.SetDelDUP(&all_list, true);

					all_list.LoadFromFile(&all_list, argv[2]);
					if (all_list.TStringList_Lines == -1) ErrorMessage();

					for (s64 n = 0; n < all_list.TStringList_Lines; n++) {
						if (strncmp(all_list.TStringList[n], "a:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] != '/') continue;
							folder_list.Add(&folder_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "d:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] != '/') continue;
							folder_list.Add(&folder_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "ga:", 3) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] != '/') continue;
							folder_list.Add(&folder_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "gd:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] != '/') continue;
							folder_list.Add(&folder_list, all_list.TStringList[n]);
						}
					}

					if (folder_list.TStringList_Lines == -1 ) { printf("ERROR: NO ELEMENT IN LIST\n"); exit(1); }
					folder_list.Sort(&folder_list);
					TStringListCreate(&work_list);
					sprintf(str_len, "%u", folder_list.TStringList_Lines);	/* int to string */
					work_list.Add(&work_list, str_len);
					for (s64 n = 0; n < folder_list.TStringList_Lines; n++) {
						work_list.Add(&work_list, folder_list.TStringList[n]);
					}

					for (s64 n = 0; n < work_list.TStringList_Lines; n++) {
						printf("%s\n", work_list.TStringList[n]);
					}
#ifdef VERSION_SYSCALL
					printf("%ld\n", syscall(SYSCALL_NR, 999900 + NUMBER, work_list.TStringList));
#else
					printf("%ld\n", syscall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER, work_list.TStringList));
#endif

					exit(0);



			case 30:	TStringListCreate(&all_list);
					TStringListCreate(&file_list);
					all_list.SetDelDUP(&all_list, true);
					all_list.LoadFromFile(&all_list, argv[2]);

					if (all_list.TStringList_Lines == -1) ErrorMessage();

					for (s64 n = 0; n < all_list.TStringList_Lines; n++) {
						if (strncmp(all_list.TStringList[n], "a:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "d:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "ga:", 3) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
							continue;
						}

						if (strncmp(all_list.TStringList[n], "gd:", 2) == 0) {
							s64 last = strlen(all_list.TStringList[n]);
							if (all_list.TStringList[n][last - 1] == '/') continue;
							file_list.Add(&file_list, all_list.TStringList[n]);
						}
					}

					if (file_list.TStringList_Lines == -1 ) { printf("ERROR: NO ELEMENT IN LIST\n"); exit(1); }

					file_list.Sort(&file_list);
					TStringListCreate(&work_list);
					//char str_len [19];
					sprintf(str_len, "%u", file_list.TStringList_Lines);	/* int to string */
					work_list.Add(&work_list, str_len);
					for (s64 n = 0; n < file_list.TStringList_Lines; n++) {
						work_list.Add(&work_list, file_list.TStringList[n]);
					}

					for (s64 n = 0; n < work_list.TStringList_Lines; n++) {
						printf("%s\n", work_list.TStringList[n]);
					}

					exit(0);

			ErrorMessage();
		}
	}

	ErrorMessage();

}














