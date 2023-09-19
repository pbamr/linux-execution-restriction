/* Copyright (c) 2022/03/28, 2022.09.17, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.03.28, 2022.09.17, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */



/*
	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.04.22, 2023.05.23

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 6.5
			  Lenovo X230, T460, T470

	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root

			: USER and GROUPS
			  IMPORTANT: file size will test

			: Extension of SYSCALL <execve>
			  You found <replaces> under "pb_safer"

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas, csafer.c
			: Simple Control Program for Extension <SYSCALL execve>
			: It only works as <root>

	LIST		: If you use binary search, a sorted list ist required
			: ALLOWED and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable files in folder
			: Several thousand entries are then no problem.

	root		: ALLOWED LIST for root is fixed in the code


	Standard	: Safer Mode = ON
			: Log Mode = Logs all programs from init

			: 999900 = safer ON
			: 999901 = safer OFF
			: 999902 = State
			: 999903 = Log ON
			: 999904 = Log OFF

			: 999905 = Clear FILE List
			: 999906 = Clear FOLDER List

			: 999907 = ROOT LIST IN KERNEL ON
			: 999908 = ROOT LIST IN KERNEL OFF

			: 999909 = LOCK changes

			: 999910 = learning ON
			: 999911 = learning OFF

			: 999920 = Set FILE List
			: 999921 = Set FOLDER List


	Important	: ./foo is not allowed
			: But not absolutely necessary for me
			: It is not checked whether the program really exists
			: This is not necessary

			: "make bzImage" need this feature
			: The Solutions is Safer OFF

			: scripts will test
			  scripts will test in this form: "python Path/prog"
			  scripts in this form ar allowed: "/path/prog"


	FILE/FOLDER List: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

			: string = USER-ID;FILE-SIZE;PATH
			: string = GROUP-ID;FILE-SIZEPATH
			: string = File Size

			: string = allow:USER-ID;FILE-SIZE;PATH
			: string = deny:GROUP-ID;PATH

			: a:USER-ID;Path
			: d:USER-ID;Path

			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path

			: Example: user
			: a:100;1224;/bin/test		= allow file
			: a:100;1234;/bin/test1		= allow file
			: a:100;/usr/sbin/		= allow Folder

			: Example: user
			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny folder

			: Example: Group
			: ga:100;/usr/sbin/		= allow group folder
			: gd:100;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;1234;/usr/bin/mc	= allow group file

			: Example: User
			: user
			: as:1000;12342/usr/bin/python	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow 
			: as:1000;123422/usr/bin/ruby	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow

			: Example: Group
			: gas:1000;1234/usr/bin/python	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow
			: gas:1000;12343/usr/bin/php	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow

			: Important:
			: java is special
			: java need no "as or gas"

			: It is up to the ADMIN to keep the list reasonable according to these rules!


	Thanks		: Linus Torvalds and others


	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, CARLA FRACCI, EVA EVDOKIMOVA, VAKHTANG CHABUKIANI and the
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Admirable ballet dancers.
	

*/


#define PRINTK
#define MAX_DYN 100000
#define RET_SHELL -2

#define NO_SECURITY_GUARANTEED "SAFER: Could not allocate buffer! Security is no longer guaranteed!\n"


/* test */
/* static char MY_NAME[] = "(C) Peter Boettcher, Muelheim Ruhr, 2023/1, safer"; */



static bool	safer_mode = false;
static bool	printk_mode = false;
static bool	safer_root_list_in_kernel_mode = false;
static bool	learning_mode = true;
static bool	change_mode = true;

static char	**file_list = NULL;
static long	file_list_max = 0;

static char	**file_learning_list = NULL;
static long	file_learning_list_max = 0;

static char	**file_argv_list = NULL;
static long	file_argv_list_max = 0;

static char	**folder_list = NULL;
static long	folder_list_max = 0;


static void	*data = NULL;

static void	*ptr = NULL;




/* def. */
struct  safer_info_struct {
	bool safer_mode;
	bool printk_mode;
	bool learning_mode;
	bool change_mode;
	bool safer_root_list_in_kernel_mode;
	long file_list_max;
	long folder_list_max;
	char **file_list;
	char **folder_list;
};


/* DATA: Only over function */
void safer_info(struct safer_info_struct *info)
{
	info->safer_mode = safer_mode;
	info->printk_mode = printk_mode;
	info->learning_mode = learning_mode;
	info->change_mode = change_mode;
	info->safer_root_list_in_kernel_mode = safer_root_list_in_kernel_mode;
	info->file_list_max = file_list_max;
	info->folder_list_max = folder_list_max;
	info->file_list = file_list;
	info->folder_list = folder_list;
}




/* def. */
struct  safer_learning_struct {
	long file_learning_list_max;
	char **file_learning_list;
	long file_argv_list_max;
	char **file_argv_list;
};



/* DATA: Only over function */
void safer_learning(struct safer_learning_struct *learning)
{
	learning->file_learning_list_max = file_learning_list_max;
	learning->file_learning_list = file_learning_list;
	learning->file_argv_list_max = file_argv_list_max;
	learning->file_argv_list = file_argv_list;

}




static int besearch_file(char *str_search, char **list, long elements)
{
	long left, right;
	long middle;
	long int_ret;

	left = 0;
	right = elements - 1;

	while(left <= right) {
		middle = (left + right) / 2;

		int_ret = strcmp(list[middle], str_search);

		if (int_ret == 0) return(0);
		else if (int_ret < 0) left = middle + 1;
		else if (int_ret > 0) right = middle - 1;
	}

	return(-1);
}



static int besearch_folder(char *str_search, char **list, long elements)
{
	long left, right;
	long middle;
	long int_ret;


	if (str_search[strlen(str_search) -1] == '/' ) return(-1);


	left = 0;
	right = elements - 1;

	while(left <= right) {
		middle = (left + right) / 2;

		int_ret = strncmp(list[middle], str_search, strlen(list[middle]));

		if (int_ret == 0) return(0);
		else if (int_ret < 0) left = middle + 1;
		else if (int_ret > 0) right = middle - 1;
	}

	return(-1);
}




static long search(char *str_search, char **list, long elements)
{
	long n;

	for (n = 0; n < elements; n++) {
		if (strncmp(list[n], str_search, strlen(list[n])) == 0) return(0);
	}

	return(-1);
}







static int allowed_deny_exec_first_step(const char *filename, char **argv, int parameter_max)
{
	uid_t	user_id;
	u32	n, n0;
	char	str_user_id[19];
	char	str_group_id[19];
	char	str_file_size[19];

	u64	str_length;
	char	*str_file_name = NULL;
	char	*str_java_name = NULL;
	//s64	parameter_max;

	struct group_info *group_info;

	size_t	file_size = 0;
	ssize_t	ret;


	user_id = get_current_user()->uid.val;

	if (learning_mode == true) {
		//parameter_max = count_strings_kernel(argv);
		//if (parameter_max > 16) parameter_max = 16;

		for (n = 1; n < parameter_max; n++) {

			ret = kernel_read_file_from_path(argv[n], 0, &data, 0, &file_size, READING_POLICY);

			if (ret == 0) {
				sprintf(str_user_id, "%u", user_id);				/* int to string */
				sprintf(str_file_size, "%lu", file_size);			/* int to string */
				str_length = strlen(str_user_id);				/* str_user_id len*/
				str_length += strlen(str_file_size);				/* str_user_id len*/
				str_length += strlen(argv[n]) + 4;				/* plus 2 semikolon + a: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name != NULL) {
					strcpy(str_file_name, "a:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, str_file_size);				/* str_file_size */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n]);					/* + filename */
				}

				if (file_learning_list_max > 0) {
					if (search(str_file_name, file_learning_list, file_learning_list_max) == 0) continue;
				}

				if (file_argv_list_max > 0) {
					if (search(str_file_name, file_argv_list, file_argv_list_max) == 0) continue;
				}

				file_argv_list_max += 1;
				ptr = file_argv_list;
				file_argv_list = krealloc(file_argv_list, file_argv_list_max * sizeof(char *), GFP_KERNEL);

				if (file_argv_list != NULL) {
					file_argv_list[file_argv_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					if (file_argv_list[file_argv_list_max - 1] != NULL) strcpy(file_argv_list[file_argv_list_max - 1], str_file_name);
				}
				else file_argv_list = ptr;
			}
		}
	}


	ret = kernel_read_file_from_path(filename, 0, &data, 0, &file_size, READING_POLICY);

	if (printk_mode == true) {
		/* max. argv */
		for ( n = 0; n < parameter_max; n++) {
				printk("USER ID:%u, PROG:%s, SIZE:%lu, argv[%d]:%s\n", user_id, filename, file_size, n, argv[n]);
		}
		if (ret != 0) {
			printk("URGENT: PROG. NOT EXIST, OR NO RIGHTS\n");
			return(RET_SHELL);
		}
	}

	if (ret != 0) return(RET_SHELL);

	if (safer_mode == true) {
		/* --------------------------------------------------------------------------------- */
		/* my choice */
		if (user_id == 0) {
			if (safer_root_list_in_kernel_mode == true) {
				//goto prog_exit_allowed;


				if (strncmp("/bin/", filename, 5) == 0) goto prog_exit_allowed;
				if (strncmp("/sbin/", filename, 6) == 0) goto prog_exit_allowed;
				if (strncmp("/usr/bin/", filename, 9) == 0) goto prog_exit_allowed;
				if (strncmp("/usr/sbin/", filename, 10) == 0) goto prog_exit_allowed;
				if (strncmp("/usr/games/", filename, 11) == 0)  goto prog_exit_allowed;
				if (strncmp("/usr/lib/", filename, 9) == 0)  goto prog_exit_allowed;
				if (strncmp("/usr/libexec/", filename, 13) == 0) goto prog_exit_allowed;
				if (strncmp("/usr/local/", filename, 11) == 0)  goto prog_exit_allowed;
				if (strncmp("/usr/share/", filename, 11) == 0)  goto prog_exit_allowed;
				/* my choice */
				if (strncmp("/usr/scripts/", filename, 13) == 0) goto prog_exit_allowed;

				if (strncmp("/lib/", filename, 5) == 0) goto prog_exit_allowed;
				if (strncmp("/lib64/", filename, 7) == 0)  goto prog_exit_allowed;
				if (strncmp("/opt/", filename, 5) == 0) goto prog_exit_allowed;
				if (strncmp("/etc/", filename, 5) == 0) goto prog_exit_allowed;

				if (strncmp("/var/lib/", filename, 9) == 0) goto prog_exit_allowed;
				/* Example: docker required /proc/self/exe */

				if (strncmp("/proc/", filename, 6) == 0) goto prog_exit_allowed;

				/* NOT allowed. */
				printk("ALLOWED LIST: USER/PROG. NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				return(RET_SHELL);
			}
		}

		/* --------------------------------------------------------------------------------- */
		sprintf(str_user_id, "%u", user_id);				/* int to string */
		str_length = strlen(str_user_id);				/* str_user_id len*/
		str_length += strlen(filename) + 3;				/* plus 1 = semikolon + d: */

		if (str_file_name != NULL) {
			kfree(str_file_name);
			str_file_name = NULL;
		}

		str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
		if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

		strcpy(str_file_name, "d:");
		strcat(str_file_name, str_user_id);				/* str_user_id */
		strcat(str_file_name, ";");					/* + semmicolon */
		strcat(str_file_name, filename);				/* + filename */

		if (folder_list_max > 0) {
			/* Importend! need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
			/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
				return(RET_SHELL);
			}
		}


		if (file_list_max > 0) {
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
				/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
				if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
				return(RET_SHELL);
			}
		}

		/* -------------------------------------------------------------------------------------------------- */
		/* deny groups */
		group_info = get_current_groups();

		for (n = 0; n < group_info->ngroups; n++) {

			sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
			str_length = strlen(str_group_id);				/* str_user_id len*/
			str_length += strlen(filename) + 4;				/* plus 1 = semikolon + gd: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "gd:");
			strcat(str_file_name, str_group_id);				/* str_group_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			if (folder_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
					if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
					return(RET_SHELL);
				}
			}


			if (file_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
					if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
					return(RET_SHELL);
				}
			}
		}

		/* first allowed files */
		/* allowed user file */
		if (file_list_max > 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			sprintf(str_file_size, "%lu", file_size);			/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(str_file_size);				/* str_user_id len*/
			str_length += strlen(filename) + 4;				/* plus 2 semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "a:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, str_file_size);				/* str_file_size */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			/* Importend! Need qsorted list */
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
		}

		/* first allowed files */
		/* allowed user file scripts languages, like python etc. */
		if (file_list_max > 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			sprintf(str_file_size, "%lu", file_size);			/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(str_file_size);				/* str_user_id len*/
			str_length += strlen(filename) + 5;				/* plus 2 semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "as:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, str_file_size);				/* str_file_size */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			/* Importend! Need qsorted list */
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
		}


		/* allowed groups file */
		group_info = get_current_groups();
		for (n = 0; n < group_info->ngroups; n++) {
			/* if (group_info->gid[n].val == 0) continue; */				/* group root not allowed. My choice! */

			/* allowed groups file */
			if (file_list_max > 0) {
				sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
				sprintf(str_file_size, "%lu", file_size);			/* int to string */
				str_length = strlen(str_group_id);				/* str_user_id len*/
				str_length += strlen(str_file_size);				/* str_user_id len*/
				str_length += strlen(filename) + 5;				/* plus 2 semikolon + ga: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

				strcpy(str_file_name, "ga:");
				strcat(str_file_name, str_group_id);				/* str_user_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, str_file_size);				/* str_file_size */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* Importend! Need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
			}
		}

		/* allowed groups file scripts languages, like python */
		group_info = get_current_groups();
		for (n = 0; n < group_info->ngroups; n++) {
			/* if (group_info->gid[n].val == 0) continue; */				/* group root not allowed. My choice! */

			/* allowed groups file */
			if (file_list_max > 0) {
				sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
				sprintf(str_file_size, "%lu", file_size);			/* int to string */
				str_length = strlen(str_group_id);				/* str_user_id len*/
				str_length += strlen(str_file_size);				/* str_user_id len*/
				str_length += strlen(filename) + 6;				/* plus 2 semikolon + ga: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

				strcpy(str_file_name, "gas:");
				strcat(str_file_name, str_group_id);				/* str_user_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, str_file_size);				/* str_file_size */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* Importend! Need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
			}
		}



		/* --------------------------------------------------------------------------------------------- */
		/* allowed user folder*/
		if (folder_list_max > 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(filename) + 3;				/* plus 1 = semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "a:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			/* Importend! Need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_allowed;
		}


		/* -------------------------------------------------------------------------------------------------- */
		/* allowed groups */
		group_info = get_current_groups();
		for (n = 0; n < group_info->ngroups; n++) {

			/* allowed groups folder */
			if (folder_list_max > 0) {
				sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
				str_length = strlen(str_group_id);				/* str_user_id len*/
				str_length += strlen(filename) + 4;				/* plus 1 = semikolon + ga: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

				strcpy(str_file_name, "ga:");
				strcat(str_file_name, str_group_id);				/* str_group_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* Importend! Need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_allowed;
			}
		}

		/* ------------------------------------------------------------------------------------------------- */
		/* Not allowed */
		printk("ALLOWED LIST: USER/PROG. NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
		if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
		return(RET_SHELL);
	}

prog_allowed:

	/* simple */
	/* test script files.max 10 param. */
	/* this form will test: python "/abc/def/prog". name only is not allowed. "python hello" etc. is not allowed */
	/* The full path is necessary */

	if (safer_mode == true) {
		if (strncmp(str_file_name, "as:", 3) == 0 || \
		strncmp(str_file_name, "gas:", 4) == 0) {
			//parameter_max = count_strings_kernel(argv);
			if (parameter_max == 1) {			/*goto prog_exit_allowed; */
				printk("ALLOWED LIST: <PROGRAM> NOT ALLOWED WITHOUT SCRIPT: %u;%lu;%s\n", user_id, file_size, filename);
				if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
				return(RET_SHELL);
			}


			for ( n = 1; n < parameter_max; n++) {
				file_size = 0;
				/* HASH */
				ret = kernel_read_file_from_path(argv[n], 0, &data, 0, &file_size, READING_POLICY);
				if (ret == 0) {
					/* group_info = get_current_groups(); */

					/* deny ---------------------------------------------------------------------- */
					/* deny user folder */
					sprintf(str_user_id, "%u", user_id);				/* int to string */
					sprintf(str_file_size, "%lu", file_size);			/* int to string */
					str_length = strlen(str_user_id);				/* str_user_id len*/
					str_length += strlen(argv[n]) + 3;				/* plus 1 = semikolon + d: */

					if (str_file_name != NULL) {
						kfree(str_file_name);
						str_file_name = NULL;
					}

					str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

					strcpy(str_file_name, "d:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n]);					/* + filename */

					/* Importend! Need qsorted list */
					if (folder_list_max > 0) {
						if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
							/* Not allowed */
							printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
							if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
							return(RET_SHELL);
						}
					}

					/* deny user file */
					sprintf(str_user_id, "%u", user_id);				/* int to string */
					sprintf(str_file_size, "%lu", file_size);			/* int to string */
					str_length = strlen(str_user_id);				/* str_user_id len*/
					str_length += strlen(argv[n]) + 3;				/* plus 1 = semikolon + d: */

					if (str_file_name != NULL) {
						kfree(str_file_name);
						str_file_name = NULL;
					}

					str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

					strcpy(str_file_name, "d:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");
					strcat(str_file_name, argv[n]);					/* + filename */

					if (file_list_max > 0) {
						if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
							/* Not allowed */
							printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
							if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
							return(RET_SHELL);
						}
					}


					/* deny group folder */
					for (n0 = 0; n0 < group_info->ngroups; n0++) {
						/* if (group_info->gid[n0].val == 0) continue; */			/* group root not allowed. My choice! */

						sprintf(str_group_id, "%u", group_info->gid[n0].val);		/* int to string */
						str_length = strlen(str_group_id);				/* str_group id len*/
						str_length += strlen(argv[n]) + 4;				/* plus 1 = semikolon + ga: */

						if (str_file_name != NULL) {
							kfree(str_file_name);
							str_file_name = NULL;
						}

						str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
						if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

						strcpy(str_file_name, "gd:");
						strcat(str_file_name, str_group_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, argv[n]);					/* + filename */

						if (folder_list_max > 0) {
							if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
								/* Not allowed */
								printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
								if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
								return(RET_SHELL);
							}
						}
					}

					/* deny group file */
					for (n0 = 0; n0 < group_info->ngroups; n0++) {
						/*if (group_info->gid[n0].val == 0) continue; */			/* group root not allowed. My choice! */

						sprintf(str_group_id, "%u", group_info->gid[n0].val);		/* int to string */
						str_length = strlen(str_group_id);				/* str_group id len*/
						str_length += strlen(argv[n]) + 4;				/* plus 1 = semikolon + ga: */

						if (str_file_name != NULL) {
							kfree(str_file_name);
							str_file_name = NULL;
						}

						str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
						if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

						strcpy(str_file_name, "gd:");
						strcat(str_file_name, str_group_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, argv[n]);					/* + filename */

						if (file_list_max > 0) {
							if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
								/* Not allowed */
								printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
								if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
								return(RET_SHELL);
							}
						}
					}

					/* ---------------------------------------------------------------------- */
					/* first allowed files */
					/* allowed user file */
					sprintf(str_user_id, "%u", user_id);				/* int to string */
					sprintf(str_file_size, "%lu", file_size);			/* int to string */
					str_length = strlen(str_user_id);				/* str_user_id len*/
					str_length += strlen(argv[n]) + 4;				/* plus 1 = semikolon + d: */

					if (str_file_name != NULL) {
						kfree(str_file_name);
						str_file_name = NULL;
					}

					str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

					strcpy(str_file_name, "a:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, str_file_size);
					strcat(str_file_name, ";");
					strcat(str_file_name, argv[n]);					/* + filename */

					if (file_list_max > 0)
						if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */

					/* allowed group file */
					for (n0 = 0; n0 < group_info->ngroups; n0++) {
						/*if (group_info->gid[n0].val == 0) continue; */			/* group root not allowed. My choice! */

						sprintf(str_group_id, "%u", group_info->gid[n0].val);		/* int to string */
						str_length = strlen(str_group_id);				/* str_group id len*/
						str_length += strlen(argv[n]) + 5;				/* plus 1 = semikolon + ga: */

						if (str_file_name != NULL) {
							kfree(str_file_name);
							str_file_name = NULL;
						}

						str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
						if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);


						strcpy(str_file_name, "ga:");
						strcat(str_file_name, str_group_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, str_file_size);
						strcat(str_file_name, ";");
						strcat(str_file_name, argv[n]);					/* + filename */

						if (file_list_max > 0)
							if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
					}


					/* allowed ---------------------------------------------------------- */
					/* allowed user folder */
					sprintf(str_user_id, "%u", user_id);				/* int to string */
					sprintf(str_file_size, "%lu", file_size);			/* int to string */
					str_length = strlen(str_user_id);				/* str_user_id len*/
					str_length += strlen(argv[n]) + 3;				/* plus 1 = semikolon + d: */

					if (str_file_name != NULL) {
						kfree(str_file_name);
						str_file_name = NULL;
					}

					str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

					strcpy(str_file_name, "a:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n]);					/* + filename */

					/* Importend! Need qsorted list */
					if (folder_list_max > 0)
						if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_exit_allowed;


					/* allowed group folder */
					for (n0 = 0; n0 < group_info->ngroups; n0++) {
						/* if (group_info->gid[n0].val == 0) continue; */			/* group root not allowed. My choice! */

						sprintf(str_group_id, "%u", group_info->gid[n0].val);		/* int to string */
						str_length = strlen(str_group_id);				/* str_group id len*/
						str_length += strlen(argv[n]) + 4;				/* plus 1 = semikolon + ga: */

						if (str_file_name != NULL) {
							kfree(str_file_name);
							str_file_name = NULL;
						}

						str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
						if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

						strcpy(str_file_name, "ga:");
						strcat(str_file_name, str_group_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, argv[n]);					/* + filename */

						if (folder_list_max > 0)
							if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_exit_allowed;
					}
				}
			}

			/* not in allowed list */
			for (n = 1; n < parameter_max; n++) {
				file_size = 0;
				ret = kernel_read_file_from_path(argv[n], 0, &data, 0, &file_size, READING_POLICY);
				if (ret == 0) printk("ALLOWED LIST: <USER/SCRIPT/MODULE> NOT IN LIST: %u;%lu;%s\n", user_id, file_size, argv[n]);
				else printk("URGENT: <SCRIPT/MODULE> NOT EXIST %u;0;%s\n", user_id, argv[n]);
			}
			if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
			return(RET_SHELL);
		}



		/* simple */
		/* java special */
		/* only user no group */
		/* this form will test: "java -classpath PATH name" IMPORTANT: PATH without last "/" */
		/*                    : "java -jar /PATH/name.jar */
		/* other not allowed */
		if (strncmp(filename, "/usr/bin/java", 13) == 0) {
			//parameter_max = count_strings_kernel(argv);				/* check Parameter */
			if (parameter_max == 1) goto prog_exit_allowed;				/* without Parameters */


			/* test "-classpath" */
			if (parameter_max == 4) {
				if (strcmp(argv[1], "-classpath") == 0) {
					if (str_java_name != NULL) {
						kfree(str_java_name);
						str_java_name = NULL;
					}


					str_length = strlen(argv[2]);						/* path */
					if (argv[2][strlen(argv[2]) - 1] != '/') str_length += 1;		/* slash yes or no */
					str_length += strlen(argv[3]);						/* name */
					str_length += strlen(".class");						/* extension */

					str_java_name = kmalloc((str_length + 1)  * sizeof(char), GFP_KERNEL);
					if (str_java_name == NULL) panic(NO_SECURITY_GUARANTEED);


					strcpy(str_java_name, argv[2]);						/* path */
					if (argv[2][strlen(argv[2]) - 1] != '/') strcat(str_java_name, "/");
					strcat(str_java_name, argv[3]);
					strcat(str_java_name, ".class");


					ret = kernel_read_file_from_path(str_java_name, 0, &data, 0, &file_size, READING_POLICY);
					if (ret == 0) {
						/* folder test */
						if (folder_list_max > 0) {
							sprintf(str_user_id, "%u", user_id);				/* int to string */
							str_length = strlen(str_user_id);				/* str_user_id len*/
							str_length += strlen(str_java_name) + 3;			/* plus 1 = semikolon + a: */

							if (str_file_name != NULL) {
								kfree(str_file_name);
								str_file_name = NULL;
							}

							str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
							if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

							strcpy(str_file_name, "a:");
							strcat(str_file_name, str_user_id);				/* str_user_id */
							strcat(str_file_name, ";");					/* + semmicolon */
							strcat(str_file_name, str_java_name);				/* + filename */

							if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_exit_allowed; /* OK in list */
						}

						/* file test */
						if (file_list_max > 0) {
							sprintf(str_user_id, "%u", user_id);				/* int to string */
							sprintf(str_file_size, "%lu", file_size);			/* int to string */
							str_length = strlen(str_user_id);				/* str_user_id len*/
							str_length += strlen(str_java_name) + 4;			/* plus 1 = semikolon + a: */

							if (str_file_name != NULL) {
								kfree(str_file_name);
								str_file_name = NULL;
							}

							str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
							if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);


							strcpy(str_file_name, "a:");
							strcat(str_file_name, str_user_id);				/* str_user_id */
							strcat(str_file_name, ";");					/* + semmicolon */
							strcat(str_file_name, str_file_size);
							strcat(str_file_name, ";");
							strcat(str_file_name, str_java_name);				/* + filename */

							if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
							printk("ALLOWED LIST: USER/PROG. <CLASS> NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
							if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
							return(RET_SHELL);
						}
					}
				}
			}

			/* test "-jar" */
			if (parameter_max == 3) {
				if (strcmp(argv[1], "-jar") == 0) {
					ret = kernel_read_file_from_path(argv[2], 0, &data, 0, &file_size, READING_POLICY);
					if (ret == 0) {
						/* folder test */
						if (folder_list_max > 0) {
							sprintf(str_user_id, "%u", user_id);				/* int to string */
							str_length = strlen(str_user_id);				/* str_user_id len*/
							str_length += strlen(argv[2]) + 3;				/* plus 1 = semikolon + a: */

							if (str_file_name != NULL) {
								kfree(str_file_name);
								str_file_name = NULL;
							}

							str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
							if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

							strcpy(str_file_name, "a:");
							strcat(str_file_name, str_user_id);				/* str_user_id */
							strcat(str_file_name, ";");					/* + semmicolon */
							strcat(str_file_name, argv[2]);					/* + filename */

							if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_exit_allowed; /* OK in list */
						}

						if (file_list_max > 0) {
							/* file test */
							sprintf(str_user_id, "%u", user_id);				/* int to string */
							sprintf(str_file_size, "%lu", file_size);			/* int to string */
							str_length = strlen(str_user_id);				/* str_user_id len*/
							str_length += strlen(str_file_size);
							str_length += strlen(argv[2]) + 4;				/* plus 1 = semikolon + a: */

							if (str_file_name != NULL) {
								kfree(str_file_name);
								str_file_name = NULL;
							}

							str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
							if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

							strcpy(str_file_name, "a:");
							strcat(str_file_name, str_user_id);				/* str_user_id */
							strcat(str_file_name, ";");					/* + semmicolon */
							strcat(str_file_name, str_file_size);
							strcat(str_file_name, ";");
							strcat(str_file_name, argv[2]);					/* + filename */

							if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
							printk("ALLOWED LIST: USER/PROG. <CLASS/JAR> NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
							if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
							return(RET_SHELL);
						}
					}
				}
			}


			printk("ALLOWED LIST: USER/PROG. <CLASS/JAR> NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
			if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
			return(RET_SHELL);
		}


/* END SCRIPTS CHECK */
/*-----------------------------------------------------------------*/
	}

prog_exit_allowed:
	if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
	return(0);

}








static int allowed_deny_exec_sec_step(const char *filename)
{
	uid_t	user_id;
	u32	n;
	char	str_user_id[19];
	char	str_group_id[19];
	char	str_file_size[19];

	u64	str_length;
	char	*str_file_name = NULL;

	struct group_info *group_info;

	size_t	file_size = 0;

	ssize_t	ret;



	ret = kernel_read_file_from_path(filename, 0, &data, 0, &file_size, READING_POLICY);
	user_id = get_current_user()->uid.val;

	if (learning_mode == true) {
		if (ret == 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			sprintf(str_file_size, "%lu", file_size);			/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(str_file_size);				/* str_user_id len*/
			str_length += strlen(filename) + 4;				/* plus 2 semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}
			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "a:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, str_file_size);				/* str_file_size */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			if (file_learning_list_max > 0) {
				if (search(str_file_name, file_learning_list, file_learning_list_max) != 0) {
					file_learning_list_max += 1;
					ptr = file_learning_list;
					file_learning_list = krealloc(file_learning_list, file_learning_list_max * sizeof(char *), GFP_KERNEL);

					if (file_learning_list != NULL) {
						file_learning_list[file_learning_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
						if (file_learning_list[file_learning_list_max - 1] != NULL) strcpy(file_learning_list[file_learning_list_max -1], str_file_name);
					}
					else file_learning_list = ptr;
				}
			}
			else {
				file_learning_list_max += 1;
				ptr = file_learning_list;
				file_learning_list = krealloc(file_learning_list, file_learning_list_max * sizeof(char *), GFP_KERNEL);

				if (file_learning_list != NULL) {
					file_learning_list[file_learning_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					if (file_learning_list[file_learning_list_max - 1] != NULL) strcpy(file_learning_list[file_learning_list_max - 1], str_file_name);
				}
				else file_learning_list = ptr;

			}
		}
	}


	if (safer_mode == true) {
		/* --------------------------------------------------------------------------------- */
		/* my choice */
		if (user_id == 0) {
			if (safer_root_list_in_kernel_mode == true) {
				//goto prog_allowed;

				if (strncmp("/bin/", filename, 5) == 0) goto prog_allowed;
				if (strncmp("/sbin/", filename, 6) == 0) goto prog_allowed;
				if (strncmp("/usr/bin/", filename, 9) == 0) goto prog_allowed;
				if (strncmp("/usr/sbin/", filename, 10) == 0) goto prog_allowed;
				if (strncmp("/usr/games/", filename, 11) == 0)  goto prog_allowed;
				if (strncmp("/usr/lib/", filename, 9) == 0)  goto prog_allowed;
				if (strncmp("/usr/libexec/", filename, 13) == 0) goto prog_allowed;
				if (strncmp("/usr/local/", filename, 11) == 0)  goto prog_allowed;
				if (strncmp("/usr/share/", filename, 11) == 0)  goto prog_allowed;
				/* my choice */
				if (strncmp("/usr/scripts/", filename, 13) == 0) goto prog_allowed;

				if (strncmp("/lib/", filename, 5) == 0) goto prog_allowed;
				if (strncmp("/lib64/", filename, 7) == 0)  goto prog_allowed;
				if (strncmp("/opt/", filename, 5) == 0) goto prog_allowed;
				if (strncmp("/etc/", filename, 5) == 0) goto prog_allowed;

				if (strncmp("/var/lib/", filename, 9) == 0) goto prog_allowed;
				/* Example: docker required /proc/self/exe */

				if (strncmp("/proc/", filename, 6) == 0) goto prog_allowed;

				/* NOT allowed. */
				printk("ALLOWED LIST: USER/PROG. NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				return(RET_SHELL);
			}
		}

		/* --------------------------------------------------------------------------------- */
		sprintf(str_user_id, "%u", user_id);				/* int to string */
		str_length = strlen(str_user_id);				/* str_user_id len*/
		str_length += strlen(filename) + 3;				/* plus 1 = semikolon + d: */

		if (str_file_name != NULL) {
			kfree(str_file_name);
			str_file_name = NULL;
		}

		str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
		if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);


		strcpy(str_file_name, "d:");
		strcat(str_file_name, str_user_id);				/* str_user_id */
		strcat(str_file_name, ";");					/* + semmicolon */
		strcat(str_file_name, filename);				/* + filename */

		if (folder_list_max > 0) {
			/* Importend! need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
			/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
				return(RET_SHELL);
			}
		}


		if (file_list_max > 0) {
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
				/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
				if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
				return(RET_SHELL);
			}
		}

		/* -------------------------------------------------------------------------------------------------- */
		/* deny groups */
		group_info = get_current_groups();

		for (n = 0; n < group_info->ngroups; n++) {

			sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
			str_length = strlen(str_group_id);				/* str_user_id len*/
			str_length += strlen(filename) + 4;				/* plus 1 = semikolon + gd: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "gd:");
			strcat(str_file_name, str_group_id);				/* str_group_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			if (folder_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
					if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
					return(RET_SHELL);
				}
			}


			if (file_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
					if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
					return(RET_SHELL);
				}
			}
		}

		/* --------------------------------------------------------------------------------------------- */
		/* allowed user folder*/

		if (folder_list_max > 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(filename) + 3;				/* plus 1 = semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "a:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			/* Importend! Need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_allowed;
		}


		if (file_list_max > 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			sprintf(str_file_size, "%lu", file_size);			/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(str_file_size);				/* str_user_id len*/
			str_length += strlen(filename) + 4;				/* plus 2 semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "a:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, str_file_size);				/* str_file_size */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			/* Importend! Need qsorted list */
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
		}


		if (file_list_max > 0) {
			sprintf(str_user_id, "%u", user_id);				/* int to string */
			sprintf(str_file_size, "%lu", file_size);			/* int to string */
			str_length = strlen(str_user_id);				/* str_user_id len*/
			str_length += strlen(str_file_size);				/* str_user_id len*/
			str_length += strlen(filename) + 5;				/* plus 2 semikolon + a: */

			if (str_file_name != NULL) {
				kfree(str_file_name);
				str_file_name = NULL;
			}

			str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
			if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

			strcpy(str_file_name, "as:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, str_file_size);				/* str_file_size */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			/* Importend! Need qsorted list */
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
		}






		/* -------------------------------------------------------------------------------------------------- */
		/* allowed groups */
		group_info = get_current_groups();

		for (n = 0; n < group_info->ngroups; n++) {
			if (group_info->gid[n].val == 0) {
				printk("ALLOWED LIST: USER/PROG. NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				return(RET_SHELL);			/* group root not allowed. My choice! */
			}

			if (folder_list_max > 0) {
				sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
				str_length = strlen(str_group_id);				/* str_user_id len*/
				str_length += strlen(filename) + 4;				/* plus 1 = semikolon + ga: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

				strcpy(str_file_name, "ga:");
				strcat(str_file_name, str_group_id);				/* str_group_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* Importend! Need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_allowed;
			}

			if (file_list_max > 0) {
				sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
				sprintf(str_file_size, "%lu", file_size);			/* int to string */
				str_length = strlen(str_group_id);				/* str_user_id len*/
				str_length += strlen(str_file_size);				/* str_user_id len*/
				str_length += strlen(filename) + 5;				/* plus 2 semikolon + ga: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

				strcpy(str_file_name, "ga:");
				strcat(str_file_name, str_group_id);				/* str_user_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, str_file_size);				/* str_file_size */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* Importend! Need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
			}

			if (file_list_max > 0) {
				sprintf(str_group_id, "%u", group_info->gid[n].val);		/* int to string */
				sprintf(str_file_size, "%lu", file_size);			/* int to string */
				str_length = strlen(str_group_id);				/* str_user_id len*/
				str_length += strlen(str_file_size);				/* str_user_id len*/
				str_length += strlen(filename) + 6;				/* plus 2 semikolon + ga: */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				if (str_file_name == NULL) panic(NO_SECURITY_GUARANTEED);

				strcpy(str_file_name, "gas:");
				strcat(str_file_name, str_group_id);				/* str_user_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, str_file_size);				/* str_file_size */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* Importend! Need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
			}


		}

		/* ------------------------------------------------------------------------------------------------- */
		/* Not allowed */
		printk("ALLOWED LIST: USER/PROG. NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
		if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
		return(RET_SHELL);
	}

prog_allowed:
/*-----------------------------------------------------------------*/


	if (printk_mode == true) {
		printk("ALLOWED LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
	}

	if (str_file_name != NULL) { kfree(str_file_name); str_file_name = NULL; }
	return(0);

}







static int allowed_deny_exec(const char *filename,
	const char __user *const __user *_argv)
{

	struct user_arg_ptr argv = { .ptr.native = _argv };

	const char __user	*str;
	char			**argv_list = NULL;
	int			argv_list_max = 0;
	int			n;
	long			str_len;

	int			ret = 0;
	long			argv_max = 16;

	char			*kernel_filename;


	if(IS_ERR(filename)) return RET_SHELL;

	/* filename -> kernel space */
	str_len = strnlen_user(filename, MAX_ARG_STRLEN);
	kernel_filename = kmalloc((str_len + 1) * sizeof(char *), GFP_KERNEL);
	if (kernel_filename == NULL) panic(NO_SECURITY_GUARANTEED);

	ret = copy_from_user(kernel_filename, filename, str_len );



	/* argv -> kernel space */
	argv_list_max = count(argv, MAX_ARG_STRINGS);
	if (argv_list_max > argv_max) argv_list_max = argv_max;

	argv_list = kmalloc(argv_list_max * sizeof(char *), GFP_KERNEL);
	if (argv_list == NULL) panic(NO_SECURITY_GUARANTEED);


	for (n = 0; n < argv_list_max; n++) {
		str = get_user_arg_ptr(argv, n);
		str_len = strnlen_user(str, MAX_ARG_STRLEN);

		argv_list[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
		if (argv_list[n] == NULL) panic(NO_SECURITY_GUARANTEED);

		ret = copy_from_user(argv_list[n], str, str_len);
	}


	ret = allowed_deny_exec_first_step(kernel_filename, argv_list, argv_list_max);


	for (n = 0; n < argv_list_max; n++) {
		if (argv_list[n] != NULL) { kfree(argv_list[n]); argv_list[n] = NULL; }
	}

	if (argv_list != NULL) { kfree(argv_list); argv_list = NULL; }
	if (kernel_filename != NULL) { kfree(kernel_filename); kernel_filename = NULL; }

	return ret;



}







/* SYSCALL NR: 459 or other */
SYSCALL_DEFINE2(set_execve,
		const loff_t, number,
		const char __user *const __user *, list)
{

	uid_t	user_id;
	u32	n;
	int	int_ret;
	int	str_len = 0;
	char	*list_string = NULL;

	struct user_arg_ptr _list = { .ptr.native = list };
	const char __user *str;


	user_id = get_current_user()->uid.val;


	/* command part, future ? */
	switch(number) {
		/* safer on */
		case 999900:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: SAFER ON\n");
#endif
				safer_mode = true;
				return(0);


			/* safer off */
		case 999901:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: SAFER OFF\n");
#endif
				safer_mode = false;
				return(0);


		/* stat */
		case 999902:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("SAFER STATE         : %d\n", safer_mode);
#endif
				return(safer_mode);


		/* printk on */
		case 999903:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: SAFER PRINTK ON\n");
#endif
				printk_mode = true;
				return(0);


		/* printk off */
		case 999904:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: SAFER PRINTK OFF\n");
#endif
				printk_mode = false;
				return(0);



		/* clear all file list */
		case 999905:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("CLEAR FILE LIST!\n");
#endif
				if (file_list_max != 0) {
					for (n = 0; n < file_list_max; n++) {
						if (file_list[n] != NULL) { kfree(file_list[n]); file_list[n] = NULL; }
					}
					if (file_list != NULL) { kfree(file_list); file_list = NULL; }
					file_list_max = 0;
				}
				return(0);

		/* clear all folder list */
		case 999906:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("CLEAR FOLDER LIST!\n");
#endif
				if (folder_list_max != 0) {
					for (n = 0; n < folder_list_max; n++) {
						if (folder_list[n] != NULL) { kfree(folder_list[n]); folder_list[n] = NULL; }
					}
					if (folder_list != NULL) { kfree(folder_list); folder_list = NULL; }
					folder_list_max = 0;
				}
				return(0);

		case 999907:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: SAFER ROOT LIST IN KERNEL ON\n");
#endif
				safer_root_list_in_kernel_mode = true;
				return(0);


		case 999908:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: SAFER ROOT LIST IN KERNEL OFF\n");
#endif
				safer_root_list_in_kernel_mode = false;
				return(0);


		case 999909:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: NO MORE CHANGES ALLOWED\n");
#endif
				change_mode = false;
				return(0);

		case 999910:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: learning ON\n");
#endif
				learning_mode = true;

				return(0);


		case 999911:	if (user_id != 0) return(-1);
				if (change_mode == false) return(-1);

#ifdef PRINTK
				printk("MODE: learning OFF\n");
#endif
				learning_mode = false;

				return(0);


		/* set all list */
		case 999920:

				if (user_id != 0) return -1;
				if (change_mode == false) return -1;


				if (list == NULL) {		/* check? */
#ifdef PRINTK
					printk("ERROR: FILE LIST\n");
#endif
					return(-1);
				} /* check!? */

				/* clear */
				if (file_list_max > 0) {
					for (n = 0; n < file_list_max; n++) {
						if (file_list[n] != NULL) { kfree(file_list[n]); file_list[n] = NULL; }
					}
					if (file_list != NULL) { kfree(file_list); file_list = NULL; }
				}



				int_ret = count(_list, MAX_ARG_STRINGS);
				if (int_ret == 0) return -1;

				str = get_user_arg_ptr(_list, 0);		/* String 0 */
				str_len = strnlen_user(str, MAX_ARG_STRLEN);
				if (str_len < 1) return -1;

				if (list_string != NULL) { kfree(list_string); list_string = NULL; }		/* sicher ist sicher */
				list_string = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) panic(NO_SECURITY_GUARANTEED);
				int_ret = copy_from_user(list_string, str, str_len);

				int_ret = kstrtol(list_string, 10, &file_list_max);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; }
				if (int_ret != 0) return -1;


				if (file_list_max < 1) {
#ifdef PRINTK
					printk("NO FILE LIST\n");
#endif
					return(-1);
				}

				if (file_list_max > MAX_DYN) {
#ifdef PRINTK
					printk("FILE LIST TO BIG!\n");
#endif
					return(-1);
				}

#ifdef PRINTK
				printk("FILE LIST ELEMENTS: %ld\n", file_list_max);
#endif


				/* dyn array */
				file_list = kmalloc(file_list_max * sizeof(char *), GFP_KERNEL);
				/* if (file_list == NULL) { file_list_max = 0; return -1; } */
				if (file_list == NULL) panic(NO_SECURITY_GUARANTEED);

				for (n = 0; n < file_list_max; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					file_list[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					if (file_list[n] == NULL) panic(NO_SECURITY_GUARANTEED);

					int_ret = copy_from_user(file_list[n], str, str_len);
				}

				return(file_list_max);

		/* set all folder list */
		case 999921:
				if (user_id != 0) return -1;
				if (change_mode == false) return -1;


				if (list == NULL) {		/* check? */
#ifdef PRINTK
					printk("ERROR: FOLDER LIST\n");
#endif
					return(-1);
				} /* check!? */

				/* clear */
				if (folder_list_max > 0) {
					for (n = 0; n < folder_list_max; n++) {
						if (folder_list[n] != NULL) { kfree(folder_list[n]); folder_list[n] = NULL; }
					}
					if (folder_list != NULL) { kfree(folder_list); folder_list = NULL; }
				}



				/* No Syscall Parameter 6 necessary */
				int_ret = count(_list, MAX_ARG_STRINGS);
				if (int_ret == 0) return -1;

				str = get_user_arg_ptr(_list, 0);		/* String 0 */
				str_len = strnlen_user(str, MAX_ARG_STRLEN);
				if (str_len < 1) return -1;

				if (list_string != NULL) { kfree(list_string); list_string = NULL; }		/* sicher ist sicher */

				list_string = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) panic(NO_SECURITY_GUARANTEED);

				int_ret = copy_from_user(list_string, str, str_len);

				int_ret = kstrtol(list_string, 10, &folder_list_max);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; };
				if (int_ret != 0) return -1;


				if (folder_list_max < 1) {
#ifdef PRINTK
					printk("NO FOLDER LIST\n");
#endif
					return(-1);
				}

				if (folder_list_max > MAX_DYN) {
#ifdef PRINTK
					printk("FOLDER LIST TO BIG!\n");
#endif
					return(-1);
				}

#ifdef PRINTK
				printk("FOLDER LIST ELEMENTS: %ld\n", folder_list_max);
#endif


				/* dyn array */
				folder_list = kmalloc(folder_list_max * sizeof(char *), GFP_KERNEL);
				/* if (folder_list == NULL) { folder_list_max = 0; return -1; } */
				if (folder_list == NULL) panic(NO_SECURITY_GUARANTEED);


				for (n = 0; n < folder_list_max; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					folder_list[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					if (folder_list[n] == NULL) panic(NO_SECURITY_GUARANTEED);

					int_ret = copy_from_user(folder_list[n], str, str_len);
				}

				return(folder_list_max);


		default:	printk("ERROR: COMMAND NOT IN LIST\n");
				return(-1);

	}

}







SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	if (allowed_deny_exec(filename, argv) == RET_SHELL) return RET_SHELL;

	return do_execve(getname(filename), argv, envp);
}

