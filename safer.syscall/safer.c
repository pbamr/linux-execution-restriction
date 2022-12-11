/* Copyright (c) 2022/03/28, 2022.06.11, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.03.28, 2022.06.11, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

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
	Date		: 2022.03.28, 2022.06.11

	Program		: safer.c
	Path		: fs/

			: Program with SYSCALL

			: in x86_64/amd64 syscall_64.tbl
			: 459	common	set_execve		sys_set_execve

	Test		: Kernel 6.0, Lenovo X230

	Functionality	: Program execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root

			: USER and GROUPS

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

			: 999909 = LOCK CHANGES

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
			: string = GROUP-ID;FILE-SIZE;PATH
			: string = File Size

			: example:
				a:0;1234;/path
				d:0;/path
				ga:0;1234;path
				d:0;/path
				gd:0;path

			: It is up to the ADMIN to keep the list reasonable according to these rules!


	Thanks		: Linus Torvalds and others

	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, VAKHTANG CHABUKIANI and the "LAS CUATRO JOYAS DEL BALLET CUBANO".
	Admirable ballet dancers.


*/


#define PRINTK
#define MAX_DYN 100000




static bool	safer_mode = true;
static bool	printk_mode = true;
static bool	safer_root_list_in_kernel_mode = true;
static bool	learning_mode = true;
static bool	no_change_mode = false;

static char	**file_list = NULL;
static char	**proc_file_list = NULL;
static char	**file_learning_list = NULL;
static char	**file_argv_list = NULL;
static long	file_learning_list_max = 0;
static long	file_argv_list_max = 0;
static long	file_list_max = 0;


static char	**folder_list;
static char	**proc_folder_list;
static long	folder_list_max = 0;

static void	*data = NULL;



/* decl. */
struct  safer_info_struct {
	bool safer_mode;
	bool printk_mode;
	bool learning_mode;
	bool no_change_mode;
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
	info->no_change_mode = no_change_mode;
	info->safer_root_list_in_kernel_mode = safer_root_list_in_kernel_mode;
	info->file_list_max = file_list_max;
	info->folder_list_max = folder_list_max;
	info->file_list = proc_file_list;
	info->folder_list = proc_folder_list;
}




/* decl. */
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





static int allowed_deny_exec(const char *filename, const char __user *const __user *argv)
{
	uid_t	user_id;
	u32	n, n0;
	char	str_user_id[19];
	char	str_group_id[19];
	char	str_file_size[19];

	u64	str_length;
	char	*str_file_name = NULL;
	char	*str_java_name = NULL;
	s64	parameter_max;

	struct group_info *group_info;

	size_t	file_size = 0;
	int	ret;


	user_id = get_current_user()->uid.val;

	if (learning_mode == true) {
		parameter_max = count_strings_kernel(argv);
		if (parameter_max > 16) parameter_max = 16;


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

				strcpy(str_file_name, "a:");
				strcat(str_file_name, str_user_id);				/* str_user_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, str_file_size);				/* str_file_size */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, argv[n]);					/* + filename */

				if (file_learning_list_max > 0) {
					if (search(str_file_name, file_learning_list, file_learning_list_max) == 0) continue;
				}

				if (file_argv_list_max > 0) {
					if (search(str_file_name, file_argv_list, file_argv_list_max) == 0) continue;
				}

				file_argv_list_max += 1;
				file_argv_list = krealloc(file_argv_list, file_argv_list_max * sizeof(char *), GFP_KERNEL);
				file_argv_list[file_argv_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				strcpy(file_argv_list[file_argv_list_max - 1], str_file_name);
			}
		}

		if (strstr(filename, "/python") != NULL || \
		strstr(filename, "/insmod") != NULL || \
		strstr(filename, "/perl") != NULL || \
		strstr(filename, "/ruby") != NULL || \
		strstr(filename, "/julia") != NULL || \
		strstr(filename, "/Rscript") != NULL || \
		strstr(filename, "/java") != NULL || \
		strstr(filename, "/lua") != NULL)  {
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

					strcpy(str_file_name, "a:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, str_file_size);				/* str_file_size */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n]);					/* + filename */

					if (file_learning_list_max > 0) {
						if (search(str_file_name, file_learning_list, file_learning_list_max) == 0) continue;
					}

					file_learning_list_max += 1;
					file_learning_list = krealloc(file_learning_list, file_learning_list_max * sizeof(char *), GFP_KERNEL);
					file_learning_list[file_learning_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					strcpy(file_learning_list[file_learning_list_max - 1], str_file_name);
				}
			}
		}
	}

	ret = kernel_read_file_from_path(filename, 0, &data, 0, &file_size, READING_POLICY);

	if (printk_mode == true) {
		/* max. argv */
		for ( n = 0; n <= 32; n++) {
			if (argv[n] != NULL)
				printk("USER ID:%u, PROG:%s, SIZE:%lu, argv[%d]:%s\n", user_id, filename, file_size, n, argv[n]);
			else break;
		}
		if (ret != 0) printk("URGENT: PROG. NOT EXIST\n");
	}

	if (ret != 0) return(-2);

	if (safer_mode == true) {
		/* --------------------------------------------------------------------------------- */
		/* my choice */
		if (user_id == 0) {
			if (safer_root_list_in_kernel_mode == true) {
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
				return(-2);
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

		strcpy(str_file_name, "d:");
		strcat(str_file_name, str_user_id);				/* str_user_id */
		strcat(str_file_name, ";");					/* + semmicolon */
		strcat(str_file_name, filename);				/* + filename */

		if (folder_list_max > 0) {
			/* Importend! need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
			/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				return(-2);
			}
		}


		if (file_list_max > 0) {
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
				/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
				return(-2);
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

			strcpy(str_file_name, "gd:");
			strcat(str_file_name, str_group_id);				/* str_group_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			if (folder_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
					return(-2);
				}
			}


			if (file_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
					return(-2);
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

			strcpy(str_file_name, "a:");
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
		return(-2);
	}

prog_allowed:

	/* simple */
	/* test script files.max 10 param. */
	/* only user, no groups */
	/* this form will test: python "/abc/def/prog". name only is not allowed. "python hello" etc. is not allowed */
	/* The full path is necessary */

	if (safer_mode == true) {
		if (strstr(filename, "/python") != NULL || \
		strstr(filename, "/insmod") != NULL || \
		strstr(filename, "/perl") != NULL || \
		strstr(filename, "/ruby") != NULL || \
		strstr(filename, "/julia") != NULL || \
		strstr(filename, "/Rscript") != NULL || \
		strstr(filename, "/lua") != NULL)  {

			parameter_max = count_strings_kernel(argv);
			if (parameter_max == 1) goto prog_exit_allowed;

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

					strcpy(str_file_name, "d:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n]);					/* + filename */

					/* Importend! Need qsorted list */
					if (folder_list_max > 0) {
						if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
							/* Not allowed */
							printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
							return(-2);
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

					strcpy(str_file_name, "d:");
					strcat(str_file_name, str_user_id);				/* str_user_id */
					strcat(str_file_name, ";");
					strcat(str_file_name, argv[n]);					/* + filename */

					if (file_list_max > 0) {
						if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
							/* Not allowed */
							printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
							return(-2);
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

						strcpy(str_file_name, "gd:");
						strcat(str_file_name, str_group_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, argv[n]);					/* + filename */

						if (folder_list_max > 0) {
							if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
								/* Not allowed */
								printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
								return(-2);
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

						strcpy(str_file_name, "gd:");
						strcat(str_file_name, str_group_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, argv[n]);					/* + filename */

						if (file_list_max > 0) {
							if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
								/* Not allowed */
								printk("DENY LIST: <USER/SCRIPT/MODULE> IN LIST: %u;%lu;%s\n", user_id,  file_size, argv[n]);
								return(-2);
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
			return(-2);

		}
			/* simple */
			/* java special */
			/* only user no group */
			/* this form will test: "java -classpath PATH name" IMPORTANT: PATH without last "/" */
			/*                    : "java -jar /PATH/name.jar */
			/* other not allowed */
		if (strstr(filename, "/java") != NULL) {
			parameter_max = count_strings_kernel(argv);				/* check Parameter */
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

							strcpy(str_file_name, "a:");
							strcat(str_file_name, str_user_id);				/* str_user_id */
							strcat(str_file_name, ";");					/* + semmicolon */
							strcat(str_file_name, str_file_size);
							strcat(str_file_name, ";");
							strcat(str_file_name, str_java_name);				/* + filename */

							if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
							printk("ALLOWED LIST: USER/PROG. <CLASS> NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
							return(-2);
						}
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
						strcpy(str_file_name, "a:");
						strcat(str_file_name, str_user_id);				/* str_user_id */
						strcat(str_file_name, ";");					/* + semmicolon */
						strcat(str_file_name, str_file_size);
						strcat(str_file_name, ";");
						strcat(str_file_name, argv[2]);					/* + filename */

						if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
						printk("ALLOWED LIST: USER/PROG. <CLASS/JAR> NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
						return(-2);
					}
				}
			}
		}

/* END SCRIPTS CHECK */
/*-----------------------------------------------------------------*/
	}

prog_exit_allowed:

	return(0);

}



static int allowed_deny_exec_sec(const char *filename)
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

	int	ret;


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

			strcpy(str_file_name, "a:");
			strcat(str_file_name, str_user_id);				/* str_user_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, str_file_size);				/* str_file_size */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			if (file_learning_list_max > 0) {
				if (search(str_file_name, file_learning_list, file_learning_list_max) != 0) {
					file_learning_list_max += 1;
					file_learning_list = krealloc(file_learning_list, file_learning_list_max * sizeof(char *), GFP_KERNEL);
					file_learning_list[file_learning_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
					strcpy(file_learning_list[file_learning_list_max -1], str_file_name);
				}
			}
			else {
				file_learning_list_max += 1;
				file_learning_list = krealloc(file_learning_list, file_learning_list_max * sizeof(char *), GFP_KERNEL);
				file_learning_list[file_learning_list_max - 1] = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);
				strcpy(file_learning_list[file_learning_list_max - 1], str_file_name);
			}
		}
	}


	if (safer_mode == true) {
		/* --------------------------------------------------------------------------------- */
		/* my choice */
		if (user_id == 0) {
			if (safer_root_list_in_kernel_mode == true) {
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
				return(-2);
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

		strcpy(str_file_name, "d:");
		strcat(str_file_name, str_user_id);				/* str_user_id */
		strcat(str_file_name, ";");					/* + semmicolon */
		strcat(str_file_name, filename);				/* + filename */

		if (folder_list_max > 0) {
			/* Importend! need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
			/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
				return(-2);
			}
		}


		if (file_list_max > 0) {
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
				/* Not allowed */
				printk("DENY LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
				return(-2);
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

			strcpy(str_file_name, "gd:");
			strcat(str_file_name, str_group_id);				/* str_group_id */
			strcat(str_file_name, ";");					/* + semmicolon */
			strcat(str_file_name, filename);				/* + filename */

			if (folder_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id,  file_size, filename);
					return(-2);
				}
			}


			if (file_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
					return(-2);
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

			strcpy(str_file_name, "a:");
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
				return(-2);			/* group root not allowed. My choice! */
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

		/* ------------------------------------------------------------------------------------------------- */
		/* Not allowed */
		printk("ALLOWED LIST: USER/PROG. NOT IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
		return(-2);
	}

prog_allowed:
/*-----------------------------------------------------------------*/


	if (printk_mode == 1) {
		printk("ALLOWED LIST: USER/PROG. IN LIST: %u;%lu;%s\n", user_id, file_size, filename);
	}


	return(0);

}









/* SYSCALL NR: 459 or other */
SYSCALL_DEFINE2(set_execve,
		const loff_t, number,
		const char __user *const __user *, list)
{

	uid_t	user_id;
	u32	n, error_n;
	long	int_ret;




	user_id = get_current_user()->uid.val;

	/* command part, future ? */
	switch(number) {
		/* safer on */
		case 999900:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("MODE: SAFER ON\n");
#endif
				safer_mode = true;
				return(0);


			/* safer off */
		case 999901:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("MODE: SAFER OFF\n");
#endif
				safer_mode = false;
				return(0);


		/* stat */
		case 999902:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("SAFER STATE         : %d\n", safer_mode);
#endif
				return(safer_mode);


		/* printk on */
		case 999903:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("MODE: SAFER PRINTK ON\n");
#endif
				printk_mode = true;
				return(0);


		/* printk off */
		case 999904:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("MODE: SAFER PRINTK OFF\n");
#endif
				printk_mode = false;
				return(0);



		/* clear all file list */
		case 999905:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("CLEAR FILE LIST!\n");
#endif
				if (file_list_max != 0) {
					for (n = 0; n < file_list_max; n++) {
						kfree(file_list[n]);
						kfree(proc_file_list[n]);
					}
					kfree(file_list);
					kfree(proc_file_list);
					file_list_max = 0;
				}
				return(0);

		/* clear all folder list */
		case 999906:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("CLEAR FOLDER LIST!\n");
#endif
				if (folder_list_max != 0) {
					for (n = 0; n < folder_list_max; n++) {
						kfree(folder_list[n]);
						kfree(proc_file_list[n]);
					}
					kfree(folder_list);
					folder_list_max = 0;
				}
				return(0);

		case 999907:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("MODE: SAFER ROOT LIST IN KERNEL ON\n");
#endif
				safer_root_list_in_kernel = true;
				return(0);


		case 999908:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

#ifdef PRINTK
				printk("MODE: SAFER ROOT LIST IN KERNEL OFF\n");
#endif
				safer_root_list_in_kernel = false;
				return(0);


		case 999909:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1);

#ifdef PRINTK
				printk("MODE: NO MORE CHANGES ALLOWED\n");
#endif
				no_change = false;
				return(0);


		/* set all list */
		case 999920:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

				if (list == NULL) {		/* check? */
#ifdef PRINTK
				printk("ERROR: FILE LIST\n"); 
#endif
					return(-1); 
				} /* check!? */

				/* clear */
				if (file_list_max > 0) {
					for (n = 0; n < file_list_max; n++) {
						kfree(file_list[n]);
						kfree(proc_file_list[n]);
					}
					kfree(file_list);
					kfree(proc_file_list);
				}

				int_ret = kstrtol(list[0], 10, &file_list_max);
				if (int_ret != 0) return(-1);

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
				if (file_list == NULL) { file_list_max = 0; return(-1); }

				for (n = 0; n < file_list_max; n++) {
					file_list[n] = kmalloc((strlen(list[n+1]) + 1) * sizeof(char), GFP_KERNEL);
					if (file_list[n] == NULL) {
						for (error_n = 0; error_n < n; error_n++) {
							kfree(file_list[error_n]);
						}
						kfree(file_list);
						file_list_max = 0;
						return(-1);
					}
					strcpy(file_list[n], list[n+1]);
				}

				proc_file_list = kmalloc(file_list_max * sizeof(char *), GFP_KERNEL);
				if (proc_file_list == NULL) { file_list_max = 0; return(-1); }

				for (n = 0; n < file_list_max; n++) {
					proc_file_list[n] = kmalloc((strlen(file_list[n]) + 1) * sizeof(char), GFP_KERNEL);
					strcpy(proc_file_list[n], file_list[n]);
				}

				return(file_list_max);

		/* set all folder list */
		case 999921:	if (user_id != 0) return(-1);
				if (no_change == false) return(-1); 

				if (list == NULL) {		/* check? */
#ifdef PRINTK
				printk("ERROR: FOLDER LIST\n"); 
#endif
					return(-1); 
				} /* check!? */

				/* clear */
				if (folder_list_max > 0) {
					for (n = 0; n < folder_list_max; n++) {
						kfree(folder_list[n]);
						kfree(proc_folder_list[n]);
					}
					kfree(folder_list);
					kfree(proc_folder_list);
				}

				int_ret = kstrtol(list[0], 10, &folder_list_max);
				if (int_ret != 0) return(-1);


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
				if (folder_list == NULL) { folder_list_max = 0; return(-1); }

				for (n = 0; n < folder_list_max; n++) {
					folder_list[n] = kmalloc((strlen(list[n+1]) + 1) * sizeof(char), GFP_KERNEL);
					if (folder_list[n] == NULL) {
						for (error_n = 0; error_n < n; error_n++) {
							kfree(folder_list[error_n]);
						}
						kfree(folder_list);
						folder_list_max = 0;
						return(-1);
					}
					strcpy(folder_list[n], list[n+1]);
				}

				proc_folder_list = kmalloc(folder_list_max * sizeof(char *), GFP_KERNEL);
				for (n = 0; n < folder_list_max; n++) {
					proc_folder_list[n] = kmalloc((strlen(folder_list[n]) + 1) * sizeof(char), GFP_KERNEL);
					strcpy(proc_folder_list[n], folder_list[n]);
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
	if (allowed_deny_exec(filename, argv) == -2) return(-2);

	return do_execve(getname(filename), argv, envp);
}

