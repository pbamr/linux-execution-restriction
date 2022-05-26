/* Copyright (c) 2022/03/28, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.03.28, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

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
 */



/*
	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.03.28

	Program		: safer.c
	Path		: fs/

			: Program with SYSCALL

			: in x86_64/amd64 syscall_64.tbl
			: 459	common	set_execve		sys_set_execve



	Functionality	: Program execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root

			: USER and GROUPS

			: Extension of SYSCALL <execve>
			: Replaces function <execve> in exec.c. Line 2060

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas
			: Simple Control Program for Extension <SYSCALL execve>
			: It only works as <root>

	LIST		: If you use binary search, a sorted list ist required
			: ALLOWED and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable files in folder
			: Several thousand entries are then no problem.

	root		: ALLOWED LIST for root is fixed in the code
			: Group root = GROUP ID 0 is not allowed


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

			: 999920 = Set FILE List
			: 999921 = Set FOLDER List


	Important	: ./foo is not allowed
			: But not absolutely necessary for me
			: It is not checked whether the program really exists
			: This is not necessary

	FILE/FOLDER List: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

			: string = USER-ID;PATH
			: string = GROUP-ID;PATH

			: It is up to the ADMIN to keep the list reasonable according to these rules!



	Thanks		: Linus Torvalds and others

	I would like to remember ALICIA ALONSO and MAYA PLISETSKAYA. Two admirable ballet dancers.

*/


#define PRINTK
#define MAX_DYN 100000




static bool	safer_mode = true;
static bool	printk_mode = true;
static u8	search_mode = 0;
static bool	safer_root_list_in_kernel = true;

static char	**file_list;
static char	**proc_file_list;
static long	file_list_max = 0;

static char	**folder_list;
static char	**proc_folder_list;
static long	folder_list_max = 0;





/* decl. */
struct info_safer_struct {
	bool safer_mode;
	bool printk_mode;
	bool safer_root_list_in_kernel;
	u8 search_mode;
	long file_list_max;
	long folder_list_max;
	char **file_list;
	char **folder_list;
};




/* DATA: Only over function */
void info_safer(struct info_safer_struct *info)
{
	info->safer_mode = safer_mode;
	info->printk_mode = printk_mode;
	info->search_mode = search_mode;
	info->safer_root_list_in_kernel = safer_root_list_in_kernel;
	info->file_list_max = file_list_max;
	info->folder_list_max = folder_list_max;
	info->file_list = proc_file_list;
	info->folder_list = proc_folder_list;
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




static int allowed_deny_exec(const char *filename, const char __user *const __user *argv) 
{
	uid_t	user_id;
	u32	n;
	char	str_user_id[19];
	char	str_group_id[19];

	u64	str_length;
	char	*str_file_name = NULL;
	s64	retval;
	s64	parameter_max;

	struct group_info *group_info;


	user_id = get_current_user()->uid.val;

	if (safer_mode == true) {
		/* --------------------------------------------------------------------------------- */
		/* my choice */
		if (user_id == 0) {
			if (safer_root_list_in_kernel == true) {
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
				printk("USER/PROG. not allowed : %u;%s\n", user_id, filename);
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
				printk("DENY LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
				return(-2);
			}
		}


		if (file_list_max > 0) {
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
				/* Not allowed */
				printk("DENY LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
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
					printk("DENY GROUP LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
					return(-2);
				}
			}


			if (file_list_max > 0) {
				/* Importend! need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) {
					/* Not allowed */
					printk("DENY GROUP LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
					return(-2);
				}
			}
		}

		/* --------------------------------------------------------------------------------------------- */
		/* allowed user */
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

		if (folder_list_max > 0) {
			/* Importend! Need qsorted list */
			if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_allowed;
		}

		if (file_list_max > 0) {
			/* Importend! Need qsorted list */
			if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
		}

		/* -------------------------------------------------------------------------------------------------- */
		/* allowed groups */
		group_info = get_current_groups();

		for (n = 0; n < group_info->ngroups; n++) {
			if (group_info->gid[n].val == 0) {
				printk("ALLOWED LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
				return(-2);			/* group root not allowed. My choice! */
			}

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

			if (folder_list_max > 0) {
				/* Importend! Need qsorted list */
				if (besearch_folder(str_file_name, folder_list, folder_list_max) == 0) goto prog_allowed;
			}

			if (file_list_max > 0) {
				/* Importend! Need qsorted list */
				if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_allowed;
			}
		}

		/* ------------------------------------------------------------------------------------------------- */
		/* Not allowed */
		printk("ALLOWED LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
		return(-2);
	}

prog_allowed:

	/* check script files.max 10 param. */
	if (safer_mode == true) {
		if (file_list_max > 0) {
			if (strncmp(argv[0], "python", 6) == 0 || \
				strcmp(argv[0], "perl") == 0 || \
				strcmp(argv[0], "ruby") == 0 || \
				strcmp(argv[0], "lua") == 0)  {

				retval = count_strings_kernel(argv);

				parameter_max = retval;
				if (retval > 10) parameter_max = 10;
				if (retval == 1) goto prog_exit_allowed;

				for ( n = 1; n < parameter_max; n++) {
				
					sprintf(str_user_id, "%u", user_id);				/* int to string */
					str_length = strlen(str_user_id);				/* str_user_id len*/
					str_length += strlen(argv[n]) + 3;				/* plus 1 = semikolon + d: */

					if (str_file_name != NULL) {
						kfree(str_file_name);
						str_file_name = NULL;
					}

					str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);

					strcpy(str_file_name, "a:");
					strcat(str_file_name, str_user_id);				/* str_group_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n]);					/* + filename */

					if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
				}

				printk("ALLOWED LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
				return(-2);
			}

			/* java special */
			if (strcmp(argv[0], "java") == 0) {
				retval = count_strings_kernel(argv); 					/* check Parameter */

				parameter_max = retval;
				if (retval > 10) parameter_max = 10;					/* Only 10 Parameters */
				if (retval == 1) goto prog_exit_allowed;				/* without Parameters */

				for ( n = 1; n < parameter_max; n++) {
					if (strcmp(argv[n], "-classpath") != 0) continue;		/* if not "-classpath" found continue */
					if ((n + 2) >= retval) break;					/* if "classpath" found, without programm name */

					sprintf(str_user_id, "%u", user_id);				/* int to string */
					str_length = strlen(str_user_id);				/* str_user_id len*/
					str_length += strlen(argv[n+1]);				
					str_length += strlen(argv[n+2]) + 5;				/* a:0;  plus "/" */

					if (str_file_name != NULL) {
						kfree(str_file_name);
						str_file_name = NULL;
					}

					str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);

					strcpy(str_file_name, "a:");
					strcat(str_file_name, str_user_id);				/* str_group_id */
					strcat(str_file_name, ";");					/* + semmicolon */
					strcat(str_file_name, argv[n+1]);				/* + classpath */
					strcat(str_file_name, "/");					/* + / */
					strcat(str_file_name, argv[n+2]);				/* + filename */

					if (besearch_file(str_file_name, file_list, file_list_max) == 0) goto prog_exit_allowed; /* OK in list */
					/* only 1 search */
					printk("ALLOWED LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
					return(-2);
				}

				printk("ALLOWED LIST USER/PROG. not allowed : %u;%s\n", user_id, filename);
				return(-2);
			}



/* END SCRIPTS CHECK */
/*-----------------------------------------------------------------*/
		}
	}

prog_exit_allowed:

	if (printk_mode == 1) {
		printk("USER/PROG. allowed          : %u;%s\n", user_id, filename);
	}

	if (printk_mode == true) {
		/* max. argv */
		
		for ( n = 0; n <= 32; n++) {
			if (argv[n] != NULL) 
				printk("%s :argv[%d] : %s\n", filename, n, argv[n]);
			else break;

		}
	}

	return(0);

}



/* SYSCALL NR: 459 or other */
SYSCALL_DEFINE2(set_execve,
		const loff_t, number,
		const char __user *const __user *, list)
{

	uid_t		user_id;
	u32		n, error_n;
	long		int_ret;




	user_id = get_current_user()->uid.val;

	/* command part, future ? */
	switch(number) {
		/* safer on */
		case 999900:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER ON\n");
#endif
				safer_mode = true;
				return(0);


			/* safer off */
		case 999901:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER OFF\n");
#endif
				safer_mode = false;
				return(0);


		/* stat */
		case 999902:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("SAFER STATE         : %d\n", safer_mode);
#endif
				return(safer_mode);


		/* printk on */
		case 999903:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER PRINTK ON\n");
#endif
				printk_mode = true;
				return(0);


		/* printk off */
		case 999904:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER PRINTK OFF\n");
#endif
				printk_mode = false;
				return(0);



		/* clear all file list */
		case 999905:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("CLEAR FILE LIST!\n");
#endif
				if (file_list_max != 0) {
					for (n = 0; n < file_list_max; n++) {
						kfree(file_list[n]);
					}
					kfree(file_list);
					file_list_max = 0;
				}
				return(0);

		/* clear all folder list */
		case 999906:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("CLEAR FOLDER LIST!\n");
#endif
				if (folder_list_max != 0) {
					for (n = 0; n < folder_list_max; n++) {
						kfree(folder_list[n]);
					}
					kfree(folder_list);
					folder_list_max = 0;
				}
				return(0);

		case 999907:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER ROOT LIST IN KERNEL ON\n");
#endif
				safer_root_list_in_kernel = true;
				return(0);


		case 999908:	if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER ROOT LIST IN KERNEL OFF\n");
#endif
				safer_root_list_in_kernel = false;
				return(0);


		/* set all list */
		case 999920:	if (user_id != 0) return(-1);

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
					}
					kfree(file_list);
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
				return(file_list_max);

		/* set all folder list */
		case 999921:	if (user_id != 0) return(-1);

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
					}
					kfree(folder_list);
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

