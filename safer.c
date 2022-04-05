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

	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root
			
			: Only User
			: No Groups. I don't need it at the moment

			: Extension of SYSCALL <execve>
			: Replaces function <execve> in exec.c. Line 2060

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas
			: Simple Control Program for Extension <SYSCALL execve>
			: It only works as <root>

	LIST		: If you use binary search, a sorted list ist required
			: ALLOW and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable files in folder
			: Several thousand entries are then no problem.

	root		: ALLOW LIST for root is fixed in the code

	Standard	: Safer Mode = ON
			: Log Mode = Logs all programs from init

			: 0 = safer ON
			: 1 = safer OFF
			: 2 = State
			: 3 = Log ON
			: 4 = Log OFF
			: 5 = Clear ALLOW List
			: 6 = Clear DENY List
			: 7 = Set ALLOW List
			: 8 = Set DENY List

	Important	: ./foo is not allowed
			: But not absolutely necessary for me
			: It is not checked whether the program really exists
			: This is not necessary

			: Only "make bzImage" need this feature
			: The Solutions is Safer OFF


	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

			: string = USER-ID;PATH

			: Example:
			: 100;/bin/test			= file
			: 100;/bin/test1		= file


			: rules besearch
			: 100;/usr/sbin			= Folder
			: 100;/usr/sbin/test		= file		avoid
			: 100;/usr/sbin/test2		= file		avoid

			: It is up to the ADMIN to keep the list reasonable according to these rules!



	Thanks		: Linus Torvalds and others

	I would like to remember ALICIA ALONSO and MAYA PLISETSKAYA. Two admirable ballet dancers.

*/





static long besearch(char *str_search, char **list, long elements)
{
	long left, right;
	long middle;
	long int_ret;

	if (elements < 1) return(-1);
	if (elements == 1) {
		int_ret = strncmp(str_search, list[0], strlen(list[0]));
		if (int_ret == 0) return(0);
		else return(-1);
	}


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





#define PRINTK


SYSCALL_DEFINE6(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp,
		const loff_t, number,
		const loff_t, sub_number,
		const char __user *const __user *, list)
{
	static u8	safer = 0;
	static u8	printk_on = 1;

	static char	**allow_list;
	static long	allow_list_max = 0;

	static char	**deny_list;
	static long	deny_list_max = 0;

	int		user_id;
	u32		n;
	char		str_user_id[19];
	u64		str_length;
	char		*str_file_name = NULL;
	long		int_ret;




	user_id = get_current_user()->uid.val;
	

	/* command part, future ? */
	if (number == 999999) {
		if (user_id != 0) { printk("ONLY USER ROOT\n"); return(-1); }

		switch(sub_number) {

			/* safer on */
			case 0:	
#ifdef PRINTK
					printk("SAFER ON\n");
#endif
					safer = 0;
					return(0);


			/* safer off */
			case 1:
#ifdef PRINTK
					printk("SAFER OFF\n");
#endif
					safer = 1;
					return(0);


			/* stat */
			case 2:
#ifdef PRINTK
					printk("SAFER STATE         : %d\n", safer);
#endif
					return(safer);


			/* printk on */
			case 3:
#ifdef PRINTK
					printk("SAFER PRINTK ON\n");
#endif
					printk_on = 1;
					return(0);


			/* printk off */
			case 4:
#ifdef PRINTK
					printk("SAFER PRINTK OFF\n");
#endif
					printk_on = 0;
					return(0);


			/* clear allow list */
			case 5:
#ifdef PRINTK
					printk("CLEAR ALLOW LIST!\n");
#endif
					if (allow_list_max != 0) {
						for (n = 0; n < allow_list_max; n++) {
							kfree(allow_list[n]);
						}
						kfree(allow_list);
						allow_list_max = 0;
					}
					return(0);


			/* clear deny list */
			case 6:
#ifdef PRINTK
					printk("CLEAR DENY LIIST!\n");
#endif
					if (deny_list_max != 0) {
						for (n = 0; n < deny_list_max; n++) {
							kfree(deny_list[n]);
						}
						kfree(deny_list);
						deny_list_max = 0;
					}
					return(0);


			/* set allow list */
			case 7:		if (list == NULL) {		/* check? */
#ifdef PRINTK
						printk("ERROR: ALLOW LIST\n"); 
#endif
						return(-1); 
					} /* check!? */

					/* clear */
					if (allow_list_max > 0) {
						for (n = 0; n < allow_list_max; n++) {
							kfree(allow_list[n]);
						}
						kfree(allow_list);
					}

					int_ret = kstrtol(list[0], 10, &allow_list_max);
					if (int_ret != 0) return(-1);

					/* Lines 
					allow_list_max = 0;
					for (;;) {
						if (list[allow_list_max] == NULL) break;
						allow_list_max++;
					}
					*/

					if (allow_list_max < 1) {
#ifdef PRINTK
						printk("NO ALLOW LIST\n");
#endif
						return(-1); 
					}

#ifdef PRINTK
					printk("ALLOW LIST ELEMENTS: %ld\n", allow_list_max);
#endif

					/* dyn array */
					allow_list = kmalloc(allow_list_max * sizeof(char *), GFP_KERNEL);
					if (allow_list == NULL) { allow_list_max = 0; return(-1); }

					for (n = 0; n < allow_list_max; n++) {
						allow_list[n] = kmalloc((strlen(list[n+1]) + 1) * sizeof(char), GFP_KERNEL);
						if (allow_list[n] == NULL) return(-1);
						strcpy(allow_list[n], list[n+1]);
					}
					return(allow_list_max);


					/* set deny list */
			case 8:		if (list == NULL) {				/* check? */
#ifdef PRINTK
						printk("ERROR: DENY LIST\n"); 
#endif
						return(-1); 
					} /*check!? */

					/* clear */
					if (deny_list_max > 0) {
						for (n = 0; n < deny_list_max; n++) {
							kfree(deny_list[n]);
						}
						kfree(deny_list);
					}

					int_ret = kstrtol(list[0], 10, &deny_list_max);
					if (int_ret != 0) return(-1);

					if (deny_list_max < 1) { 
#ifdef PRINTK
						printk("NO DENY LIST\n"); 
#endif
						return(-1); 
					}

#ifdef PRINTK
					printk("DENY LIST ELEMENTS: %ld\n", deny_list_max);
#endif

					/* dyn array */
					deny_list = kmalloc(deny_list_max * sizeof(char *), GFP_KERNEL);
					if (deny_list == NULL) { deny_list_max = 0; return(-1); }

					for (n = 0; n < deny_list_max; n++) {
						deny_list[n] = kmalloc((strlen(list[n+1]) + 1) * sizeof(char), GFP_KERNEL);
						if (deny_list[n] == NULL) return(-1);
						strcpy(deny_list[n], list[n+1]);
					}
					return(deny_list_max);


			default:
#ifdef PRINTK
					printk("ERROR: ORDER NOT IN LIST!\n");
#endif
					return(-1);
		}
	}



	if (safer == 0) {
		for(;;) {
			//-----------------------------------------------------------------------
			if (user_id == 0) {
				if (strncmp("/bin/", filename, 5) == 0) break;
				if (strncmp("/sbin/", filename, 6) == 0) break;

				if (strncmp("/usr/bin/", filename, 9) == 0) break;
				if (strncmp("/usr/sbin/", filename, 10) == 0) break;
				if (strncmp("/usr/games/", filename, 11) == 0) break;
				if (strncmp("/usr/lib/", filename, 9) == 0) break;
				if (strncmp("/usr/libexec/", filename, 13) == 0) break;
				if (strncmp("/usr/local/", filename, 11) == 0) break;
				if (strncmp("/usr/share/", filename, 11) == 0) break;
				if (strncmp("/usr/scripts/", filename, 13) == 0) break;

				if (strncmp("/lib/", filename, 5) == 0) break;
				if (strncmp("/opt/", filename, 5) == 0) break;
				if (strncmp("/etc/", filename, 5) == 0) break;

				if (strncmp("/var/lib/", filename, 9) == 0) break;
				/* Example: docker required /proc/self/exe */

				if (strncmp("/proc/", filename, 6) == 0) break;

				/* NOT allowed. */
				printk("USER/PROG. not allowed : %d, %s\n", user_id, filename);
				return(-1);
			}

			/* --------------------------------------------------------------------------------- */
			/* future */
			if (user_id > 0) {
				/* user-id not 0 */
				sprintf(str_user_id, "%d", user_id);				/* int to string */
				str_length = strlen(str_user_id);				/* str_user_id len*/
				str_length += strlen(filename) + 1;				/* plus 1 = semikolon */

				if (str_file_name != NULL) {
					kfree(str_file_name);
					str_file_name = NULL;
				}

				str_file_name = kmalloc((str_length + 1) * sizeof(char), GFP_KERNEL);

				strcpy(str_file_name, str_user_id);				/* str_user_id */
				strcat(str_file_name, ";");					/* + semmicolon */
				strcat(str_file_name, filename);				/* + filename */

				/* first deny list */
				if (deny_list_max > 0) {
					/* simple. Not ALLOWED
					for (n = 0; n < deny_list_max; n++) {
						if (strncmp(deny_list[n], str_file_name, strlen(deny_list[n])) == 0) {
							printk("DENY LIST USER/PROG. not allowed  : %d, %s\n", user_id, filename);
							return(-1);
						}
					} */

					/* Importend! need qsorted list */
					if (besearch(str_file_name, deny_list, deny_list_max) == 0) {
						/* Not allowed */
						printk("DENY LIST USER/PROG. not allowed  : %d;%s\n", user_id, filename);
						return(-1);
					}
				}


				if (allow_list_max > 0) {
					/* simple
					for (n = 0; n < allow_list_max; n++) {
						if (strncmp(allow_list[n], str_file_name, strlen(allow_list[n])) == 0) goto prog_allowed;
					} */

					/* Importend! Need qsorted list */
					if (besearch(str_file_name, allow_list, allow_list_max) == 0) break;
				}
			}

			/* ------------------------------------------------------------------------------------------------- */
			/* Not allowed */
			printk("ALLOW LIST USER/PROG. not allowed : %d;%s\n", user_id, filename);
			return(-1);
		}
	}


	if (printk_on == 1) {
		printk("USER/PROG. allowed          : %d, %s\n", user_id, filename);

		/* max. argv */
		for ( n = 1; n <= 32; n++) {
			if (argv[n] != NULL) 
				printk("%s:argv[%d] : %s\n", argv[0], n, argv[n]);
			else break;
		}
	}

	return do_execve(getname(filename), argv, envp);

}

