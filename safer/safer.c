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
	Date		: 2022.04.22, 2023.05.23 2023.12.18

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 6.6
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

			: 999905 = LOCK changes

			: 999906 = learning on
			: 999907 = learning off


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

	PROG/FILE
			: a: allowed
			: d: deny

			: ga: group allowed
			: da: group deny

			: ai: interpreter
			      interpreter = arg/param/file only
			      First allowed Interpreter
			      Second allow Interpreter File


		FOLDER
			: a:  Folder allowed
			: d:  Folder deny

			: ga: group folder allowed
			: gd: group folder deny


		Example
			: string = USER-ID;FILE-SIZE;PATH
			: string = GROUP-ID;FILE-SIZEPATH
			: string = File Size

			: string = allow:USER-ID;FILE-SIZE;PATH
			: string = deny:GROUP-ID;PATH

			: a:USER-ID;Path
			: d:USER-ID;Path

			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path

			: ai:USER-ID;PATH

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

	Interpreter
			: Interpreter <USER> ONLY. INTERPTETER FILE <USER> <GROUP> allowed

			: ai:1000;12342/usr/bin/python = allow INTERPRETER
			: a:1000;123422/usr/bin/hello.py = allow INTERPRETER FILE
			: ga:1000;123422/usr/bin/hello.py = allow INTERPRETER FILE

			  - Interpreter not allowed
			  - Interpreter + Interpreter File allowed
			  - Interpreter File allowed

			  python = allone = not allowed
			  python hello.py = allowed  is python allawed and hello.py is allowed
			  hello.py = allowed  is python allowed and hello.py allowed


			: Important:
			: java is special
			: ".jar" Files/Prog. only
			: -classpath is not allowed

			: It is up to the ADMIN to keep the list reasonable according to these rules!


	Thanks		: Linus Torvalds and others


	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, CARLA FRACCI, EVA EVDOKIMOVA, VAKHTANG CHABUKIANI and the
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Admirable ballet dancers.
	

*/


#define PRINTK
#define MAX_DYN 100000
#define RET_SHELL -2
#define ARGV_MAX 16

#define NO_SECURITY_GUARANTEED "SAFER: Could not allocate buffer! Security is no longer guaranteed!\n"


/* test */
/* static char MY_NAME[] = "(C) Peter Boettcher, Muelheim Ruhr, 2023/1, safer"; */



static bool	safer_mode = false;
static bool	printk_mode = false;
static bool	learning_mode = true;
static bool	change_mode = true;	/*true = change_mode allowed */

static char	**global_list_prog = NULL;
static long	global_list_prog_len = 0;

static char	**global_list_learning = NULL;
static long	global_list_learning_len = 0;

static char	**global_list_learning_argv = NULL;
static long	global_list_learning_argv_len = 0;

static char	**global_list_folder = NULL;
static long	global_list_folder_len = 0;

s64		unix_epoch_time_sec = 0;



/* proto. */
struct  safer_info_struct {
	bool safer_mode;
	bool printk_mode;
	bool learning_mode;
	bool change_mode;
	long global_list_prog_len;
	long global_list_folder_len;
	char **global_list_prog;
	char **global_list_folder;
};


/* DATA: Only over function */
void safer_info(struct safer_info_struct *info)
{
	info->safer_mode = safer_mode;
	info->printk_mode = printk_mode;
	info->learning_mode = learning_mode;
	info->change_mode = change_mode;
	info->global_list_prog_len = global_list_prog_len;
	info->global_list_folder_len = global_list_folder_len;
	info->global_list_prog = global_list_prog;
	info->global_list_folder = global_list_folder;
}




/* proto. */
struct  safer_learning_struct {
	long global_list_learning_len;
	char **global_list_learning;
	long global_list_learning_argv_len;
	char **global_list_learning_argv;
};



/* DATA: Only over function */
void safer_learning(struct safer_learning_struct *learning)
{
	learning->global_list_learning_len = global_list_learning_len;
	learning->global_list_learning = global_list_learning;
	learning->global_list_learning_argv_len = global_list_learning_argv_len;
	learning->global_list_learning_argv = global_list_learning_argv;
}



/* proto */
struct sfile_size {
	int	ret;
	size_t	file_size;
};









static int besearch_file(char *str_search,
			char **list,
			long elements)
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



static int besearch_folder(	char *str_search,
				char **list,
				long elements)
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




static long search(char *str_search,
		char **list,
		long elements)
{
	long n;

	for (n = 0; n < elements; n++) {
		if (strncmp(list[n], str_search, strlen(list[n])) == 0) return 0;
	}

	return -1;
}




static struct sfile_size get_file_size(const char *filename)
{
	int	retval;

	void	*data = NULL;

	struct sfile_size file_size;

	/* max read = 0. size in file_size. other 0 is error */
	retval = kernel_read_file_from_path(	filename,
						0,
						&data,
						0,
						&file_size.file_size,
						READING_POLICY);

	if (retval == 0) {
		if (data != NULL) {
			vfree(data);
			data = NULL;
		}

		file_size.ret = 0;
		return(file_size);
	}
	

	file_size.ret = -1;

	return(file_size);
}



/*--------------------------------------------------------------------------------*/
static void learning_argv(uid_t user_id,
			const char *filename,
			char **argv,
			long argv_len,
			char ***list,
			long *list_len)

{

	char			str_user_id[20];
	char			str_file_size[20];
	char			str_argv_size[20];

	struct sfile_size	file_size;
	struct sfile_size	argv_size;

	char	*str_learning =  NULL;
	int	string_length = 0;


	if (argv_len == 1)
		return;

	argv_size = get_file_size(argv[1]);

	if (argv_size.ret == -1)
		return;

	if (argv_size.file_size == 0)
		return;

	//argv_size.file_size = 1234;

	file_size = get_file_size(filename);
	if (file_size.ret == -1)
		return;

	if (file_size.file_size == 0)
		return;

	sprintf(str_user_id, "%u", user_id);
	sprintf(str_file_size, "%lu", file_size.file_size);
	sprintf(str_argv_size, "%lu", argv_size.file_size);



	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen(str_argv_size);
	string_length += strlen(argv[1]);
	string_length += strlen("a:;;::;") + 1;

	str_learning = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_learning)
		panic(NO_SECURITY_GUARANTEED);
		/* return; */

	strcpy(str_learning, "a:");
	strcat(str_learning, str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, filename);
	strcat(str_learning, "::");
	strcat(str_learning, str_argv_size);
	strcat(str_learning, ";");
	strcat(str_learning, argv[1]);

	if (*list_len == 0) {
		*list = kzalloc(sizeof(char *), GFP_ATOMIC);
		if (!*list) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			return;
			*/
		}

		(*list)[0] = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!(*list)[0]) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			kfree(*list);
			return;
			*/
		}

		strcpy((*list)[0], str_learning);
		*list_len = 1;
		kfree(str_learning);
		str_learning = NULL;
		return;
	}


	if (search(str_learning, *list, *list_len) != 0) {
		*list = krealloc(*list, (*list_len + 1) * sizeof(char *), GFP_ATOMIC);
		if (!*list) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			return;
			*/
		}

		(*list)[*list_len] = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!(*list)[*list_len]) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			*list = krealloc(*list, (*list_len - 1) * sizeof(char *), GFP_ATOMIC);
			return;
			*/
		}

		strcpy((*list)[*list_len], str_learning);
		*list_len += 1;
		kfree(str_learning);
		str_learning = NULL;
		return;
	}

	kfree(str_learning);
	str_learning = NULL;
	return;

}









/*--------------------------------------------------------------------------------*/
static void learning(	uid_t user_id,
			const char *filename,
			char ***list,
			long *list_len)
{

	char			str_user_id[20];
	char			str_file_size[20];

	struct sfile_size	file_size;

	char	*str_learning =  NULL;
	int	string_length = 0;



	file_size = get_file_size(filename);
	/* file not exist */
	if (file_size.ret == -1)
		return;

	/* file exist, but empty */
	if (file_size.file_size == 0)
		return;


	sprintf(str_user_id, "%u", user_id);
	sprintf(str_file_size, "%lu", file_size.file_size);

	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen("a:;;") + 1;

	str_learning = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_learning)
		panic(NO_SECURITY_GUARANTEED);
		/* return; */

	strcpy(str_learning, "a:");
	strcat(str_learning, str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, filename);


	if (*list_len == 0) {
		*list = kzalloc(sizeof(char *), GFP_ATOMIC);
		if (!*list) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			return;
			*/
		}

		(*list)[0] = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!(*list)[0]) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			kfree(*list);
			return;
			*/
		}

		strcpy((*list)[0], str_learning);
		*list_len = 1;
		kfree(str_learning);
		str_learning = NULL;
		return;
	}


	if (search(str_learning, *list, *list_len) != 0) {
		*list = krealloc(*list, (*list_len + 1) * sizeof(char *), GFP_ATOMIC);
		if (!*list) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			return;
			*/
		}

		(*list)[*list_len] = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!(*list)[*list_len]) {
			panic(NO_SECURITY_GUARANTEED);
			/*
			kfree(str_learning);
			*list = krealloc(*list, (*list_len - 1) * sizeof(char *), GFP_ATOMIC);
			return;
			*/
		}

		strcpy((*list)[*list_len], str_learning);
		*list_len += 1;
		kfree(str_learning);
		str_learning = NULL;
		return;
	}

	kfree(str_learning);
	str_learning = NULL;
	return;
}






/*--------------------------------------------------------------------------------*/
static int
user_allowed(	uid_t user_id,
		const char *filename,
		size_t file_size,
		char **list,
		long list_len,
		bool printk_mode,
		const char *step)
{

	char str_user_id[20];
	char str_file_size[20];
	char *str_user_file = NULL;

	sprintf(str_user_id, "%d", user_id); 
	sprintf(str_file_size, "%ld", file_size); 

	/* user allowed */
	int string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen("a:;;") + 1;

	str_user_file = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_user_file)
		return -1;

	strcpy(str_user_file, "a:");
	strcat(str_user_file, str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, filename);

	if (besearch_file(str_user_file, list, list_len) == 0) {
		if (printk_mode == true)
			printk("STAT %s: USER/PROG. ALLOWED: a:%s;%s;%s\n", step, str_user_id, str_file_size, filename);
		kfree(str_user_file);
		str_user_file = NULL;
		return 0;
	}

	kfree(str_user_file);
	str_user_file = NULL;
	return -1;
}


/*--------------------------------------------------------------------------------*/
static int
user_deny(uid_t user_id,
	const char *filename,
	size_t file_size,
	char **list,
	long list_len,
	const char *step)

{

	char str_user_id[20];
	char str_file_size[20];
	char *str_user_file = NULL;


	sprintf(str_user_id, "%d", user_id); 
	sprintf(str_file_size, "%ld", file_size); 

	/* user allowed */
	int string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen("d:;;") + 1;

	str_user_file = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_user_file)
		return -1;

	strcpy(str_user_file, "d:");
	strcat(str_user_file, str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, filename);

	if (besearch_file(str_user_file, list, list_len) == 0) {
		printk("STAT %s: USER/PROG. DENY: a:%s;%s;%s\n", step, str_user_id, str_file_size, filename);
		kfree(str_user_file);
		str_user_file = NULL;
		return -1;
	}

	kfree(str_user_file);
	str_user_file = NULL;
	return 0;
}


/*--------------------------------------------------------------------------------*/
static int
group_allowed(uid_t user_id,
		const char *filename,
		size_t file_size,
		char **list,
		long list_len,
		bool printk_mode,
		const char *step)

{

	char	str_user_id[20];
	char	str_file_size[20];
	char	str_group_id[20];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();

	sprintf(str_user_id, "%d", user_id); 


	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);
		sprintf(str_file_size, "%lu", file_size);

		string_length = strlen(str_group_id);
		string_length += strlen(str_file_size);
		string_length += strlen(filename);
		string_length += strlen("ga:;;") +1;

		//if (str_group_file != NULL) kfree(str_group_file);
		str_group_file = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_file)
			return -1;

		strcpy(str_group_file, "ga:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, filename);

		if (besearch_file(str_group_file, list, list_len) == 0) {
			if (printk_mode == true)
				printk("STAT %s: USER/PROG. ALLOWED: ga:%s;%s;%s\n", step, str_user_id, str_file_size, filename);
			kfree(str_group_file);
			str_group_file = NULL;
			return 0;
		}

		kfree(str_group_file);
		str_group_file = NULL;
	}

	return -1;
}


static int
group_deny(	uid_t user_id,
		const char *filename,
		size_t file_size,
		char **list,
		long list_len,
		const char *step)
{

	char	str_user_id[20];
	char	str_file_size[20];
	char	str_group_id[20];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();

	sprintf(str_user_id, "%d", user_id); 

	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);
		sprintf(str_file_size, "%lu", file_size);

		string_length = strlen(str_group_id);
		string_length += strlen(str_file_size);
		string_length += strlen(filename);
		string_length += strlen("gd:;;") +1;

		str_group_file = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_file)
			return -1;

		strcpy(str_group_file, "gd:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, filename);

		if (besearch_file(str_group_file, list, list_len) == 0) {
			printk("STAT %s: USER/PROG. DENY: gd:%s;%s;%s\n", step, str_user_id, str_file_size, filename);
			kfree(str_group_file);
			str_group_file = NULL;
			return -1;
		}
		else {
			kfree(str_group_file);
			str_group_file = NULL;
		}
	}

	return 0;
}


/*--------------------------------------------------------------------------------*/
static int
user_folder_allowed(	uid_t user_id,
			const char *filename,
			size_t file_size,
			char **list,
			long list_len,
			bool printk_mode,
			const char *step)

{

	char str_user_id[20];
	char *str_folder = NULL;
	int  string_length;

	sprintf(str_user_id, "%d", user_id); 

	string_length = strlen(str_user_id);
	string_length += strlen(filename);
	string_length += strlen("a:;") + 1;

	str_folder = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_folder)
		return -1;

	strcpy(str_folder, "a:");
	strcat(str_folder, str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, filename);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == 0) {
		if (printk_mode == true)
			printk("STAT %s: USER/PROG. ALLOWED: a:%s;%s;\n", step, str_user_id, filename);

		kfree(str_folder);
		str_folder = NULL;
		return 0;
	}

	kfree(str_folder);
	str_folder = NULL;
	return -1;
}


static int
user_folder_deny(uid_t user_id,
		const char *filename,
		size_t file_size,
		char **list,
		long list_len,
		const char *step)

{

	char str_user_id[20];
	char *str_folder = NULL;
	int  string_length;

	sprintf(str_user_id, "%d", user_id); 

	string_length = strlen(str_user_id);
	string_length += strlen(filename);
	string_length += strlen("d:;") + 1;

	str_folder = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_folder)
		return -1;

	strcpy(str_folder, "d:");
	strcat(str_folder, str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, filename);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == 0) {
		printk("STAT %s: USER/PROG. DENY: a:%s;%s;\n", step, str_user_id, filename);
		kfree(str_folder);
		str_folder = NULL;
		return -1;
	}

	kfree(str_folder);
	str_folder = NULL;
	return 0;
}


/*--------------------------------------------------------------------------------*/
static int
group_folder_allowed(	uid_t user_id,
			const char *filename,
			size_t file_size,
			char **list,
			long list_len,
			bool printk_mode,
			const char *step)

{

	char	str_user_id[20];
	char	str_group_id[20];
	char	*str_group_folder = NULL;
	struct	group_info *group_info;
	int	string_length;


	group_info = get_current_groups();

	sprintf(str_user_id, "%d", user_id); 


	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(filename);
		string_length += strlen("ga:;") + 1;

		//if (str_group_folder != NULL) kfree(str_group_folder);
		str_group_folder = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_folder)
			return -1;

		strcpy(str_group_folder, "ga:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, filename);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == 0) {
			if (printk_mode == true)
				printk("STAT %s: USER/PROG. ALLOWED: a:%s;%s\n", step, str_user_id, filename);
			kfree(str_group_folder);
			str_group_folder = NULL;
			return 0;
		}
		else {
			kfree(str_group_folder);
			str_group_folder = NULL;
		}
	}

	return -1;
}


static int
group_folder_deny(uid_t user_id,
		const char *filename,
		size_t file_size,
		char **list,
		long list_len,
		const char *step)

{

	char	str_user_id[20];
	char	str_group_id[20];
	char	*str_group_folder = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();

	sprintf(str_user_id, "%d", user_id); 


	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(filename);
		string_length += strlen("gd:;") + 1;

		//if (str_group_folder != NULL) kfree(str_group_folder);
		str_group_folder = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_folder)
			return -1;

		strcpy(str_group_folder, "gd:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, filename);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == 0) {
			printk("STAT %s: USER/PROG. ALLOWED: d:%s;%s\n", step, str_user_id, filename);
			kfree(str_group_folder);
			str_group_folder = NULL;
			return -1;
		}
		else {
			kfree(str_group_folder);
			str_group_folder = NULL;
		}
	}

	return 0;
}


/*--------------------------------------------------------------------------------*/
static int
user_interpreter_allowed(uid_t user_id,
			const char *filename,
			size_t file_size,
			char **list,
			long list_len,
			bool printk_mode,
			const char *step)

{
	char	str_user_id[20];
	char	str_file_size[20];
	char	*str_user_file = NULL;
	int	string_length;


	sprintf(str_user_id, "%d", user_id); 
	sprintf(str_file_size, "%ld", file_size); 


	/* user allowed interpreter */
	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen("ai:;;") + 1;

	str_user_file = kmalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (str_user_file == NULL)
		return -1;

	strcpy(str_user_file, "ai:");
	strcat(str_user_file, str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, filename);


	if (besearch_file(str_user_file, list, list_len) == 0) {
		if (printk_mode == true)
			printk("STAT %s: USER/PROG. ALLOWED: ai:%s;%s;%s\n", step, str_user_id, str_file_size, filename);

		kfree(str_user_file);
		str_user_file = NULL;
		return 0;
	}

	kfree(str_user_file);
	str_user_file = NULL;

	return -1;
}



/* user allowed interpreter and allowed group script file*/
/* 0 allowed */
/* -1 deny */
static int
user_interpreter_file_allowed(	uid_t user_id,
				const char *filename,
				size_t file_size,
				char **argv,
				long argv_len,
				char **list,
				long list_len,
				bool printk_mode,
				const char *step)

{

	int retval;
	struct sfile_size argv_size;

	if (argv_len == 1) return -1;


	/* check interpreter and files */
	/* user allowed interpreter */
	retval = user_interpreter_allowed(user_id,
					filename,
					file_size,
					list,
					list_len,
					printk_mode,
					step);

	if (retval ==  -1) return -1;


	if (strcmp(argv[1], "-jar") == 0) {
		if (argv_len == 2) return -1;

		argv_size = get_file_size(argv[2]);

		/* error file */
		if (argv_size.ret == -1) return -1;
		/* file size = 0 */
		if (argv_size.file_size == 0) return -1;

		/* check file/prog is in list/allowed */
		if (user_allowed(user_id, argv[2], argv_size.file_size, list, list_len, printk_mode, step) == 0) return 0;
		if (group_allowed(user_id, argv[2], argv_size.file_size, list, list_len, printk_mode, step) == 0) return 0;

		printk("STAT %s: USER/INTERPRETER PROG. DENY: a:%d;%ld,%s;\n", step, user_id, argv_size.file_size, argv[2]);
		return -1;
	}

	/* other */
	argv_size = get_file_size(argv[1]);
	/* error file */
	if (argv_size.ret  == -1) return -1;
	/* file size = 0 */
	if (argv_size.file_size  == 0) return -1;

	/* check file/prog is in list/allowed */
	if (user_allowed(user_id, argv[1], argv_size.file_size, list, list_len, printk_mode, step) == 0) return 0;
	if (group_allowed(user_id, argv[1], argv_size.file_size, list, list_len, printk_mode, step) == 0) return 0;

	printk("STAT %s: USER/INTERPRETER PROG. DENY: a:%d;%ld,%s;\n", step, user_id, argv_size.file_size, argv[1]);

	/* not found */
	return -1;
}


static int exec_first_step(uid_t user_id, const char *filename, char **argv, long argv_len)
{

	struct sfile_size file_size;


	file_size = get_file_size(filename);

	/* file exist? */
	if (file_size.ret == -1) return RET_SHELL;

	if (printk_mode == true) {
		printk("USER ID:%u, PROG:%s, SIZE:%lu\n", user_id, filename, file_size.file_size);

		for (int n = 0; n < argv_len; n++) {
			printk("argv[%d]:%s\n", n, argv[n]);
		}
	}


	/* group deny folder */
	if (global_list_folder_len > 0) {
		if (group_folder_deny(	user_id,
				filename,
				file_size.file_size,
				global_list_prog,
				global_list_prog_len,
				"FIRST") == 1)
			return RET_SHELL;
	}

	/* deny folder */
	if (global_list_folder_len > 0) {
		if (user_folder_deny(	user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					"FIRST") == 1)
				return RET_SHELL;
	}

	/* deny group */
	if (global_list_prog_len > 0) {
		if (group_deny( user_id,
				filename,
				file_size.file_size,
				global_list_prog,
				global_list_prog_len,
				"FIRST") == 1)
			return RET_SHELL;
	}

	/* deny user */
	if (global_list_prog_len > 0) {
		if (user_deny(	user_id,
				filename,
				file_size.file_size,
				global_list_prog,
				global_list_prog_len,
				"FIRST") == 1)
			return RET_SHELL;
	}

	/* group allowed folder */
	if (global_list_folder_len > 0) {
		if (group_folder_allowed(user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					printk_mode,
					"FIRST") == 0)
				return 0;
	}

	/* user allowed folder */
	if (global_list_folder_len > 0) {
		if (user_folder_allowed(user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					printk_mode,
					"FIRST") == 0)
				return 0;
	}

	/* allowed user */
	if (global_list_prog_len > 0) {
		if (user_allowed(user_id,
				filename,
				file_size.file_size,
				global_list_prog,
				global_list_prog_len,
				printk_mode,
				"FIRST") == 0)
			return 0;
	}

	/* allowed group */
	if (global_list_prog_len > 0) {
		if (group_allowed(user_id,
				filename,
				file_size.file_size,
				global_list_prog,
				global_list_prog_len,
				printk_mode,
				"FIRST") == 0)
			return 0;
	}

	/* user allowed interpreter and allowed group script file*/
	/* 0 allowed */
	/* -1 deny */
	if (global_list_prog_len > 0) {
		if (user_interpreter_file_allowed(user_id,
					filename,
					file_size.file_size,
					argv,
					argv_len,
					global_list_prog,
					global_list_prog_len,
					printk_mode,
					"FIRST") == 0)
				return 0;
	}


	printk("STAT END FIRST STEP: USER/PROG. FILE DENY: a:%d;%ld;%s\n", user_id, file_size.file_size, filename);
	return (RET_SHELL);

}







static int exec_second_step(const char *filename)
{

	struct sfile_size file_size;

	uid_t user_id = get_current_user()->uid.val;


	if (learning_mode == true)
			learning(user_id,
				filename,
				&global_list_learning,
				&global_list_learning_len);


	if (safer_mode == true) {

		/* file size? */
		file_size = get_file_size(filename);

		if (file_size.ret == -1) return RET_SHELL;

		/* group deny folder */
		if (global_list_folder_len > 0) {
			if (group_folder_deny(	user_id,
						filename,
						file_size.file_size,
						global_list_prog,
						global_list_prog_len,
						"SEC  ") == 1)
					return RET_SHELL;
		}

		/* deny folder */
		if (global_list_folder_len > 0) {
			if (user_folder_deny(	user_id,
						filename,
						file_size.file_size,
						global_list_prog,
						global_list_prog_len,
						"SEC  ") == 1)
					return RET_SHELL;
		}

		/* deny group */
		if (global_list_prog_len > 0) {
			if (group_deny(user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					"SEC  ") == 1)
				return RET_SHELL;
		}

		/* deny user */
		if (global_list_prog_len > 0) {
			if (user_deny(	user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					"SEC  ") == 1)
				return RET_SHELL;
		}

		/* allowed folder */
		if (global_list_folder_len > 0) {
			if (group_folder_allowed(user_id,
						filename,
						file_size.file_size,
						global_list_prog,
						global_list_prog_len,
						printk_mode,
						"SEC  ") == 0)
					return 0;
		}

		/* allowed folder */
		if (global_list_folder_len > 0) {
			if (user_folder_allowed(user_id,
						filename,
						file_size.file_size,
						global_list_prog,
						global_list_prog_len,
						printk_mode,
						"SEC  ") == 0)
					return 0;
		}

		/* allowed user */
		if (global_list_prog_len > 0) {
			if (user_allowed(user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					printk_mode,
					"SEC  ") == 0)
				return 0;
		}

		/* allowed group */
		if (global_list_prog_len > 0) {
			if (group_allowed(user_id,
					filename,
					file_size.file_size,
					global_list_prog,
					global_list_prog_len,
					printk_mode,
					"SEC  ") == 0)
				return 0;
		}

		/* user allowed interpreter */
		if (global_list_prog_len > 0) {
			if (user_interpreter_allowed(	user_id,
							filename,
							file_size.file_size,
							global_list_prog,
							global_list_prog_len,
							printk_mode,
							"SEC  ") == 0)
						return 0;
		}

		printk("STAT ENS SEC STEP: USER/PROG. DENY: a:%d;%ld;%s\n", user_id, file_size.file_size, filename);
		return (RET_SHELL);
	}

	return 0;
}





static int allowed_exec(const char *filename,
			const char __user *const __user *_argv)
{

	struct user_arg_ptr argv = { .ptr.native = _argv };

	const char __user	*str;
	char			**argv_list = NULL;
	long			argv_list_len = 0;
	long			str_len;
	int			retval = 0;
	char			*kernel_filename;
	uid_t			user_id;


	/* not time critical, but necessary! */
	if (unix_epoch_time_sec == 0)
		ktime_get_real_seconds();


	if (safer_mode == false)
		if (learning_mode == false) return 0;


	/* filename -> kernel space */
	str_len = strnlen_user(filename, MAX_ARG_STRLEN) + 1;

	kernel_filename = kzalloc(str_len * sizeof(char), GFP_ATOMIC);

	if (kernel_filename == NULL)
		panic(NO_SECURITY_GUARANTEED);
		/* return RET_SHELL; */


	retval = copy_from_user(kernel_filename, filename, str_len );


	/* argv -> kernel space */
	argv_list_len = count(argv, MAX_ARG_STRINGS);

	if (argv_list_len > ARGV_MAX) argv_list_len = ARGV_MAX;


	argv_list = kzalloc(argv_list_len * sizeof(char *), GFP_ATOMIC);
	if (argv_list == NULL) {
		panic(NO_SECURITY_GUARANTEED);
		/*
		kfree(kernel_filename);
		return RET_SHELL;
		*/
	}


	for (int n = 0; n < argv_list_len; n++) {
		str = get_user_arg_ptr(argv, n);
		str_len = strnlen_user(str, MAX_ARG_STRLEN);

		argv_list[n] = kzalloc((str_len + 1) * sizeof(char), GFP_ATOMIC);

		if (argv_list[n] == NULL)
			panic(NO_SECURITY_GUARANTEED);

		retval = copy_from_user(argv_list[n], str, str_len);
	}


	user_id = get_current_user()->uid.val;


	/* not time critical, but necessary! */
	/* the kernel is not yet fully initialized ??? */

	s64 new_unix_epoch_time_sec = ktime_get_real_seconds();

	if ((new_unix_epoch_time_sec - unix_epoch_time_sec) > 5)
		if (learning_mode == true) if (argv_list_len > 1)
		learning_argv(	user_id,
				kernel_filename,
				argv_list,
				argv_list_len,
				&global_list_learning_argv,
				&global_list_learning_argv_len);


	if (safer_mode == true)
		retval = exec_first_step(user_id, kernel_filename, argv_list, argv_list_len);


	for (int n = 0; n < argv_list_len; n++) {
		if (argv_list[n] != NULL) {
			kfree(argv_list[n]);
			argv_list[n] = NULL;
		}
	}

	if (argv_list != NULL) {
		kfree(argv_list);
		argv_list = NULL;
	}


	if (kernel_filename != NULL) {
		kfree(kernel_filename);
		kernel_filename = NULL;
	}


	return retval;

}











SYSCALL_DEFINE5(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp,
		const loff_t, number,
		const char __user *const __user *, list)
{

	uid_t	user_id;
	int	str_len = 0;
	char	*list_string = NULL;

	struct user_arg_ptr _list = { .ptr.native = list };
	const char __user *str;



	user_id = get_current_user()->uid.val;

	/* command part, future ? */
	switch(number) {
		/* safer on */
		case 999900:	if (change_mode == false) return -1;
				if (user_id != 0) return -1;

				if (global_list_prog_len > 0 || global_list_folder_len > 0) {
					safer_mode = true;
#ifdef PRINTK
					printk("MODE: SAFER ON\n");
#endif
					return 0;
				}
				else {
#ifdef PRINTK
					printk("MODE: SAFER OFF\n");
#endif
					return -1;
				}


		/* safer off */
		case 999901:	if (change_mode == false) return -1;
				if (user_id != 0) return -1;
#ifdef PRINTK
				printk("MODE: SAFER OFF\n");
#endif
				safer_mode = false;
				return 0;


		/* stat */
		case 999902:	if (change_mode == false) return -1;
				if (user_id != 0) return -1;
#ifdef PRINTK
				printk("SAFER STATE         : %d\n", safer_mode);
#endif
				return(safer_mode);


		/* printk on */
		case 999903:	if (change_mode == false) return -1;
				if (user_id != 0) return -1;
#ifdef PRINTK
				printk("MODE: SAFER PRINTK ON\n");
#endif
				printk_mode = true;
				return 0;


		/* printk off */
		case 999904:	if (change_mode == false) return(-1);
				if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: SAFER PRINTK OFF\n");
#endif
				printk_mode = false;
				return 0;


		case 999905:	if (change_mode == false) return -1;
				if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: NO MORE CHANGES ALLOWED\n");
#endif
				change_mode = false;
				return 0;


		case 999906:	if (change_mode == false) return -1;
				if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: learning ON\n");
#endif
				learning_mode = true;

				return 0;


		case 999907:	if (change_mode == false) return -1;
				if (user_id != 0) return(-1);
#ifdef PRINTK
				printk("MODE: learning OFF\n");
#endif
				learning_mode = false;

				return 0;


		/* set all list */
		case 999920:

				if (change_mode == false) return -1;
				if (user_id != 0) return -1;


				if (list == NULL) {		/* check? */
#ifdef PRINTK
					printk("ERROR: FILE LIST\n");
#endif
					return -1;
				} /* check!? */

				/* clear */
				if (global_list_prog_len > 0) {
					for (int n = 0; n < global_list_prog_len; n++) {
						if (global_list_prog[n] != NULL) {
								kfree(global_list_prog[n]);
								global_list_prog[n] = NULL;
						}
					}

					if (global_list_prog != NULL) {
						kfree(global_list_prog);
						global_list_prog = NULL;
					}
				}


				int int_ret = count(_list, MAX_ARG_STRINGS);
				if (int_ret == 0) return -1;

				str = get_user_arg_ptr(_list, 0);		/* String 0 */
				str_len = strnlen_user(str, MAX_ARG_STRLEN);
				if (str_len < 1) return -1;

				if (list_string != NULL) { kfree(list_string); list_string = NULL; }		/* sicher ist sicher */
				list_string = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) panic(NO_SECURITY_GUARANTEED);
				int_ret = copy_from_user(list_string, str, str_len);

				int_ret = kstrtol(list_string, 10, &global_list_prog_len);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; }
				if (int_ret != 0) return -1;


				if (global_list_prog_len < 1) {
#ifdef PRINTK
					printk("NO FILE LIST\n");
#endif
					return -1;
				}

				if (global_list_prog_len > MAX_DYN) {
#ifdef PRINTK
					printk("FILE LIST TO BIG!\n");
#endif
					return -1;
				}

#ifdef PRINTK
				printk("FILE LIST ELEMENTS: %ld\n", global_list_prog_len);
#endif


				/* dyn array */
				global_list_prog = kmalloc(global_list_prog_len * sizeof(char *), GFP_KERNEL);
				if (global_list_prog == NULL) panic(NO_SECURITY_GUARANTEED);

				for (int n = 0; n < global_list_prog_len; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					global_list_prog[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					if (global_list_prog[n] == NULL) panic(NO_SECURITY_GUARANTEED);

					int_ret = copy_from_user(global_list_prog[n], str, str_len);
				}

				return(global_list_prog_len);


		/* set all folder list */
		case 999921:
				if (change_mode == false) return -1;
				if (user_id != 0) return -1;


				if (list == NULL) {		/* check? */
#ifdef PRINTK
					printk("ERROR: FOLDER LIST\n");
#endif
					return -1;
				} /* check!? */

				/* clear */
				if (global_list_folder_len > 0) {
					for (int n = 0; n < global_list_folder_len; n++) {
						if (global_list_folder[n] != NULL) {
							kfree(global_list_folder[n]);
							global_list_folder[n] = NULL;
						}
						
					}

					if (global_list_folder != NULL) {
						kfree(global_list_folder);
						global_list_folder = NULL;
					}
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

				int_ret = kstrtol(list_string, 10, &global_list_folder_len);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; };
				if (int_ret != 0) return -1;


				if (global_list_folder_len < 1) {
#ifdef PRINTK
					printk("NO FOLDER LIST\n");
#endif
					return -1;
				}

				if (global_list_folder_len > MAX_DYN) {
#ifdef PRINTK
					printk("FOLDER LIST TO BIG!\n");
#endif
					return -1;
				}

#ifdef PRINTK
				printk("FOLDER LIST ELEMENTS: %ld\n", global_list_folder_len);
#endif


				/* dyn array */ 
				global_list_folder = kmalloc(global_list_folder_len * sizeof(char *), GFP_KERNEL);
				if (global_list_folder == NULL) panic(NO_SECURITY_GUARANTEED);


				for (int n = 0; n < global_list_folder_len; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					global_list_folder[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					if (global_list_folder[n] == NULL) panic(NO_SECURITY_GUARANTEED);

					int_ret = copy_from_user(global_list_folder[n], str, str_len);
				}

				return(global_list_folder_len);

		default:	break;
	}

	if (allowed_exec(filename, argv) == RET_SHELL) return(RET_SHELL);


	return do_execve(getname(filename), argv, envp);

}







