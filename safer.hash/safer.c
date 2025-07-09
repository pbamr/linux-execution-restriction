/* Copyright (c) 2022/03/28, 2025.07.08, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.03.28, 2025.07.08, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

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
	Date		: 2022.04.22 - 2025.07.08

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 6.15.0

			  Lenovo X230, T460, T470, Fujitsu Futro S xxx, AMD Ryzen Zen 3
			  Proxmox, Docker

	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root

			: USER and GROUPS

			: Extension of SYSCALL <execve>
			  You found <replaces> under "add_safer"

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas, csafer.c
			: Simple Control Program for Extension <SYSCALL execve>
			: It only works as <root>

	LIST		: If you use binary search, a sorted list ist required
			: ALLOWED and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable files in folder
			: Several thousand entries are then no problem.

	Control		: Safer Mode = ON
			: Log Mode = Logs all programs from init
			  LOG only once

			: 999900 = safer ON
			: 999901 = safer OFF
			: 999902 = State

			: 999903 = Log ON, allowed
			: 999904 = Log OFF, allowed

			: 999905 = LOCK changes

			: 999906 = learning on
			: 999907 = learning off

			: 999908 = verbose parameter show ON
			: 999909 = verbose parameter show OFF


			: 999920 = Set FILE List
			: 999921 = Set FOLDER List

			: 999912 = Log ON, deny
			: 999913 = Log OFF, deny


	Rules allowed	:
			  a  = user allowed
			  ga = group allowed

			  a:USER-ID;PATH-FOLDER/
			  ga:GROUP-ID;PATH-FOLDER/
			  a:*;PATH-FOLDER/

			  a:USER-ID;FILE-SIZE;HASH;PATH-FILE
			  ga:GROUP-ID;FILE-SIZE;HASH;PATH-FILE
			  a:*;FILE-SIZE;HASH;PATH-FILE

	Interpreter:
			  ai:USER-ID;FILE-SIZE;HASH;PATH-FILE
			  gai:USER-ID;FILE-SIZE;HASH;PATH-FILE
			  a:USER-ID;FILE-SIZE;HASH;PATH-FILE-Script

			  Only SCRIPTS allowed. Python without Script will not work.
			  Python Scripts will work.
			


	Rules deny	:
			  d  = user deny
			  gd = group deny

			  DENY is not absolutely necessary
			  But maybe faster
			  The same is PROG. not in list


			  d:USER-ID;PATH-FOLDER/
			  gd:GROUP-ID;PATH-FOLDER/
			  d:*;PATH-FOLDER/

			  d:USER-ID;PATH-FILE
			  gd:GROUP-ID;PATH-FILE
			  d:*;PATH-FILE


	Example		:
			 a:1000;PATH-FOLDER/
			 ga:1000;PATH-FOLDER/
			 a:*;PATH-FOLDER/

			 d:1000;PATH-FOLDER/
			 gd:1000;PATH-FOLDER/
			 d:*;PATH-FOLDER/


			 a:1000;1234;HASH;PATH-FILE
			 ga:1000;1234;HASH;PATH-FILE
			 a:*;1234;HASH;PATH-FILE

			 ai:1000;1234;HASH;PATH-FILE
			 gai:1000;1234;HASH;PATH-FILE
			 a:1000;1234;HASH;PATH-SCRIPT-FILE

			 d:1000;PATH-FILE
			 gd:1000;PATH-FILE
			 d:*;PATH-FILE



Interpreter not allowed:
			  - Interpreter + Interpreter File allowed
			  - Interpreter File allowed

			  python = allone = not allowed
			  python <PATH>/hello.py = allowed  is python allowed and hello.py is allowed
			  hello.py = allowed  is python allowed and hello.py allowed



			: Important:
			: java is supported
			: -jar			java -jar <PATH>/file.jar
			: -classpath		java -classpath <PATH> <NAME>


			: This is also possible
			: ai:0;1234;HASH;/sbin/insmod
			: a:0;1234;HASH;/lib/modules/KERNEL-VERSION/modulx.ko


			: It is up to the ADMIN to keep the list reasonable according to these rules!



	Install
			: copy safer.c -> fs/
			  copy safer_info.c -> /fs
			  copy safer_learning.c -> /fs

			  look for changes "#define add_safer" in EXAMPLE "fs:exec.c" and write in your current "exec.c"

			  write in fs/Makefile
			  obj-y	+= safer_info.o
			  obj-y	+= safer_learning.o


	with syscall	: *.tbl
			  xxx common set_execve_list sys_set_execve_list

			  make bzImage (architecture)


	Frontend:
			: fpsafer.pas, csafer.c

			  Search Executables:
			  search.exec

	Working
			: The easiest way to use "safer" is to use "/proc/safer.learning".
			  Simply save the content to a file.

			  This will then be loaded into the kernel.
			  Example programs: "csafer PLIST <file.conf>" (root only)
			  Example folder  : "csafer FLIST <file.conf>" (root only)

			  Then activate (root only)
			  Example: "csafer SON"

			  The programs are then only executed according to the list.

			  Programs that are required but are not on the list must then be included
			  be added.


	Start		:
			  Manually

			  Init System

			  Included in the "initramfs"
			  The best way to find all required programs in the "initramfs" is: test
			  this with the command "csafer PDON". Then look at dmesg: "deny"

			  Another option: Include the list in the kernel. Not yet realized


	Thanks		: Linus Torvalds and others





	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, CARLA FRACCI, EVA EVDOKIMOVA, VAKHTANG CHABUKIANI and the
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Admirable ballet dancers.
*/






/*
Look -> "exec_first_step"
Limit argv[0] = 1000
Reason glibc
A GOOD IDEA? I don't know?
But it's works
when in doubt remove it
*/



/*--------------------------------------------------------------------------------*/
/* HASH ?*/

/* Your choice */
/*
#define HASH_ALG "md5"
#define DIGIT 16
*/

#define HASH_ALG "sha256"
#define DIGIT 32
/*
#define HASH_ALG "sha512"
#define DIGIT 64
*/

#define HASH_STRING_LENGTH (DIGIT * 2) + 1




/*your choice */
#define MAX_DYN 100000
#define MAX_DYN_BYTES MAX_DYN * 200
#define ARGV_MAX 16
#define LEARNING_ARGV_MAX 5000
#define KERNEL_READ_SIZE 2000000




#define RET_SHELL -1
#define ALLOWED 0
#define NOT_ALLOWED -1
#define CONTROL_ERROR -1
#define CONRTOL_OK 0
#define ERROR -1
#define NOT_IN_LIST -1


/*--------------------------------------------------------------------------------*/
static DEFINE_MUTEX(learning_lock);
static DEFINE_MUTEX(control);
/*
static DEFINE_MUTEX(allowed_lock);
*/


static bool	safer_mode = false;

static bool	printk_allowed = false;
static bool	printk_deny = false;
static bool	learning_mode = true;
static bool	change_mode = true;	/*true = change_mode allowed */
static bool	verbose_param_mode = false;

static char	**global_list_prog = NULL;
static long	global_list_prog_size = 0;

static char	**global_list_learning = NULL;
static long	global_list_learning_size = 0;

static char	**global_list_learning_argv = NULL;
static long	global_list_learning_argv_size = 0;
static bool	global_list_learning_argv_init = false;

static char	**global_list_folder = NULL;
static long	global_list_folder_size = 0;

static long	global_list_progs_bytes = 0;
static long	global_list_folders_bytes = 0;



/*--------------------------------------------------------------------------------*/
/* proto. */
struct struct_file_info {
	bool		retval;
	char		hash_string[HASH_STRING_LENGTH];
	ssize_t		file_size;
	char		str_file_size[19];
	char		str_user_id[19];
	uid_t		user_id;
	const char	*fname;
};

/*--------------------------------------------------------------------------------*/
/* proto. */
struct struct_hash_sum {
	bool	retval;
	char	hash_string[HASH_STRING_LENGTH];
};




/*--------------------------------------------------------------------------------*/
/* proto. */
struct  safer_info_struct {
	bool safer_mode;
	bool printk_allowed;
	bool printk_deny;
	bool learning_mode;
	bool change_mode;
	long global_list_prog_size;
	long global_list_folder_size;
	char **global_list_prog;
	char **global_list_folder;
	long global_hash_size;
	long global_list_progs_bytes;
	long global_list_folders_bytes;
};


/* proto. */
struct  safer_learning_struct {
	long global_list_learning_size;
	char **global_list_learning;
	long global_list_learning_argv_max;
	long global_list_learning_argv_size;
	char **global_list_learning_argv;
};


/* Makes compiler happy */
void safer_info(struct safer_info_struct *info);
void safer_learning(struct safer_learning_struct *learning);


/* DATA: Only over function */
void safer_info(struct safer_info_struct *info)
{
	info->safer_mode = safer_mode;
	info->printk_allowed = printk_allowed;
	info->printk_deny = printk_deny;
	info->learning_mode = learning_mode;
	info->change_mode = change_mode;
	info->global_list_prog_size = global_list_prog_size;
	info->global_list_folder_size = global_list_folder_size;
	info->global_list_prog = global_list_prog;
	info->global_list_folder = global_list_folder;
	info->global_hash_size = KERNEL_READ_SIZE;
	info->global_list_progs_bytes = global_list_progs_bytes;
	info->global_list_folders_bytes = global_list_folders_bytes;
	return;
}


/* DATA: Only over function */
void safer_learning(struct safer_learning_struct *learning)
{
	learning->global_list_learning_size = global_list_learning_size;
	learning->global_list_learning = global_list_learning;
	learning->global_list_learning_argv_max = LEARNING_ARGV_MAX;
	learning->global_list_learning_argv_size = global_list_learning_argv_size;
	learning->global_list_learning_argv = global_list_learning_argv;
	return;
}



/*--------------------------------------------------------------------------------*/
static bool besearch_file(char *str_search,
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

		if (int_ret == 0) return true;
		else if (int_ret < 0) left = middle + 1;
		else if (int_ret > 0) right = middle - 1;
	}

	return false;
}



/*
	/usr/bin
	/usr/bin/ls

	check: is "/usr/bin/" in "/usr/bin/ls"
*/

static bool besearch_folder(	char *str_search,
				char **list,
				long elements)
{
	long left, right;
	long middle;
	long int_ret;


	if (str_search[strlen(str_search) -1] == '/' ) return NOT_IN_LIST;


	left = 0;
	right = elements - 1;

	while(left <= right) {
		middle = (left + right) / 2;

		int_ret = strncmp(list[middle], str_search, strlen(list[middle]));

		if (int_ret == 0) return true;
		else if (int_ret < 0) left = middle + 1;
		else if (int_ret > 0) right = middle - 1;
	}

	return false;
}


static bool search(char *str_search,
		char **list,
		long elements)
{
	long n;

	for (n = 0; n < elements; n++) {
		if (strncmp(list[n], str_search, strlen(list[n])) == 0) return true;
	}

	return false;
}


/*--------------------------------------------------------------------------------*/
static ssize_t get_file_size(const char *filename)
{

	loff_t	i_size;
	struct	file *file;

	file = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(file))
		return ERROR;

	if (!S_ISREG(file_inode(file)->i_mode)) {
		fput(file);
		return ERROR;
	}

	if (deny_write_access(file)) {
		fput(file);
		return ERROR;
	}

	i_size = i_size_read(file_inode(file));
	if (i_size < 1) {
		allow_write_access(file);
		fput(file);
		return ERROR;
	}

	/* The file is too big for sane activities. */
	if (i_size > INT_MAX) {
		allow_write_access(file);
		fput(file);
		return ERROR;
	}

	allow_write_access(file);
	fput(file);
	return (ssize_t) i_size;
}




/*--------------------------------------------------------------------------------*/
static struct struct_hash_sum get_hash_sum(char buffer[], int max)
{

	char			hash_out[DIGIT];
	struct crypto_shash	*hash;
	struct shash_desc	*shash;
	struct struct_hash_sum	struct_hash_sum;

	char			hash_[2];


	hash = crypto_alloc_shash(HASH_ALG, 0, 0);
	if (IS_ERR(hash)) {
		struct_hash_sum.retval = false;
		return struct_hash_sum;
	}

	shash = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash), GFP_KERNEL);
	if (!shash) {
		struct_hash_sum.retval = false;
		crypto_free_shash(hash);
		return struct_hash_sum;
	}

	shash->tfm = hash;


	if (crypto_shash_init(shash)) {
		struct_hash_sum.retval = false;
		crypto_free_shash(hash);
		kfree(shash);
		return struct_hash_sum;
	}


	if (crypto_shash_update(shash, buffer, max)) {
		struct_hash_sum.retval = false;
		crypto_free_shash(hash);
		kfree(shash);
		return struct_hash_sum;
	}

	if (crypto_shash_final(shash, hash_out)) {
		struct_hash_sum.retval = false;
		crypto_free_shash(hash);
		kfree(shash);
		return struct_hash_sum;
	}

	kfree(shash);
	crypto_free_shash(hash);


	for (int n = 0; n < DIGIT; n++) {
		sprintf(hash_, "%02x", (unsigned char) hash_out[n]);
		struct_hash_sum.hash_string[n * 2] = hash_[0];
		struct_hash_sum.hash_string[(n * 2) + 1] = hash_[1];
	}

	/* Byte 63 = Last DIGIT. Byte 64 = 0. '\0' = 1 Byte */
	struct_hash_sum.hash_string[DIGIT * 2] = '\0';
	struct_hash_sum.retval = true;

	return struct_hash_sum;
}


static struct struct_file_info get_file_info(const char *fname)
{
	ssize_t				retval;
	ssize_t				file_size;
	void				*data = NULL;
	struct struct_file_info		struct_file_info;
	int				max = KERNEL_READ_SIZE;


	struct_file_info.fname = fname;
	struct_file_info.user_id = get_current_user()->uid.val;
	sprintf(struct_file_info.str_user_id, "%d", struct_file_info.user_id);



	struct_file_info.file_size = get_file_size(fname);
	if (struct_file_info.file_size == ERROR) {
		struct_file_info.retval = false;
		return struct_file_info;
	}


	/* Datei einlesen */
	retval = kernel_read_file_from_path(	fname,
						0,
						&data,
						KERNEL_READ_SIZE,
						&file_size,
						READING_POLICY);

	if (retval < 1) {
		vfree(data);
		struct_file_info.file_size = ERROR;
		struct_file_info.hash_string[0] = '\0'; /* '\0' gleich 1 Byte' */
		struct_file_info.retval = false;
		return struct_file_info;
	}

	if (file_size < 1) {
		vfree(data);
		struct_file_info.file_size = ERROR;
		struct_file_info.hash_string[0] = '\0';
		struct_file_info.retval = false;
		return struct_file_info;
	}

	/* wieviel Bytes von Datei einlesen */
	if (file_size < max) max = file_size;

	char *buffer = data;

	struct struct_hash_sum struct_hash_sum = get_hash_sum(buffer, max);
	if (struct_hash_sum.retval == true) {
		vfree(data);

		struct_file_info.file_size = get_file_size(fname);
		sprintf(struct_file_info.str_file_size, "%ld", struct_file_info.file_size);

		strcpy(struct_file_info.hash_string, struct_hash_sum.hash_string);

		struct_file_info.retval = true;

		return struct_file_info;
	}

	vfree(data);
	struct_file_info.retval = false;
	struct_file_info.file_size = ERROR;
	struct_file_info.hash_string[0] = '\0';
	return struct_file_info;
}




/*--------------------------------------------------------------------------------*/
static void learning_argv(struct struct_file_info *struct_file_info,
			char **argv,
			long argv_len,
			char ***list,
			long *list_len,
			bool *list_init)

{

	char	*str_learning =  NULL;
	int	string_length = 0;


	if (argv_len == 1) return;

	// file not exist or empty 
	if (struct_file_info->retval == false) return;


	// init list, vollstaendig max Zeilen
	// Only One 
	if (*list_init == false) {
		*list = kzalloc(sizeof(char *) * LEARNING_ARGV_MAX, GFP_KERNEL);
		if (*list == NULL) {
			return;
		}
		else *list_init = true;
	}

	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen("a:;;;") + 1;

	//if (argv_len > 10) argv_len = 10;
	for (int n = 1; n < argv_len; n++) {
		string_length += strlen(argv[n]);
		string_length += 1;
	}


	str_learning = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_learning) return;


	strcpy(str_learning, "a:");
	strcat(str_learning, struct_file_info->str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, struct_file_info->str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, struct_file_info->fname);
	strcat(str_learning, ";");

	for (int n = 1; n < argv_len; n++) {
		strcat(str_learning, argv[n]);
		strcat(str_learning, ";");
	}


	if (search(str_learning, *list, *list_len) != true) {

		// Wenn Umlauf?
		if ((*list)[*list_len] != NULL)
			kfree((*list)[*list_len]);

		(*list)[*list_len] = kzalloc(string_length * sizeof(char), GFP_KERNEL);
			if ((*list)[*list_len] == NULL) {
				kfree(str_learning);
				return;
			}

		strcpy((*list)[*list_len], str_learning);

		*list_len += 1;
		// check argv_len > lerning_argv_max
		if (*list_len > LEARNING_ARGV_MAX - 1)
			*list_len = 0;

	}

	kfree(str_learning);
	return;
}




static void learning(	struct struct_file_info *struct_file_info,
			char ***list,
			long *list_len)
{

	char	*str_learning =  NULL;
	int	string_length = 0;

	if (struct_file_info->retval == false) return;


	if (struct_file_info->fname[0] != '/') return;
	if (struct_file_info->retval == false) return;


	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen(struct_file_info->hash_string);
	string_length += strlen("a:;;;") + 1;


	str_learning = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_learning) {
		return;
	}

	strcpy(str_learning, "a:");
	strcat(str_learning, struct_file_info->str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, struct_file_info->str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, struct_file_info->hash_string);
	strcat(str_learning, ";");
	strcat(str_learning, struct_file_info->fname);


	if (search(str_learning, *list, *list_len) != true) {

	// init
	if (*list_len == 0) {
			*list = kzalloc(sizeof(char *), GFP_KERNEL);
			if (*list == NULL) {
				kfree(str_learning);
				return;
			}

			(*list)[0] = kzalloc(string_length * sizeof(char), GFP_KERNEL);
			if ((*list)[0] == NULL) {
				kfree(str_learning);
				return;
			}

			strcpy((*list)[0], str_learning);
			*list_len = 1;
		}
		else {
			*list = krealloc(*list, (*list_len + 1) * sizeof(char *), GFP_KERNEL);
			if (*list == NULL) {
				kfree(str_learning);
				return;
			}

			(*list)[*list_len] = kzalloc(string_length * sizeof(char), GFP_KERNEL);
			if ((*list)[*list_len] == NULL) {

				// back liste + 1
				*list = krealloc(*list, *list_len * sizeof(char *), GFP_KERNEL);
				kfree(str_learning);
				return;
			}

			strcpy((*list)[*list_len], str_learning);
			*list_len += 1;
		}
	}

	kfree(str_learning);

	return;
}




/*--------------------------------------------------------------------------------*/
/* test */
/*direkter Zugriff auf Liste*/
/*
static void learning(	uid_t user_id,
			const char *filename,
			char const *hash_alg)
{

	char	str_user_id[19];
	char	str_file_size[19];
	char	*str_learning =  NULL;
	int	string_length = 0;
	struct	sum_hash_struct size_hash_sum;


	if (filename[0] != '/')
		return;

	//size_hash_sum = get_file_size_hash_read(filename);
	size_hash_sum = get_file_size_hash_read(filename);
	if (size_hash_sum.retval == false) return;

	sprintf(str_user_id, "%u", user_id);
	sprintf(str_file_size, "%ld", size_hash_sum.file_size);

	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen(size_hash_sum.hash_string);
	string_length += strlen("a:;;;") + 1;


	str_learning = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_learning) {
		return;
	}

	strcpy(str_learning, "a:");
	strcat(str_learning, str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, size_hash_sum.hash_string);
	strcat(str_learning, ";");
	strcat(str_learning, filename);


	if (search(str_learning, global_list_learning, global_list_learning_size) != 0) {

		/// init
		if (global_list_learning_size == 0) {
			global_list_learning = kzalloc(sizeof(char *), GFP_KERNEL);
			if (global_list_learning == NULL) {
				kfree(str_learning);
				return;
			}

			global_list_learning[0] = kzalloc(string_length * sizeof(char), GFP_KERNEL);
			if (global_list_learning[0] == NULL) {
				kfree(str_learning);
				return;
			}

			strcpy(global_list_learning[0], str_learning);
			global_list_learning_size = 1;
		}
		else {
			global_list_learning = krealloc(global_list_learning, (global_list_learning_size + 1) * sizeof(char *), GFP_KERNEL);
			if (global_list_learning == NULL) {
				kfree(str_learning);
				return;
			}

			global_list_learning[global_list_learning_size] = kzalloc(string_length * sizeof(char), GFP_KERNEL);
			if (global_list_learning[global_list_learning_size] == NULL) {

				// back liste + 1
				global_list_learning = krealloc(global_list_learning, global_list_learning_size * sizeof(char *), GFP_KERNEL);
				kfree(str_learning);
				return;
			}

			strcpy(global_list_learning[global_list_learning_size], str_learning);
			global_list_learning_size += 1;
		}
	}

	kfree(str_learning);
	return;
}

*/






/*--------------------------------------------------------------------------------*/
static void print_prog_arguments(struct struct_file_info *struct_file_info,
				char **argv,
				long argv_len)
{

	if (struct_file_info->retval == false) return;

	printk("USER ID:%s;%s;%s;%s\n",struct_file_info->str_user_id,
					struct_file_info->str_file_size,
					struct_file_info->hash_string,
					struct_file_info->fname);

	for (int n = 0; n < argv_len; n++) {
		/*
		size_hash_sum = get_file_size_hash_read(argv[n], hash_alg, digit);
		printk("argv[%d]:%ld:%s:%s\n", n, size_hash_sum.file_size, size_hash_sum.hash_string, argv[n]);
		*/
		printk("argv[%d]:%s\n", n, argv[n]);

	}

	return;
}


/*--------------------------------------------------------------------------------*/
static bool
user_wildcard_deny(struct struct_file_info *struct_file_info,
		char **list,
		long list_len,
		const char *step)

{

	if (list_len == 0) return true;

	/* user allowed */
	int string_length = strlen(struct_file_info->fname);
	string_length += strlen("d:*;") + 1;

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "d:*;");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG.  DENY   : a:%s;%s;%s;%s\n", step, 
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_user_file);
		return false;
	}

	kfree(str_user_file);
	return true;
}


/*--------------------------------------------------------------------------------*/
static bool
user_wildcard_allowed(struct struct_file_info *struct_file_info,
			char **list,
			long list_len,
			const char *step)
{

	if (list_len == 0) return false;


	/* user allowed */
	int string_length = strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen(struct_file_info->hash_string);

	/* i hope the compiler makes a constant ? */
	string_length += strlen("a:*;;;") + 1;

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "a:*;");
	strcat(str_user_file, struct_file_info->str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->hash_string);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_allowed == true)
			printk("%s USER/PROG.  ALLOWED: a:%s;%s;%s;%s\n", step, 
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_user_file);
		return true;
	}

	kfree(str_user_file);
	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
user_wildcard_folder_allowed(struct struct_file_info *struct_file_info,
				char **list,
				long list_len,
				const char *step)

{

	if (list_len == 0) return false;


	int string_length = strlen(struct_file_info->fname);
	string_length += strlen("a:*;") + 1;

	char *str_folder = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_folder)
		return false;

	strcpy(str_folder, "a:*;");
	strcat(str_folder, struct_file_info->fname);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == true) {
		if (printk_allowed == true)
			printk("%s USER/PROG.  ALLOWED: a:%s;%s;%s;%s\n", step,
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size,
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_folder);
		return true;
	}

	kfree(str_folder);
	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
user_wildcard_folder_deny(struct struct_file_info *struct_file_info,
			char **list,
			long list_len,
			const char *step)

{

	if (list_len == 0) return true;


	int string_length = strlen(struct_file_info->fname);
	string_length += strlen("d:*;") + 1;

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "d:*;");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_folder(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG.  DENY   : a:%s;%s;%s;%s\n", step,
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_user_file);
		return false;
	}

	kfree(str_user_file);
	return true;
}


/*--------------------------------------------------------------------------------*/
static bool
user_deny(struct struct_file_info *struct_file_info,
	char **list,
	long list_len,
	const char *step)

{

	if (list_len == 0) return true;



	char *str_user_file = NULL;



	/* user allowed */
	int string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen("d:;") + 1;

	str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "d:");
	strcat(str_user_file, struct_file_info->str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG.  DENY   : a:%s;%s;%s;%s\n", step,
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string,
									struct_file_info->fname);

		kfree(str_user_file);
		return false;
	}

	kfree(str_user_file);
	return true;
}


/*--------------------------------------------------------------------------------*/
static bool
group_deny(struct struct_file_info *struct_file_info,
	char **list,
	long list_len,
	const char *step)
{

	if (list_len == 0)
		return true;


	char	str_group_id[19];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();

	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(struct_file_info->fname);
		string_length += strlen("gd:;") +1;

		str_group_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_file)
			return false;

		strcpy(str_group_file, "gd:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->fname);

		if (besearch_file(str_group_file, list, list_len) == true) {
			if (printk_deny == true)
				printk("%s GROUP/PROG. DENY   : gd:%s;%s;%s;%s\n", step, 
										    str_group_id, 
										    struct_file_info->str_file_size, 
										    struct_file_info->hash_string, 
										    struct_file_info->fname);

			kfree(str_group_file);
			return false;
		}

		kfree(str_group_file);
		str_group_file = NULL;
	}

	return true;
}


/*--------------------------------------------------------------------------------*/
static bool
user_folder_deny(struct struct_file_info *struct_file_info,
		char **list,
		long list_len,
		const char *step)

{

	if (list_len == 0) return true;


	char *str_folder = NULL;
	int  string_length;

	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen("d:;") + 1;

	str_folder = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_folder)
		return false;

	strcpy(str_folder, "d:");
	strcat(str_folder, struct_file_info->str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, struct_file_info->fname);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG.  DENY   : a:%s;%s;%s;%s\n", step,
									struct_file_info->str_user_id,
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_folder);
		return false;
	}

	kfree(str_folder);
	return true;
}


/*--------------------------------------------------------------------------------*/
static bool
group_folder_deny(struct struct_file_info *struct_file_info,
		char **list,
		long list_len,
		const char *step)

{

	if (list_len == 0) return true;


	char	str_group_id[19];
	char	*str_group_folder = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();


	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(struct_file_info->fname);
		string_length += strlen("gd:;") + 1;

		//if (str_group_folder != NULL) kfree(str_group_folder);
		str_group_folder = kzalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_folder)
			return false;

		strcpy(str_group_folder, "gd:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, struct_file_info->fname);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == true) {
			if (printk_deny == true)
				printk("%s USER/PROG.  DENY   : gd:%s;%s;%s;%s\n", step,
										str_group_id, 
										struct_file_info->str_file_size, 
										struct_file_info->hash_string, 
										struct_file_info->fname);

			kfree(str_group_folder);
			return false;
		}

		kfree(str_group_folder);
		str_group_folder = NULL;
	}

	return true;
}


/*--------------------------------------------------------------------------------*/
static bool
user_allowed(	struct struct_file_info *struct_file_info,
		char **list,
		long list_len,
		const char *step)
{

	if (list_len == 0) return false;


	char *str_user_file = NULL;

	/* user allowed */
	int string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen(struct_file_info->hash_string);

	/* i hope the compiler makes a constant ? */
	string_length += strlen("a:;;;") + 1;

	str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file) return false;

	strcpy(str_user_file, "a:");
	strcat(str_user_file, struct_file_info->str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->hash_string);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_allowed == true)
			printk("%s USER/PROG.  ALLOWED: a:%s;%s;%s;%s\n", step,
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_user_file);
		return true;
	}

	kfree(str_user_file);
	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
group_allowed(struct struct_file_info *struct_file_info,
		char **list,
		long list_len,
		const char *step)

{


	if (list_len == 0) return false;

	char	str_group_id[19];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();



	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(struct_file_info->str_file_size);
		string_length += strlen(struct_file_info->fname);
		string_length += strlen(struct_file_info->hash_string);
		string_length += strlen("ga:;;;") +1;

		//if (str_group_file != NULL) kfree(str_group_file);
		str_group_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_file) return false;

		strcpy(str_group_file, "ga:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->hash_string);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->fname);

		if (besearch_file(str_group_file, list, list_len) == true) {
			if (printk_allowed == true)
				printk("%s GROUP/PROG. ALLOWED: ga:%s;%s;%s;%s\n", step, 
										str_group_id, 
										struct_file_info->str_file_size, 
										struct_file_info->hash_string, 
										struct_file_info->fname);

			kfree(str_group_file);
			return true;
		}

		kfree(str_group_file);
		str_group_file = NULL;
	}

	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
user_folder_allowed(struct struct_file_info *struct_file_info,
			char **list,
			long list_len,
			const char *step)

{

	if (list_len == 0) return false;


	char *str_folder = NULL;
	int  string_length;


	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen("a:;") + 1;

	str_folder = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_folder) return false;

	strcpy(str_folder, "a:");
	strcat(str_folder, struct_file_info->str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, struct_file_info->fname);
	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == true) {
		if (printk_allowed == true)
			printk("%s USER/PROG.  ALLOWED: a:%s;%s;%s;%s\n", step, 
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_folder);
		return true;
	}

	kfree(str_folder);

	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
group_folder_allowed(struct struct_file_info *struct_file_info,
			char **list,
			long list_len,
			const char *step)

{


	if (list_len == 0) return false;



	char	str_group_id[19];
	char	*str_group_folder = NULL;
	struct	group_info *group_info;
	int	string_length;


	group_info = get_current_groups();


	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(struct_file_info->fname);
		string_length += strlen("ga:;") + 1;

		//if (str_group_folder != NULL) kfree(str_group_folder);
		str_group_folder = kzalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_folder)
			return false;

		strcpy(str_group_folder, "ga:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, struct_file_info->fname);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == true) {
			if (printk_allowed == true)
				printk("%s USER/PROG.  ALLOWED: ga:%s;%s;%s;%s\n", step,
										str_group_id,
										struct_file_info->str_file_size,
										struct_file_info->hash_string,
										struct_file_info->fname);

			kfree(str_group_folder);
			return true;
		}

		kfree(str_group_folder);
		str_group_folder = NULL;

	}

	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
user_interpreter_allowed(struct struct_file_info *struct_file_info,
			char **list,
			long list_len,
			const char *step)

{

	char	*str_user_file = NULL;
	int	string_length;


	/* user allowed interpreter */
	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->hash_string);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen("ai:;;;") + 1;

	str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (str_user_file == NULL)
		return false;

	strcpy(str_user_file, "ai:");
	strcat(str_user_file, struct_file_info->str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->hash_string);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->fname);


	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_allowed == true)
			printk("%s USER/PROG.  ALLOWED: ai:%s;%s;%s;%s\n", step,
									struct_file_info->str_user_id, 
									struct_file_info->str_file_size, 
									struct_file_info->hash_string, 
									struct_file_info->fname);

		kfree(str_user_file);
		return true;
	}

	kfree(str_user_file);

	return false;
}


/*--------------------------------------------------------------------------------*/
static bool
group_interpreter_allowed(struct struct_file_info *struct_file_info,
			char **list,
			long list_len,
			const char *step)

{

	char	str_group_id[19];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();



	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);

		string_length = strlen(str_group_id);
		string_length += strlen(struct_file_info->str_file_size);
		string_length += strlen(struct_file_info->fname);
		string_length += strlen(struct_file_info->hash_string);
		string_length += strlen("gai:;;;") +1;

		//if (str_group_file != NULL) kfree(str_group_file);
		str_group_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_file)
			return false;

		strcpy(str_group_file, "gai:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->hash_string);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->fname);

		if (besearch_file(str_group_file, list, list_len) == true) {
			if (printk_allowed == true)
				printk("%s GROUP/PROG. ALLOWED: gai:%s;%s;%s;%s\n", step, 
										    str_group_id, 
										    struct_file_info->str_file_size, 
										    struct_file_info->hash_string, 
										    struct_file_info->fname);

			kfree(str_group_file);
			return true;
		}

		kfree(str_group_file);
		str_group_file = NULL;
	}


	return false;
}


/*--------------------------------------------------------------------------------*/
/* allowed/deny user/group script file*/
/* 0 allowed */
/* -1 deny */
static bool
param_file(struct struct_file_info *struct_file_info,
		char **argv,
		long argv_len,
		char **list,
		long list_len,
		const char *step)

{


	if (argv_len == 1) return false;


	/* check interpreter and files */
	/* user allowed interpreter */
	/* check "ai:  gai:"  */
	if (user_interpreter_allowed(struct_file_info,
					list,
					list_len,
					step) == false)
		if (group_interpreter_allowed(struct_file_info,
						list,
						list_len,
						step) == false)
			return false;


	struct struct_file_info struct_param_info;

	/* java */
	if (strcmp(argv[1], "-jar") == 0) {
		if (argv_len != 3) return false;

		struct_param_info = get_file_info(argv[2]);
		if (struct_param_info.retval == false) {
			if (printk_deny == true)
				printk("STAT STEP FIRST: USER/PROG.  UNKNOWN : a:%d;;;%s\n", struct_param_info.user_id,
											     argv[2]);
			return false;
		}

		/* check file/prog is in the list: allowed or deny */
		/* deny user not required. not in the list is the same */
		if (user_deny(&struct_param_info,
				list,
				list_len,
				step) == false) return false;

		if (group_deny(&struct_param_info,
				list,
				list_len,
				step) == false) return false;

		if (user_allowed(&struct_param_info,
				list,
				list_len,
				step) == true) return true;

		if (group_allowed(&struct_param_info,
				list,
				list_len,
				step) == true) return true;

		if (printk_deny == true)
			printk("%s USER/SCRIPT DENY   : a:%s;%s;%s;%s\n", step,
									struct_param_info.str_user_id,
									struct_param_info.str_file_size,
									struct_param_info.hash_string,
									struct_param_info.fname);

		return false;

	}


	/* java */
	if (strcmp(argv[1], "-classpath") == 0) {
		if (argv_len != 4) return false;

		long str_length;
		str_length = strlen(argv[2]);
		str_length += strlen(argv[3]);
		str_length += strlen("/.class") + 1;

		char *str_class_name = kzalloc(str_length * sizeof(char), GFP_KERNEL);
		if (str_class_name == NULL) return false;

		strcpy(str_class_name, argv[2]);
		strcat(str_class_name, "/");
		strcat(str_class_name, argv[3]);
		strcat(str_class_name, ".class");

		struct_param_info = get_file_info(str_class_name);
		if (struct_param_info.retval == false) {
			if (printk_deny == true)
				printk("STAT STEP FIRST: USER/PROG.  UNKNOWN : a:%s;;;%s\n",struct_param_info.str_user_id,
											    struct_param_info.fname);

			kfree(str_class_name);
			return false;
		}

		/* check file/prog is in the list: allowed or deny */
		/* deny user not required. not in the list is the same */
		if (user_deny(&struct_param_info,
				list,
				list_len,
				step) == false) {

			kfree(str_class_name);
			return false;
		}

		if (group_deny(&struct_param_info,
				list,
				list_len,
				step) == false) {

			kfree(str_class_name);
			return false;
		}

		if (user_allowed(&struct_param_info,
				list,
				list_len,
				step) == true) {

			kfree(str_class_name);
			return true;
		}

		if (group_allowed(&struct_param_info,
				list,
				list_len,
				step) == true) {

			kfree(str_class_name);
			return true;
		}

		if (printk_deny == true)
			printk("%s USER/SCRIPT DENY   : d:%s;%s;%s;%s\n", step,
									struct_param_info.str_user_id,
									struct_param_info.str_file_size,
									struct_param_info.hash_string,
									struct_param_info.fname);

		kfree(str_class_name);

		return false;
	}


	/* other */
	struct struct_file_info struct_other_file_info = get_file_info(argv[1]);
	if (struct_other_file_info.retval == false)
		return false;


	/* check file/prog is in the list: allowed or deny */
	/* deny user not required. not in the list is the same */
	if (user_deny(&struct_other_file_info,
			list,
			list_len,
			step) == false) return false;

	if (group_deny(&struct_other_file_info,
			list,
			list_len,
			step) == false) return false;

	if (user_allowed(&struct_other_file_info,
			list,
			list_len,
			step) == true) return true;

	if (group_allowed(&struct_other_file_info,
			list,
			list_len,
			step) == true) return true;

	if (printk_deny == true)
		printk("%s USER/SCRIPT DENY   : d:%s;%s;%s;%s\n", step,
								struct_other_file_info.str_user_id,
								struct_other_file_info.str_file_size,
								struct_other_file_info.hash_string,
								struct_other_file_info.fname);

	/* not found */
	return false;
}




/*--------------------------------------------------------------------------------*/
static bool exec_first_step(struct struct_file_info *struct_file_info,
			    char **argv,
			    long argv_len)
{

	if (struct_file_info->retval == false) {
		if ((printk_allowed == true) || (printk_deny == true)) {
			printk("STAT STEP FIRST: USER/PROG.  UNKNOWN : a:%s;;;%s\n", struct_file_info->str_user_id,
										      struct_file_info->fname);
		}

		return true;
	}

	/* deny wildcard folder */
	if (user_wildcard_folder_deny(	struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"STAT STEP FIRST:") == false)
		return false;


/* wildcard deny user */
	if (user_wildcard_deny(	struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"STAT STEP FIRST:") == false)
		return false;

	/* group deny folder */
	if (group_folder_deny(	struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP FIRST:") == false)
		return false;

	/* deny group */
	/* if global_list_prog_size = 0, safer_mode not true */
	if (group_deny(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP FIRST:") == false)
		return false;

	/* deny folder */
	if (user_folder_deny(struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP FIRST:") == false)
		return false;

	/* deny user */
	if (user_deny(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP FIRST:") == false)
		return false;

/*--------------------------------------------------------------------------------*/

	/* user wildcard allowed folder */
	if (user_wildcard_folder_allowed(struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"STAT STEP FIRST:") == true)
		return true;

	/* all wildcard user */
	if (user_wildcard_allowed(struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"STAT STEP FIRST:") == true)
		return true;

	/* group allowed folder */
	if (group_folder_allowed(struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP FIRST:") == true)
		return true;

	/* allowed group */
	if (group_allowed(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP FIRST:") == true)
		return true;

	/* user allowed folder */
	if (user_folder_allowed(struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP FIRST:") == true)
		return true;

	/* allowed user */
	if (user_allowed(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP FIRST:") == true)
		return true;

	/* user allowed interpreter and allowed group script file*/
	/* 0 allowed */
	/* -1 deny */
	if (param_file(struct_file_info,
			argv,
			argv_len,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP FIRST:") == true)
		return true;

	if (printk_deny == true)
		printk("STAT STEP FIRST: USER/PROG.  DENY   : a:%s;%s;%s;%s\n", struct_file_info->str_user_id,
										struct_file_info->str_file_size,
										struct_file_info->hash_string,
										struct_file_info->fname);

	return false;

}


/*--------------------------------------------------------------------------------*/
static bool exec_second_step(const char *filename)
{

	bool retval;

	/* if size = 0 not check */
	/* if path not correct not check */
	struct struct_file_info struct_file_info = get_file_info(filename);
	if (struct_file_info.retval == false) {
		if ((printk_allowed == true) || (printk_deny == true)) {
			printk("STAT STEP SEC  : USER/PROG.  UNKNOWN : a:%s;;;%s\n",   struct_file_info.str_user_id, 
											struct_file_info.fname);
		}
		return true;
	}


	if (learning_mode == true) {

		/* works too */
		if (mutex_trylock(&learning_lock)) {

			learning(&struct_file_info,
				&global_list_learning,
				&global_list_learning_size);

			mutex_unlock(&learning_lock);
		}
	}


	if (safer_mode == false) return true;




/*-------------------------------------------------------------------------------------------*/
	/* deny wildcard folder */
	retval = user_wildcard_folder_deny(&struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"STAT STEP FIRST:");
	if (retval == false) return false;

/*-------------------------------------------------------------------------------------------*/

	/* deny wildcard user */
	retval = user_wildcard_deny(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"STAT STEP SEC  :");
	if (retval == false) return false;

/*-------------------------------------------------------------------------------------------*/

	/* group deny folder */
	retval = group_folder_deny(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :");
	if (retval == false) return false;

/*-------------------------------------------------------------------------------------------*/

	/* deny group */
	/* if global_list_prog_size = 0, safer_mode not true */
	retval = group_deny(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :");
	if (retval == false) return false;

/*-------------------------------------------------------------------------------------------*/

	/* deny folder */
	retval = user_folder_deny(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :");
	if (retval == false) return false;

/*-------------------------------------------------------------------------------------------*/

	/* deny user */
	retval = user_deny(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :");
	if (retval == false) return false;

/*-------------------------------------------------------------------------------------------*/

	/* allowed wildcard folder */
	if (user_wildcard_folder_allowed(&struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"STAT STEP SEC  :") == true)
		return true;

	/* allowed wildcard user */
	if (user_wildcard_allowed(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"STAT STEP SEC  :") == true)
		return true;

	/* group allowed folder */
	if (group_folder_allowed(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :") == true)
		return true;

	/* allowed group */
	if (group_allowed(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :") == true)
		return true;

	/* allowed user folder */
	if (user_folder_allowed(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :") == true)
		return true;

	/* allowed user */
	if (user_allowed(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :") == true)
		return true;

	/* group allowed interpreter */
	if (group_interpreter_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"STAT STEP SEC  :") == true)
		return true;

	/* user allowed interpreter */
	if (user_interpreter_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"STAT STEP SEC  :") == true)
		return true;

	if (printk_deny == true) {
		printk("STAT STEP SEC  : USER/PROG.  DENY   : a:%s;%s;%s;%s\n", struct_file_info.str_user_id,
										struct_file_info.str_file_size,
										struct_file_info.hash_string,
										struct_file_info.fname);
	}

	/* filter end */
	return false;
}





/*--------------------------------------------------------------------------------*/
static bool allowed_exec(const char *filename,
			struct user_arg_ptr argv)
{

	const char __user	*str;
	char			**argv_list = NULL;
	long			argv_list_len = 0;
	long			str_len;
	bool			retval;


	argv_list_len = count(argv, MAX_ARG_STRINGS);

	if ((printk_allowed == true) || (printk_deny == true)) {
		for (int n = 0; n < argv_list_len; n++) {
			str = get_user_arg_ptr(argv, n);
			str_len = strnlen_user(str, MAX_ARG_STRLEN);
			if (str_len > 5000) {
				printk("STAT STEP FIRST: NOTICE: PROG.: %s, ARGV:[%d], LENGTH:[%ld] > 5000\n",
													filename,
													n,
													str_len);
			}
		}
	}

	/* argv -> kernel space */
	/* NOT ALL argv */
	if (argv_list_len > ARGV_MAX) argv_list_len = ARGV_MAX;


	/* Init List */
	argv_list = kzalloc(argv_list_len * sizeof(char *), GFP_KERNEL);
	if (!argv_list) {
		return false;
	}

	for (int n = 0; n < argv_list_len; n++) {
		/*Address User String */
		str = get_user_arg_ptr(argv, n);
		str_len = strnlen_user(str, MAX_ARG_STRLEN);

		argv_list[n] = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
		/* abbau bei error */
		if (!argv_list[n]) {
			for (int n_ = 0; n_ < n; n_++) {
				kfree(argv_list[n_]);
			}
			kfree(argv_list);
			return false;
		}

		retval = copy_from_user(argv_list[n], str, str_len);
	}



	struct struct_file_info struct_file_info = get_file_info(filename);


	if (verbose_param_mode == true)
		print_prog_arguments(	&struct_file_info,
					argv_list,
					argv_list_len);


	if (learning_mode == true) {

		/* works too */
		mutex_lock(&learning_lock);

		learning(&struct_file_info,
			&global_list_learning,
			&global_list_learning_size);

		learning_argv(	&struct_file_info,
				argv_list,
				argv_list_len,
				&global_list_learning_argv,
				&global_list_learning_argv_size,
				&global_list_learning_argv_init);

		mutex_unlock(&learning_lock);

	}


	if (safer_mode == true) {
		retval = exec_first_step(&struct_file_info,
					argv_list,
					argv_list_len);
	}
	else retval = true;


	/* Free all Elements in argv_list */
	for (int n = 0; n < argv_list_len; n++) {
		kfree(argv_list[n]);
	}

	kfree(argv_list);

	return retval;


}



/*--------------------------------------------------------------------------------*/
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



	/* command part, future ? */
	switch(number) {

		/* safer on */
		case 999900:	user_id = get_current_user()->uid.val;
				if (user_id != 0) return CONTROL_ERROR;
				if (change_mode == false) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;

				if (global_list_prog_size > 0 || global_list_folder_size > 0) {
					safer_mode = true;
					printk("MODE: SAFER ON\n");
					mutex_unlock(&control);
					return CONRTOL_OK;
				}
				else {
					printk("MODE: SAFER OFF\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


		/* safer off */
		case 999901:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER OFF\n");
				safer_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* stat */
		case 999902:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				printk("SAFER STATE         : %d\n", safer_mode);
				return(safer_mode);


		/* printk allowed on */
		case 999903:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK ALLOWED ON\n");
				printk_allowed = true;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* printk allowed off */
		case 999904:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK ALLOWED OFF\n");
				printk_allowed = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999905:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: NO MORE CHANGES ALLOWED\n");
				change_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999906:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: learning ON\n");
				learning_mode = true;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999907:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: learning OFF\n");
				learning_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999908:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: verbose paramter mode ON\n");
				verbose_param_mode = true;
				mutex_unlock(&control);
				return CONRTOL_OK;



		case 999909:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: verbose parameter mode OFF\n");
				verbose_param_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* printk deny ON */
		case 999912:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK DENY ON\n");
				printk_deny = true;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* printk deny OFF */
		case 999913:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK DENY OFF\n");
				printk_deny = false;
				mutex_unlock(&control);
				return CONRTOL_OK;



		/* set all list */
		case 999920:
				user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;


				if (list == NULL) {		/* check? */
					printk("ERROR: FILE LIST\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				} /* check!? */

				int int_ret = count(_list, MAX_ARG_STRINGS);
				if (int_ret == 0) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				str = get_user_arg_ptr(_list, 0);		/* String 0 */
				str_len = strnlen_user(str, MAX_ARG_STRLEN);
				if (str_len < 1) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* safer */
				if (list_string != NULL) { kfree(list_string); list_string = NULL; }

				list_string = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				int_ret = copy_from_user(list_string, str, str_len);

				long list_prog_size;
				int_ret = kstrtol(list_string, 10, &list_prog_size);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; }
				if (int_ret != 0) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* new list 0 ? */
				if (list_prog_size < 1) {
					printk("NO FILE LIST\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* new list > MAX_DYN */
				if (list_prog_size > MAX_DYN) {
					printk("FILE LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/* check bytes */
				/* new list */
				long list_progs_bytes = 0;
				for (int n = 0; n < list_prog_size; n++) {
					str = get_user_arg_ptr(_list, n + 1);
					list_progs_bytes += strnlen_user(str, MAX_ARG_STRLEN);
				}

				if (list_progs_bytes > MAX_DYN_BYTES) {
					printk("FILE LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/*
				first: new list
				if new list ok. clear old list.
				if new list not ok clear new list
				keep old list
				*/

				char **list_prog_temp = NULL;

				/* dyn list */
				list_prog_temp = kzalloc(list_prog_size * sizeof(char *), GFP_KERNEL);
				/* Create a new not ok */
				if (list_prog_temp == NULL) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				for (int n = 0; n < list_prog_size; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					list_prog_temp[n] = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					/* Create a new list not ok */
					if (list_prog_temp[n] == NULL) {
						for (int n_error = 0; n_error < n; n_error++) {
							kfree(list_prog_temp[n_error]);
							list_prog_temp[n_error] = NULL;
						}

						kfree(list_prog_temp);
						list_prog_temp = NULL;
						mutex_unlock(&control);
						return CONTROL_ERROR;
					}

					int_ret = copy_from_user(list_prog_temp[n], str, str_len);
				}


				/* clear */
				/* old list */
				if (global_list_prog_size > 0) {
					for (int n = 0; n < global_list_prog_size; n++) {
						kfree(global_list_prog[n]);
						global_list_prog[n] = NULL;
					}
					kfree(global_list_prog);
				}

				/* global = new */
				global_list_prog = list_prog_temp;
				list_prog_temp = NULL;
				global_list_prog_size = list_prog_size;
				global_list_progs_bytes = list_progs_bytes;

				printk("FILE LIST ELEMENTS: %ld\n", global_list_prog_size);
				printk("FILE LIST BYTES   : %ld\n", global_list_progs_bytes);


				mutex_unlock(&control);
				return(global_list_prog_size);


		/* set all folder list */
		case 999921:	user_id = get_current_user()->uid.val;
				if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;


				if (list == NULL) {		/* check? */
					printk("ERROR: FOLDER LIST\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				} /* check!? */


				/* No Syscall Parameter 6 necessary */
				int_ret = count(_list, MAX_ARG_STRINGS);
				if (int_ret == 0) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				str = get_user_arg_ptr(_list, 0);		/* String 0 */
				str_len = strnlen_user(str, MAX_ARG_STRLEN);
				if (str_len < 1) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* safer */
				if (list_string != NULL) { kfree(list_string); list_string = NULL; }

				list_string = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				int_ret = copy_from_user(list_string, str, str_len);

				long list_folder_size;
				int_ret = kstrtol(list_string, 10, &list_folder_size);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; };
				if (int_ret != 0) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/* new list = 0 ? */
				if (list_folder_size < 1) {
					printk("NO FOLDER LIST\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* new list > MAX_DYN */
				if (list_folder_size > MAX_DYN) {
					printk("FOLDER LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/* check bytes */
				/* new list */
				long list_folders_bytes = 0;
				for (int n = 0; n < list_folder_size; n++) {
					str = get_user_arg_ptr(_list, n + 1);
					list_folders_bytes += strnlen_user(str, MAX_ARG_STRLEN);
				}

				if (list_folders_bytes > MAX_DYN_BYTES) {
					printk("FOLDER LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/*
				first: new list
				if new list ok. clear old list.
				if new list not ok clear new list
				keep old list
				*/

				char **list_folder_temp = NULL;

				/* dyn array */
				list_folder_temp = kzalloc(list_folder_size * sizeof(char *), GFP_KERNEL);
				/* Create a new list not ok */
				if (list_folder_temp == NULL) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				for (int n = 0; n < list_folder_size; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					list_folder_temp[n] = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					/* Create a new list not ok*/
					if (list_folder_temp[n] == NULL) {
						for (int n_error = 0; n_error < n; n_error++) {
							kfree(list_folder_temp[n_error]);
							list_folder_temp[n_error] = NULL;
						}

						kfree(list_folder_temp);
						list_folder_temp = NULL;
						mutex_unlock(&control);
						return CONTROL_ERROR;
					}

					int_ret = copy_from_user(list_folder_temp[n], str, str_len);
				}

				/* clear */
				/* old list */
				if (global_list_folder_size > 0) {
					for (int n = 0; n < global_list_folder_size; n++) {
						kfree(global_list_folder[n]);
						global_list_folder[n] = NULL;
					}
					kfree(global_list_folder);
				}

				/* global = new */
				global_list_folder = list_folder_temp;
				list_folder_temp = NULL;
				global_list_folder_size = list_folder_size;
				global_list_folders_bytes = list_folders_bytes;

				printk("FILE LIST ELEMENTS: %ld\n", global_list_folder_size);
				printk("FILE LIST BYTES   : %ld\n", global_list_folders_bytes);


				mutex_unlock(&control);
				return(global_list_folder_size);


		default:	break;
	}

	return do_execve(getname(filename), argv, envp);

}
