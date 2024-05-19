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
	Date		: 2022.04.22 - 2024.05.16

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 6.9.0
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

	Standard	: Safer Mode = ON
			: Log Mode = Logs all programs from init
			  But only once

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

			: 999910 = safer show only ON
			: 999911 = safer show only OFF


			: 999920 = Set FILE List
			: 999921 = Set FOLDER List

			: 999912 = Log ON, deny
			: 999913 = Log OFF, deny


	Important	: ./foo is not a good idea
			  its works with SHA256 or other, but you don't know where the program file is in the PATH
			  all programs with this relative PATH and same HASH are allowed

			: see "make bzImage" etc.

	Example		:
			 a:1000;1234;HASH;./scripts/setlocalversion
			 a:1000;1234;HASH;arch/x86/tools/relocs


	FILE/FOLDER List: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

	PROG/FILE	:
			: DENY is not absolutely necessary
			  But maybe faster

			: a: allowed
			: d: deny

			: ga: group allowed
			: da: group deny

			: ai: interpreter or other
			      interpreter = arg/param/file only
			      First allowed Interpreter
			      Second allow Interpreter File


		FOLDER
			: a:  Folder allowed
			: d:  Folder deny

			: ga: group folder allowed
			: gd: group folder deny


		Example
			: string = USER-ID;FILE-SIZE;HASH;PATH
			: string = GROUP-ID;FILE-SIZE;HASH;PATH
			: string = File Size

			: string = allow:USER-ID;FILE-SIZE;HASH;PATH
			: string = deny:GROUP-ID;PATH

			: a:USER-ID;1234;HASH;Path
			: d:USER-ID;1234;HASH;Path

			: ga:GROUP-ID;1234;HASH;Path
			: gd:GROUP-ID;1234;HASH;Path

			: ai:USER-ID;1234;HASH;PATH

			: Example: user
			: a:100;1224;HASH;/bin/test		= allow file
			: a:100;1234;HASH;/bin/test1		= allow file
			: a:100;/usr/sbin/			= allow Folder

			: Example: user
			: d:100;1234;HASH;/usr/sbin/test	= deny file
			: d:100;/usr/sbin/			= deny folder

			: Example: Group
			: ga:100;HASH;/usr/sbin/		= allow group folder
			: gd:100;HASH;/usr/bin/			= deny group folder
			: gd:101;HASH;/usr/bin/mc		= deny group file
			: ga:101;HASH;/usr/bin/mc		= allow group file

			: Example: User
			: user

	Interpreter or other
			: Interpreter <USER> ONLY. INTERPTETER FILE <USER> <GROUP> allowed

			: ai:1000;12342;HASH;/usr/bin/python = allow INTERPRETER
			: a:1000;123422;HASH;/usr/bin/hello.py = allow INTERPRETER FILE
			: ga:1000;123422;HASH;/usr/bin/hello.py = allow INTERPRETER FILE

			  - Interpreter not allowed
			  - Interpreter + Interpreter File allowed
			  - Interpreter File allowed

			  python = allone = not allowed
			  python hello.py = allowed  is python allawed and hello.py is allowed
			  hello.py = allowed  is python allowed and hello.py allowed


			: Important:
			: java is supported
			: -jar			java -jar <PATH>/file.jar
			: -classpath		java -classpath <PATH> <NAME>


			: This is also possible
			: ai:0;1234;HASH;/sbin/insmod
			: a:0;1234;HASH;/lib/modules/KERNEL-VERSION/../modulx.ko


			: It is up to the ADMIN to keep the list reasonable according to these rules!



	Install
			: copy safer.c -> fs/
			  copy safer_info.c -> /fs
			  copy safer_learning.c -> /fs

			  look for changes in "#define add_safer" in EXAMPLE "fs:exec.c" and write in your current "exec.c"

			  write in fs/Makefile
			  obj-y	+= safer_info.o
			  obj-y	+= safer_learning.o

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

			  Another option: Include the list in the kernel


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

/*your choice */
#define MAX_DYN 100000
#define MAX_DYN_BYTES MAX_DYN * 200
#define ARGV_MAX 16
#define LEARNING_ARGV_MAX 5000
#define KERNEL_READ_SIZE 2000000




#define RET_SHELL -2
#define ALLOWED 0
#define NOT_ALLOWED -1
#define CONTROL_ERROR -1
#define CONRTOL_OK 0
#define ERROR -1
#define NOT_IN_LIST -1
#define NO_SECURITY_GUARANTEED "SAFER: Could not allocate buffer! Security is no longer guaranteed!\n"


/*--------------------------------------------------------------------------------*/
static DEFINE_MUTEX(learning_lock);
static DEFINE_MUTEX(control);


static bool	safer_show_mode = false;
static bool	safer_mode = false;

static bool	printk_allowed = false;
static bool	printk_deny = false;
static bool	learning_mode = true;
static bool	change_mode = true;	/*true = change_mode allowed */
static bool	verbose_param_mode = false;

static char	**global_list_prog = NULL;
static long	global_list_prog_len = 0;

static char	**global_list_learning = NULL;
static long	global_list_learning_len = 0;

static char	**global_list_learning_argv = NULL;
static long	global_list_learning_argv_len = 0;
static bool	global_list_learning_argv_init = false;

static char	**global_list_folder = NULL;
static long	global_list_folder_len = 0;

static long	global_list_progs_bytes = 0;
static long	global_list_folders_bytes = 0;




/*--------------------------------------------------------------------------------*/
/* proto. */
struct sum_hash_struct {
	int	retval;
	char	hash_string[DIGIT * 2 + 1];
	ssize_t	file_size;
};


/*--------------------------------------------------------------------------------*/
/* proto. */
struct  safer_info_struct {
	bool safer_show_mode;
	bool safer_mode;
	bool printk_allowed;
	bool printk_deny;
	bool learning_mode;
	bool change_mode;
	long global_list_prog_len;
	long global_list_folder_len;
	char **global_list_prog;
	char **global_list_folder;
	long global_hash_size;
	long global_list_progs_bytes;
	long global_list_folders_bytes;
};


/* proto. */
struct  safer_learning_struct {
	long global_list_learning_len;
	char **global_list_learning;
	long global_list_learning_argv_max;
	long global_list_learning_argv_len;
	char **global_list_learning_argv;
};


/* Makes compiler happy */
void safer_info(struct safer_info_struct *info);
void safer_learning(struct safer_learning_struct *learning);


/* DATA: Only over function */
void safer_info(struct safer_info_struct *info)
{
	info->safer_show_mode =safer_show_mode;
	info->safer_mode = safer_mode;
	info->printk_allowed = printk_allowed;
	info->printk_deny = printk_deny;
	info->learning_mode = learning_mode;
	info->change_mode = change_mode;
	info->global_list_prog_len = global_list_prog_len;
	info->global_list_folder_len = global_list_folder_len;
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
	learning->global_list_learning_len = global_list_learning_len;
	learning->global_list_learning = global_list_learning;
	learning->global_list_learning_argv_max = LEARNING_ARGV_MAX;
	learning->global_list_learning_argv_len = global_list_learning_argv_len;
	learning->global_list_learning_argv = global_list_learning_argv;
	return;
}



/*--------------------------------------------------------------------------------*/
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

		if (int_ret == 0) return 0;
		else if (int_ret < 0) left = middle + 1;
		else if (int_ret > 0) right = middle - 1;
	}

	return NOT_IN_LIST;
}





static int besearch_folder(	char *str_search,
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

		if (int_ret == 0) return 0;
		else if (int_ret < 0) left = middle + 1;
		else if (int_ret > 0) right = middle - 1;
	}

	return NOT_IN_LIST;
}




static long search(char *str_search,
		char **list,
		long elements)
{
	long n;

	for (n = 0; n < elements; n++) {
		if (strncmp(list[n], str_search, strlen(list[n])) == 0) return 0;
	}

	return NOT_IN_LIST;
}



/*--------------------------------------------------------------------------------*/
static struct sum_hash_struct get_hash_sum_buffer(char buffer[], int max, const char *hash_alg, int digit)
{

	char			hash_out[64];
	struct crypto_shash	*hash;
	struct shash_desc	*shash;
	struct sum_hash_struct	hash_sum;

	char			hash_[2];


	hash = crypto_alloc_shash(hash_alg, 0, 0);
	if (IS_ERR(hash)) {
		hash_sum.retval = ERROR;
		return hash_sum;
	}

	shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash), GFP_KERNEL);
	if (!shash) {
		hash_sum.retval = ERROR;
		return hash_sum;
	}

	shash->tfm = hash;


	if (crypto_shash_init(shash)) {
		hash_sum.retval = ERROR;
		return hash_sum;
	}



	if (crypto_shash_update(shash, buffer, max)) {
		hash_sum.retval = ERROR;
		return hash_sum;
	}

	if (crypto_shash_final(shash, hash_out)) {
		hash_sum.retval = ERROR;
		return hash_sum;
	}

	kfree(shash);
	crypto_free_shash(hash);


	for (int n = 0; n < digit; n++) {
		sprintf(hash_, "%02x", (unsigned char) hash_out[n]);
		hash_sum.hash_string[n * 2] = hash_[0];
		hash_sum.hash_string[(n * 2) + 1] = hash_[1];
	}

	hash_sum.hash_string[digit * 2] = '\0';
	hash_sum.retval = 0;

	return hash_sum;
}






static struct sum_hash_struct get_file_size_hash_read(const char *filename, const char *hash_alg, int digit)
{
	ssize_t				retval;
	ssize_t				file_size;
	void				*data = NULL;
	struct sum_hash_struct		size_hash_sum;
	int				max = KERNEL_READ_SIZE;


	retval = kernel_read_file_from_path(	filename,
						0,
						&data,
						KERNEL_READ_SIZE,
						&file_size,
						READING_POLICY);

	if (retval < 1) {
		size_hash_sum.file_size = 0;
		size_hash_sum.hash_string[0] = '\0';
		size_hash_sum.retval = ERROR;
		return size_hash_sum;
	}

	if (file_size < 1) {
		vfree(data);
		size_hash_sum.file_size = 0;
		size_hash_sum.hash_string[0] = '\0';
		size_hash_sum.retval = ERROR;
		return size_hash_sum;
	}

	if (file_size < max) max = file_size;

	char *buffer = data;

	size_hash_sum = get_hash_sum_buffer(buffer, max, hash_alg, digit);

	if (size_hash_sum.retval == 0) {
		vfree(data);
		size_hash_sum.file_size = file_size;
		return size_hash_sum;
	}

	vfree(data);
	size_hash_sum.retval = -1;
	size_hash_sum.file_size = 0;
	size_hash_sum.hash_string[0] = '\0';

	return size_hash_sum;
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
static void learning_argv(uid_t user_id,
			const char *filename,
			char **argv,
			long argv_len,
			char ***list,
			long *list_len,
			bool *list_init)

{

	char	str_user_id[19];
	char	str_file_size[19];

	ssize_t	file_size;

	char	*str_learning =  NULL;
	int	string_length = 0;


	if (argv_len == 1)
		return;

	file_size = get_file_size(filename);
	/* file not exist or empty */
	if (file_size < 1)
		return;


	/* init list */
	if (*list_init == false) {
		*list = kzalloc(sizeof(char *) * LEARNING_ARGV_MAX, GFP_KERNEL);
		if (*list == NULL) {
			return;
		}
		else *list_init = true;
	}


	sprintf(str_user_id, "%u", user_id);
	sprintf(str_file_size, "%ld", file_size);

	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen("a:;;;") + 1;

	//if (argv_len > 10) argv_len = 10;
	for (int n = 1; n < argv_len; n++) {
		string_length += strlen(argv[n]);
		string_length += 1;
	}

	str_learning = kzalloc(string_length * sizeof(char), GFP_KERNEL);

	strcpy(str_learning, "a:");
	strcat(str_learning, str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, filename);
	strcat(str_learning, ";");

	for (int n = 1; n < argv_len; n++) {
		strcat(str_learning, argv[n]);
		strcat(str_learning, ";");
	}


	if (search(str_learning, *list, *list_len) != 0) {

		if ((*list)[*list_len] != NULL)
			kfree((*list)[*list_len]);

		(*list)[*list_len] = kzalloc(string_length * sizeof(char), GFP_KERNEL);
			if ((*list)[*list_len] == NULL) {
				kfree(str_learning);
				return;
			}

		strcpy((*list)[*list_len], str_learning);

		*list_len += 1;
		/* check argv_len > lerning_argv_max */
		if (*list_len > LEARNING_ARGV_MAX - 1)
			*list_len = 0;

	}

	kfree(str_learning);
	return;
}










static void learning(	uid_t user_id,
			const char *filename,
			char ***list,
			long *list_len,
			char const *hash_alg,
			int digit)
{

	char	str_user_id[19];
	char	str_file_size[19];
	char	*str_learning =  NULL;
	int	string_length = 0;

	struct sum_hash_struct size_hash_sum;


	if (filename[0] != '/')
		return;

	//size_hash_sum = get_file_size_hash_read(filename);
	size_hash_sum = get_file_size_hash_read(filename, hash_alg, digit);

	if (size_hash_sum.retval == -1)
		return;

	sprintf(str_user_id, "%u", user_id);
	sprintf(str_file_size, "%ld", size_hash_sum.file_size);

	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen(size_hash_sum.hash_string);
	string_length += strlen("a:;;;") + 1;

	str_learning = kzalloc(string_length * sizeof(char), GFP_KERNEL);

	strcpy(str_learning, "a:");
	strcat(str_learning, str_user_id);
	strcat(str_learning, ";");
	strcat(str_learning, str_file_size);
	strcat(str_learning, ";");
	strcat(str_learning, size_hash_sum.hash_string);
	strcat(str_learning, ";");
	strcat(str_learning, filename);


	if (search(str_learning, *list, *list_len) != 0) {

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
static void print_prog_arguments(uid_t user_id,
				const char *filename,
				char **argv,
				long argv_len,
				const char *hash_alg,
				int digit)
{


	struct sum_hash_struct size_hash_sum;

	size_hash_sum = get_file_size_hash_read(filename, hash_alg, digit);
	if (size_hash_sum.retval == -1)
		return;


	printk("USER ID:%u;%ld;%s;%s\n",user_id,
					size_hash_sum.file_size,
					size_hash_sum.hash_string,
					filename);

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
static int
user_allowed(	uid_t user_id,
		const char *filename,
		ssize_t file_size,
		char hash[],
		char **list,
		long list_len,
		const char *step)
{

	char str_user_id[19];
	char str_file_size[19];
	char *str_user_file = NULL;

	sprintf(str_user_id, "%u", user_id); 
	sprintf(str_file_size, "%ld", file_size); 

	/* user allowed */
	int string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen(hash);

	/* i hope the compiler makes a constant ? */
	string_length += strlen("a:;;;") + 1;

	str_user_file = kmalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return NOT_ALLOWED;

	strcpy(str_user_file, "a:");
	strcat(str_user_file, str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, hash);
	strcat(str_user_file, ";");
	strcat(str_user_file, filename);

	if (besearch_file(str_user_file, list, list_len) == 0) {
		if (printk_allowed == true)
			printk("%s USER/PROG. ALLOWED: a:%s;%s;%s;%s\n", step, str_user_id, str_file_size, hash, filename);
		kfree(str_user_file);
		str_user_file = NULL;
		return ALLOWED;
	}

	kfree(str_user_file);
	str_user_file = NULL;
	return NOT_ALLOWED;
}


/*--------------------------------------------------------------------------------*/
static int
user_deny(uid_t user_id,
	const char *filename,
	ssize_t file_size,
	char hash[],
	char **list,
	long list_len,
	const char *step)

{

	char str_user_id[19];
	char str_file_size[19];
	char *str_user_file = NULL;


	sprintf(str_user_id, "%d", user_id); 
	sprintf(str_file_size, "%ld", file_size); 

	/* user allowed */
	int string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(filename);
	string_length += strlen(hash);
	string_length += strlen("d:;;;") + 1;

	str_user_file = kmalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return NOT_ALLOWED;

	strcpy(str_user_file, "d:");
	strcat(str_user_file, str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, hash);
	strcat(str_user_file, ";");
	strcat(str_user_file, filename);

	if (besearch_file(str_user_file, list, list_len) == 0) {
		if (printk_deny == true)
			printk("%s USER/PROG. DENY   : a:%s;%s;%s;%s\n", step, str_user_id, str_file_size, hash, filename);

		kfree(str_user_file);
		return NOT_ALLOWED;
	}

	kfree(str_user_file);
	return ALLOWED;
}


/*--------------------------------------------------------------------------------*/
static int
group_allowed(uid_t user_id,
		const char *filename,
		ssize_t file_size,
		char hash[],
		char **list,
		long list_len,
		const char *step)

{

	char	str_user_id[19];
	char	str_file_size[19];
	char	str_group_id[19];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();

	sprintf(str_user_id, "%d", user_id); 


	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);
		sprintf(str_file_size, "%ld", file_size);

		string_length = strlen(str_group_id);
		string_length += strlen(str_file_size);
		string_length += strlen(filename);
		string_length += strlen(hash);
		string_length += strlen("ga:;;;") +1;

		//if (str_group_file != NULL) kfree(str_group_file);
		str_group_file = kmalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_file)
			return NOT_ALLOWED;

		strcpy(str_group_file, "ga:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, hash);
		strcat(str_group_file, ";");
		strcat(str_group_file, filename);

		if (besearch_file(str_group_file, list, list_len) == 0) {
			if (printk_allowed == true)
				printk("%s USER/PROG. ALLOWED: ga:%s;%s;%s;%s\n", step, str_group_id, str_file_size, hash, filename);

			kfree(str_group_file);
			str_group_file = NULL;
			return ALLOWED;
		}

		kfree(str_group_file);
		str_group_file = NULL;
	}

	return NOT_ALLOWED;
}



/*--------------------------------------------------------------------------------*/
static int
group_deny(	uid_t user_id,
		const char *filename,
		ssize_t file_size,
		char hash[],
		char **list,
		long list_len,
		const char *step)
{

	char	str_user_id[19];
	char	str_file_size[19];
	char	str_group_id[19];
	char	*str_group_file = NULL;
	struct	group_info *group_info;
	int	string_length;

	group_info = get_current_groups();

	sprintf(str_user_id, "%d", user_id); 

	for (int n = 0; n < group_info->ngroups; n++) {
		sprintf(str_group_id, "%u", group_info->gid[n].val);
		sprintf(str_file_size, "%ld", file_size);

		string_length = strlen(str_group_id);
		string_length += strlen(str_file_size);
		string_length += strlen(hash);
		string_length += strlen(filename);
		string_length += strlen("gd:;;;") +1;

		str_group_file = kmalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_file)
			return NOT_ALLOWED;

		strcpy(str_group_file, "gd:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, hash);
		strcat(str_group_file, ";");
		strcat(str_group_file, filename);

		if (besearch_file(str_group_file, list, list_len) == 0) {
			if (printk_deny == true)
				printk("%s USER/PROG. DENY   : gd:%s;%s;%s;%s\n", step, str_group_id, str_file_size, hash, filename);

			kfree(str_group_file);

			return NOT_ALLOWED;
		}
		else kfree(str_group_file);
	}

	return ALLOWED;
}


/*--------------------------------------------------------------------------------*/
static int
user_folder_allowed(	uid_t user_id,
			const char *filename,
			char **list,
			long list_len,
			const char *step)

{

	char str_user_id[19];
	char *str_folder = NULL;
	int  string_length;

	sprintf(str_user_id, "%d", user_id); 

	string_length = strlen(str_user_id);
	string_length += strlen(filename);
	string_length += strlen("a:;") + 1;

	str_folder = kmalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_folder)
		return NOT_ALLOWED;

	strcpy(str_folder, "a:");
	strcat(str_folder, str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, filename);
	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == 0) {
		if (printk_allowed == true)
			printk("%s USER/PROG. ALLOWED: a:%s;%s\n", step, str_user_id, filename);

		kfree(str_folder);
		return ALLOWED;
	}

	kfree(str_folder);
	return NOT_ALLOWED;
}



/*--------------------------------------------------------------------------------*/
static int
user_folder_deny(uid_t user_id,
		const char *filename,
		char **list,
		long list_len,
		const char *step)

{

	char str_user_id[19];
	char *str_folder = NULL;
	int  string_length;

	sprintf(str_user_id, "%d", user_id); 

	string_length = strlen(str_user_id);
	string_length += strlen(filename);
	string_length += strlen("d:;") + 1;

	str_folder = kmalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_folder)
		return NOT_ALLOWED;

	strcpy(str_folder, "d:");
	strcat(str_folder, str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, filename);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == 0) {
		if (printk_deny == true)
			printk("%s USER/PROG. DENY   : a:%s;%s\n", step, str_user_id, filename);

		kfree(str_folder);
		return NOT_ALLOWED;
	}

	kfree(str_folder);
	return ALLOWED;
}


/*--------------------------------------------------------------------------------*/
static int
group_folder_allowed(	uid_t user_id,
			const char *filename,
			char **list,
			long list_len,
			const char *step)

{

	char	str_user_id[19];
	char	str_group_id[19];
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
		str_group_folder = kmalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_folder)
			return NOT_ALLOWED;

		strcpy(str_group_folder, "ga:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, filename);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == 0) {
			if (printk_allowed == true)
				printk("%s USER/PROG. ALLOWED: ga:%s;%s\n", step, str_group_id, filename);

			kfree(str_group_folder);
			return ALLOWED;
		}
		else kfree(str_group_folder);

	}

	return NOT_ALLOWED;
}



/*--------------------------------------------------------------------------------*/
static int
group_folder_deny(uid_t user_id,
		const char *filename,
		char **list,
		long list_len,
		const char *step)

{

	char	str_user_id[19];
	char	str_group_id[19];
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
		str_group_folder = kmalloc(string_length * sizeof(char), GFP_KERNEL);
		if (!str_group_folder)
			return NOT_ALLOWED;

		strcpy(str_group_folder, "gd:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, filename);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == 0) {
			if (printk_deny == true)
				printk("%s USER/PROG. DENY   : gd:%s;%s\n", step, str_group_id, filename);

			kfree(str_group_folder);
			return NOT_ALLOWED;
		}
		else kfree(str_group_folder);
	}

	return ALLOWED;
}


/*--------------------------------------------------------------------------------*/
static int
user_interpreter_allowed(uid_t user_id,
			const char *filename,
			ssize_t file_size,
			char hash[],
			char **list,
			long list_len,
			const char *step)

{

	char	str_user_id[19];
	char	str_file_size[19];
	char	*str_user_file = NULL;
	int	string_length;


	sprintf(str_user_id, "%d", user_id); 
	sprintf(str_file_size, "%ld", file_size); 


	/* user allowed interpreter */
	string_length = strlen(str_user_id);
	string_length += strlen(str_file_size);
	string_length += strlen(hash);
	string_length += strlen(filename);
	string_length += strlen("ai:;;;") + 1;

	str_user_file = kmalloc(string_length * sizeof(char), GFP_KERNEL);
	if (str_user_file == NULL)
		return NOT_ALLOWED;

	strcpy(str_user_file, "ai:");
	strcat(str_user_file, str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, hash);
	strcat(str_user_file, ";");
	strcat(str_user_file, filename);


	if (besearch_file(str_user_file, list, list_len) == 0) {
		if (printk_allowed == true)
			printk("%s USER/PROG. ALLOWED: ai:%s;%s;%s;%s\n", step, str_user_id, str_file_size, hash, filename);

		kfree(str_user_file);
		str_user_file = NULL;
		return ALLOWED;
	}

	kfree(str_user_file);
	str_user_file = NULL;

	return NOT_ALLOWED;
}


/*--------------------------------------------------------------------------------*/
/* user allowed interpreter etc. and allowed group script file*/
/* 0 allowed */
/* -1 deny */
static int
user_interpreter_file_allowed(	uid_t user_id,
				const char *filename,
				ssize_t file_size,
				char hash[],
				char **argv,
				long argv_len,
				char **list,
				long list_len,
				const char *step)

{

	int retval;
	struct sum_hash_struct size_hash_sum;


	if (argv_len == 1) return NOT_ALLOWED;


	/* check interpreter and files */
	/* user allowed interpreter */
	/* check "ai:" */
	retval = user_interpreter_allowed(user_id,
					filename,
					file_size,
					hash,
					list,
					list_len,
					step);

	if (retval == NOT_ALLOWED)
		return NOT_ALLOWED;

	/* java */
	if (strcmp(argv[1], "-jar") == 0) {
		if (argv_len != 3) return NOT_ALLOWED;

		size_hash_sum = get_file_size_hash_read(argv[2], HASH_ALG, DIGIT);
		if (size_hash_sum.retval == NOT_ALLOWED) {
			if (printk_deny == true)
				printk("STAT STEP FIRST: USER/PROG. UNKOWN : a:%d;;;%s\n",user_id,
											argv[2]);
			return NOT_ALLOWED;
		}

		/* check file/prog is in list/allowed */
		if (user_allowed(user_id,
				argv[2],
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				list,
				list_len,
				step) == ALLOWED) return ALLOWED;


		if (group_allowed(user_id,
				argv[2],
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				list,
				list_len,
				step) == ALLOWED) return ALLOWED;

		if (printk_deny == true)
			printk("%s USER/SCRIPT DENY  : a:%d;%ld;%s;%s\n", step,
									user_id,
									size_hash_sum.file_size,
									size_hash_sum.hash_string,
									argv[2]);
	}


	/* java */
	if (strcmp(argv[1], "-classpath") == 0) {
		if (argv_len != 4) return NOT_ALLOWED;

		long str_length;
		str_length = strlen(argv[2]);
		str_length += strlen(argv[3]);
		str_length += strlen("/.class") + 1;

		char *str_class_name = kmalloc(str_length * sizeof(char), GFP_KERNEL);
		if (str_class_name == NULL) return(NOT_ALLOWED);

		strcpy(str_class_name, argv[2]);
		strcat(str_class_name, "/");
		strcat(str_class_name, argv[3]);
		strcat(str_class_name, ".class");

		size_hash_sum = get_file_size_hash_read(str_class_name, HASH_ALG, DIGIT);
		if (size_hash_sum.retval == NOT_ALLOWED) {
			if (printk_deny == true)
				printk("STAT STEP FIRST: USER/PROG. UNKOWN : a:%d;;;%s\n",user_id,
											str_class_name);

			kfree(str_class_name);
			return NOT_ALLOWED;
		}

		/* check file/prog is in list/allowed */
		if (user_allowed(user_id,
				str_class_name,
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				list,
				list_len,
				step) == ALLOWED) {

			kfree(str_class_name);
			return ALLOWED;
		}

		if (group_allowed(user_id,
				str_class_name,
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				list,
				list_len,
				step) == ALLOWED) {

			kfree(str_class_name);
			return ALLOWED;
		}

		if (printk_deny == true)
			printk("%s USER/SCRIPT DENY  : a:%d;%ld;%s;%s\n", step,
									user_id,
									size_hash_sum.file_size,
									size_hash_sum.hash_string,
									str_class_name);

		//printk("%s\n", str_class_name);
		kfree(str_class_name);

		return(NOT_ALLOWED);
	}


	/* other */
	size_hash_sum = get_file_size_hash_read(argv[1], HASH_ALG, DIGIT);
	if (size_hash_sum.retval == NOT_ALLOWED)
		return NOT_ALLOWED;

	/* check file/prog is in list/allowed */
	/* check if argv[1] is Prog/File than is allowed*/ 
	if (user_allowed(user_id,
			argv[1],
			size_hash_sum.file_size,
			size_hash_sum.hash_string,
			list,
			list_len,
			step) == ALLOWED) return ALLOWED;

	if (group_allowed(user_id,
			argv[1],
			size_hash_sum.file_size,
			size_hash_sum.hash_string,
			list,
			list_len,
			step) == ALLOWED) return ALLOWED;

	if (printk_deny == true)
		printk("%s USER/SCRIPT DENY  : a:%d;%ld;%s;%s\n", step,
								user_id,
								size_hash_sum.file_size,
								size_hash_sum.hash_string,
								argv[1]);

	/* not found */
	return NOT_ALLOWED;
}






/*--------------------------------------------------------------------------------*/
static int exec_first_step(uid_t user_id, const char *filename, char **argv, long argv_len)
{

	struct sum_hash_struct size_hash_sum;


	/* Limit argv[0] = 1000 */
	/* Reason glibc */
	/* A GOOD IDEA? I don't know? */
	/* But it's works */
	/* when in doubt remove it */
	if (strlen(argv[0]) > 1000) {
		if (printk_deny == true || printk_allowed == true)
			printk("STAT STEP FIRST: USER/PROG. DENY. ARGV[0] ERROR: a:%d;;;%s\n",user_id,
												filename);
		return RET_SHELL;
	}


	/* if Size = 0 not check */
	size_hash_sum = get_file_size_hash_read(filename, HASH_ALG, DIGIT);
	if (size_hash_sum.retval == NOT_ALLOWED) {
		if (printk_deny == true)
			printk("STAT STEP FIRST: USER/PROG. UNKOWN : a:%d;;;%s\n",user_id,
										filename);
		return ALLOWED;
	}


	/* group deny folder */
	if (global_list_folder_len > 0) {
		if (group_folder_deny(user_id,
					filename,
					global_list_folder,
					global_list_folder_len,
					"STAT STEP FIRST:") == NOT_ALLOWED)
			return RET_SHELL;
	}

	/* deny folder */
	if (global_list_folder_len > 0) {
		if (user_folder_deny(user_id,
					filename,
					global_list_folder,
					global_list_folder_len,
					"STAT STEP FIRST:") == NOT_ALLOWED)
			return RET_SHELL;
	}

	/* deny group */
	/* if global_list_prog_len = 0, safer_mode not true */
	if (group_deny( user_id,
			filename,
			size_hash_sum.file_size,
			size_hash_sum.hash_string,
			global_list_prog,
			global_list_prog_len,
					"STAT STEP FIRST:") == NOT_ALLOWED)
		return RET_SHELL;

	/* deny user */
	if (user_deny(user_id,
			filename,
			size_hash_sum.file_size,
			size_hash_sum.hash_string,
			global_list_prog,
			global_list_prog_len,
					"STAT STEP FIRST:") == NOT_ALLOWED)
		return RET_SHELL;

	/* group allowed folder */
	if (global_list_folder_len > 0) {
		if (group_folder_allowed(user_id,
					filename,
					global_list_folder,
					global_list_folder_len,
					"STAT STEP FIRST:") == ALLOWED)
			return ALLOWED;
	}

	/* user allowed folder */
	if (global_list_folder_len > 0) {
		if (user_folder_allowed(user_id,
					filename,
					global_list_folder,
					global_list_folder_len,
					"STAT STEP FIRST:") == ALLOWED)
			return ALLOWED;
	}

	/* allowed user */
	if (user_allowed(user_id,
			filename,
			size_hash_sum.file_size,
			size_hash_sum.hash_string,
			global_list_prog,
			global_list_prog_len,
			"STAT STEP FIRST:") == ALLOWED)
		return ALLOWED;;

	/* allowed group */
	if (group_allowed(user_id,
			filename,
			size_hash_sum.file_size,
			size_hash_sum.hash_string,
			global_list_prog,
			global_list_prog_len,
			"STAT STEP FIRST:") == ALLOWED)
		return ALLOWED;


	/* user allowed interpreter and allowed group script file*/
	/* 0 allowed */
	/* -1 deny */
	if (user_interpreter_file_allowed(user_id,
					filename,
					size_hash_sum.file_size,
					size_hash_sum.hash_string,
					argv,
					argv_len,
					global_list_prog,
					global_list_prog_len,
					"STAT STEP FIRST:") == ALLOWED)
		return ALLOWED;

	if (printk_deny == true)
		printk("STAT STEP FIRST: USER/PROG. DENY   : a:%d;%ld;%s;%s\n", user_id,
										size_hash_sum.file_size,
										size_hash_sum.hash_string,
										filename);

	return (RET_SHELL);

}





/*--------------------------------------------------------------------------------*/
static int exec_second_step(const char *filename)
{

	struct sum_hash_struct size_hash_sum;
	int retval;

	uid_t user_id = get_current_user()->uid.val;




	if (learning_mode == true) {

		/* works too */
		mutex_lock(&learning_lock);

		learning(user_id,
			filename,
			&global_list_learning,
			&global_list_learning_len,
			HASH_ALG,
			DIGIT);

		mutex_unlock(&learning_lock);
	}



	if (safer_mode == true	|| (safer_show_mode == true && printk_allowed == true )
				|| (safer_show_mode == true && printk_deny == true)) {

		/* if size = 0 not check */
		size_hash_sum = get_file_size_hash_read(filename, HASH_ALG, DIGIT);
		if (size_hash_sum.retval == NOT_ALLOWED) {
			if (printk_deny == true)
				printk("STAT STEP SEC  : USER/PROG. UNKOWN : a:%d;;;%s\n",user_id,
											filename);
			return ALLOWED;
		}


		/* group deny folder */
		if (global_list_folder_len > 0) {
			retval = group_folder_deny(user_id,
						filename,
						global_list_folder,
						global_list_folder_len,
						"STAT STEP SEC  :");

			if (safer_mode == true) {
				if (retval == NOT_ALLOWED)
					return RET_SHELL;
			}
			else if (retval == NOT_ALLOWED)
				return ALLOWED;
		}


		/* deny folder */
		if (global_list_folder_len > 0) {
			retval = user_folder_deny(user_id,
						filename,
						global_list_folder,
						global_list_folder_len,
						"STAT STEP SEC  :");

			if (safer_mode == true) {
				if (retval == NOT_ALLOWED)
					return RET_SHELL;
			}
			else if (retval == NOT_ALLOWED)
				return ALLOWED;
		}



		/* deny group */
		/* if global_list_prog_len = 0, safer_mode not true */
		retval = group_deny(user_id,
				filename,
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				global_list_prog,
				global_list_prog_len,
				"STAT STEP SEC  :");

		if (safer_mode == true) {
			if (retval == NOT_ALLOWED)
				return RET_SHELL;
		}
		else if (retval == NOT_ALLOWED)
			return ALLOWED;


		/* deny user */
		retval = user_deny(user_id,
				filename,
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				global_list_prog,
				global_list_prog_len,
				"STAT STEP SEC  :");

		if (safer_mode == true) {
			if (retval == NOT_ALLOWED)
				return RET_SHELL;
		}
		else if (retval == NOT_ALLOWED)
			return ALLOWED;


		/* allowed folder */
		if (global_list_folder_len > 0) {
			if (group_folder_allowed(user_id,
						filename,
						global_list_folder,
						global_list_folder_len,
						"STAT STEP SEC  :") == ALLOWED)
				return ALLOWED;
		}

		/* allowed folder */
		if (global_list_folder_len > 0) {
			if (user_folder_allowed(user_id,
						filename,
						global_list_folder,
						global_list_folder_len,
						"STAT STEP SEC  :") == ALLOWED)
				return ALLOWED;
		}

		/* allowed user */
		if (user_allowed(user_id,
				filename,
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				global_list_prog,
				global_list_prog_len,
				"STAT STEP SEC  :") == ALLOWED)
			return ALLOWED;

		/* allowed group */
		if (group_allowed(user_id,
				filename,
				size_hash_sum.file_size,
				size_hash_sum.hash_string,
				global_list_prog,
				global_list_prog_len,
				"STAT STEP SEC  :") == ALLOWED)
			return ALLOWED;


		/* user allowed interpreter */
		if (user_interpreter_allowed(	user_id,
						filename,
						size_hash_sum.file_size,
						size_hash_sum.hash_string,
						global_list_prog,
						global_list_prog_len,
						"STAT STEP SEC  :") == ALLOWED)
				return ALLOWED;

		if (printk_deny == true) {
			printk("STAT STEP SEC  : USER/PROG. DENY   : a:%d;%ld;%s;%s\n",user_id,
											size_hash_sum.file_size,
											size_hash_sum.hash_string,
											filename);
		}






		/* filter end */
		if (safer_mode == true)
			return (RET_SHELL);
		else return ALLOWED;
	}

	return ALLOWED;
}



/*--------------------------------------------------------------------------------*/
static int allowed_exec(struct filename *kernel_filename,
			const char __user *const __user *_argv)
{

	struct user_arg_ptr argv = { .ptr.native = _argv };

	const char __user	*str;
	char			**argv_list = NULL;
	long			argv_list_len = 0;
	long			str_len;
	int			retval;
	uid_t			user_id;


	if (safer_mode == false)
		if (learning_mode == false)
			if (safer_show_mode == false || printk_allowed == false)
				if (safer_show_mode == false || printk_deny == false)
					return ALLOWED;

	/* argv -> kernel space */
	argv_list_len = count(argv, MAX_ARG_STRINGS);

	if (argv_list_len > ARGV_MAX) argv_list_len = ARGV_MAX;
	argv_list = kzalloc(argv_list_len * sizeof(char *), GFP_KERNEL);
	if (!argv_list)
		return ALLOWED;

	for (int n = 0; n < argv_list_len; n++) {
		str = get_user_arg_ptr(argv, n);
		str_len = strnlen_user(str, MAX_ARG_STRLEN);

		argv_list[n] = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);

		retval = copy_from_user(argv_list[n], str, str_len);
	}

	user_id = get_current_user()->uid.val;



	if (verbose_param_mode == true)
		print_prog_arguments(	user_id,
					kernel_filename->name,
					argv_list,
					argv_list_len,
					HASH_ALG,
					DIGIT);


	if (learning_mode == true) {

		/* works too */
		mutex_lock(&learning_lock);

		learning(user_id,
			kernel_filename->name,
			&global_list_learning,
			&global_list_learning_len,
			HASH_ALG,
			DIGIT);

		learning_argv(	user_id,
				kernel_filename->name,
				argv_list,
				argv_list_len,
				&global_list_learning_argv,
				&global_list_learning_argv_len,
				&global_list_learning_argv_init);

		mutex_unlock(&learning_lock);

	}

	if (safer_mode == true	|| (safer_show_mode == true && printk_allowed == true)
				|| (safer_show_mode == true && printk_deny == true))
		retval = exec_first_step(user_id,
					kernel_filename->name,
					argv_list,
					argv_list_len);


	for (int n = 0; n < argv_list_len; n++) {
		if (argv_list[n] != NULL)
			kfree(argv_list[n]);
	}

	if (argv_list != NULL) {
		kfree(argv_list);
		argv_list = NULL;
	}


	if (safer_mode == true)
		return (retval);

	return ALLOWED;

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



	user_id = get_current_user()->uid.val;

	/* command part, future ? */
	switch(number) {


		/* safer on */
		case 999900:	if (user_id != 0) return CONTROL_ERROR;
				if (change_mode == false) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;

				if (global_list_prog_len > 0 || global_list_folder_len > 0) {
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
		case 999901:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER OFF\n");
				safer_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* stat */
		case 999902:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				printk("SAFER STATE         : %d\n", safer_mode);
				return(safer_mode);


		/* printk allowed */
		case 999903:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK ALLOWED ON\n");
				printk_allowed = true;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* printk allowed */
		case 999904:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK ALLOWED OFF\n");
				printk_allowed = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999905:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: NO MORE CHANGES ALLOWED\n");
				change_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999906:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: learning ON\n");
				learning_mode = true;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999907:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: learning OFF\n");
				learning_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		case 999908:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: verbose paramter mode ON\n");
				verbose_param_mode = true;
				mutex_unlock(&control);
				return CONRTOL_OK;



		case 999909:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: verbose parameter mode OFF\n");
				verbose_param_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* safer show on */
		case 999910:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;

				safer_show_mode = true;
				printk("MODE: SAFER SHOW ONLY ON\n");
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* safer show off */
		case 999911:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER SHOW ONLY OFF\n");
				safer_show_mode = false;
				mutex_unlock(&control);
				return CONRTOL_OK;



		/* printk deny ON */
		case 999912:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK DENY ON\n");
				printk_deny = true;
				mutex_unlock(&control);
				return CONRTOL_OK;


		/* printk deny OFF */
		case 999913:	if (change_mode == false) return CONTROL_ERROR;
				if (user_id != 0) return CONTROL_ERROR;
				if (!mutex_trylock(&control)) return CONTROL_ERROR;
				printk("MODE: SAFER PRINTK DENY OFF\n");
				printk_deny = false;
				mutex_unlock(&control);
				return CONRTOL_OK;



		/* set all list */
		case 999920:

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

				list_string = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				int_ret = copy_from_user(list_string, str, str_len);

				long list_prog_len;
				int_ret = kstrtol(list_string, 10, &list_prog_len);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; }
				if (int_ret != 0) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* new list 0 ? */
				if (list_prog_len < 1) {
					printk("NO FILE LIST\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* new list > MAX_DYN */
				if (list_prog_len > MAX_DYN) {
					printk("FILE LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/* check bytes */
				/* new list */
				long list_progs_bytes = 0;
				for (int n = 0; n < list_prog_len; n++) {
					str = get_user_arg_ptr(_list, n + 1);
					list_progs_bytes += strnlen_user(str, MAX_ARG_STRLEN);
				}

				if (list_progs_bytes > MAX_DYN_BYTES) {
					printk("FILE LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* clear */
				/* old list */
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

				/* global = new */
				global_list_prog_len = list_prog_len;
				global_list_progs_bytes = list_progs_bytes;

				printk("FILE LIST ELEMENTS: %ld\n", global_list_prog_len);
				printk("FILE LIST BYTES   : %ld\n", global_list_progs_bytes);


				/* dyn array */
				global_list_prog = kmalloc(global_list_prog_len * sizeof(char *), GFP_KERNEL);
				/* Old list no longer exists. Cannot create a new one */
				if (global_list_prog == NULL) {
					mutex_unlock(&control);
					panic(NO_SECURITY_GUARANTEED);
				}

				for (int n = 0; n < global_list_prog_len; n++) {
					str = get_user_arg_ptr(_list, n + 1);		/* String 0 */
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					global_list_prog[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					/* Old list no longer exists. Cannot create a new one */
					if (global_list_prog[n] == NULL) {
						mutex_unlock(&control);
						panic(NO_SECURITY_GUARANTEED);
					}

					int_ret = copy_from_user(global_list_prog[n], str, str_len);
				}
 
				mutex_unlock(&control);
				return(global_list_prog_len);


		/* set all folder list */
		case 999921:
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

				list_string = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
				if (list_string == NULL) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				int_ret = copy_from_user(list_string, str, str_len);

				long list_folder_len;
				int_ret = kstrtol(list_string, 10, &list_folder_len);
				if (list_string != NULL) { kfree(list_string); list_string = NULL; };
				if (int_ret != 0) {
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/* new list = 0 ? */
				if (list_folder_len < 1) {
					printk("NO FOLDER LIST\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}

				/* new list > MAX_DYN */
				if (list_folder_len > MAX_DYN) {
					printk("FOLDER LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}


				/* check bytes */
				/* new list */
				long list_folders_bytes = 0;
				for (int n = 0; n < list_folder_len; n++) {
					str = get_user_arg_ptr(_list, n + 1);
					list_folders_bytes += strnlen_user(str, MAX_ARG_STRLEN);
				}

				if (list_folders_bytes > MAX_DYN_BYTES) {
					printk("FOLDER LIST TO BIG!\n");
					mutex_unlock(&control);
					return CONTROL_ERROR;
				}



				/* clear */
				/* old list */
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

				// global = new */
				global_list_folder_len = list_folder_len;
				global_list_folders_bytes = list_folders_bytes;

				printk("FOLDER LIST ELEMENTS: %ld\n", global_list_folder_len);
				printk("FOLDER LIST BYTES   : %ld\n", global_list_folders_bytes);



				/* dyn array */
				global_list_folder = kmalloc(global_list_folder_len * sizeof(char *), GFP_KERNEL);
				/* Old list no longer exists. Cannot create a new one */
				if (global_list_folder == NULL) {
					mutex_unlock(&control);
					panic(NO_SECURITY_GUARANTEED);
				}

				for (int n = 0; n < global_list_folder_len; n++) {
					str = get_user_arg_ptr(_list, n + 1);
					str_len = strnlen_user(str, MAX_ARG_STRLEN);

					global_list_folder[n] = kmalloc((str_len + 1) * sizeof(char), GFP_KERNEL);
					/* Old list no longer exists. Cannot create a new one */
					if (global_list_folder[n] == NULL) {
						mutex_unlock(&control);
						panic(NO_SECURITY_GUARANTEED);
					}

					int_ret = copy_from_user(global_list_folder[n], str, str_len);
				}

				mutex_unlock(&control);
				return(global_list_folder_len);

		default:	break;
	}


	if (allowed_exec(getname(filename), argv) == RET_SHELL) return(RET_SHELL);


	return do_execve(getname(filename), argv, envp);

}
