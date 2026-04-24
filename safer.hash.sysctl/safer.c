/* Copyright (c) 2022/03/28, 2026.04.24, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.03.28, 2026.04.24, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

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
	Date		: 2022.04.22 - 2026.04.24

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 7.0.0

			  Lenovo X230, T460, T470, Fujitsu Futro S xxx, AMD Ryzen
			  Proxmox, Docker

	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root

			: USER and GROUPS

			: Extension of SYSCALL <execve>
			  You found <replaces> under "add_safer"

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: bsafer
			: Simple Control Program
			: It only works as <root>

			: Shell Script: bsafer
			  look /proc/sys/kernel/safer

			: echo n > kernel/safer/safer_active
			  etc.

			  sysctl -w kernel.safer.safer_aktive=0
			  sysctl -w kernel.safer.safer_aktive=1
			  etc.



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

			: Imortand:
			: Set: ld-linux-x86-64.so.2 etc.
			  ai:....
			  then you can not start python in this form: 
				ld-linux-x86-64.so.2 python

	Install
			: copy safer.c -> fs/
			  copy safer_info.c -> /fs
			  copy safer_learning.c -> /fs

			  look for changes "#define add_safer" in EXAMPLE "fs:exec.c" and write in your current "exec.c"

			  write in fs/Makefile
			  obj-y	+= safer_info.o
			  obj-y	+= safer_learning.o


	Working
			: The easiest way to use "safer" is to use "/proc/safer.learning".
			  Simply save the content to a file.

			  This will then be loaded into the kernel.
			  Example programs: "bsafer PLIST <file.conf>" (root only)
			  Example folder  : "bsafer FLIST <file.conf>" (root only)

			  Then activate (root only)
			  Example: "bsafer SON"

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
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Cesare Pugni, Tschaikowski and Leon Minkus. Admirable ballet dancers and composers/musician.


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
#include <crypto/internal/hash.h>
#include <linux/sysctl.h>


#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>








#define LEARNING	0
#define CHECK		1


/* HASH ?*/

/* Your choice */
/*
#define HASH_ALG "md5"
#define DIGIT 16
#define HASH_STRING_LENGTH (DIGIT * 2) + 1
*/


#define HASH_ALG "sha256"
#define DIGIT 32
#define HASH_STRING_LENGTH (DIGIT * 2) + 1

/*
#define HASH_ALG "sha512"
#define DIGIT 64
#define HASH_STRING_LENGTH (DIGIT * 2) + 1
*/



/*your choice */
#define ARGV_MAX 16

#define LEARNING_ARGV_MAX 5000
#define LEARNING_MAX 50000
#define DENY_MAX 10000

#define LIST_MAX 50000
#define LIST_MIN 1


#define KERNEL_READ_SIZE 2000000

//#define RET_SHELL -1
#define CONTROL_ERROR -1
#define SIZE_ERROR -1



typedef int ibool;


/*--------------------------------------------------------------------------------*/
static DEFINE_MUTEX(learning_lock);
static DEFINE_MUTEX(control);
static DEFINE_MUTEX(kernel_read_from_path_lock);
static DEFINE_MUTEX(deny_lock);


static ibool	learning_mode = true;
static ibool	printk_deny = true;
static ibool	printk_allowed = false;
static ibool	safer_mode = false;
static ibool	ONLY_SHOW_DENY = false;


static ibool	lock_mode = false;
static ibool	verbose_param_mode = false;
static ibool	verbose_file_unknown = true;

static char	**global_list_prog = NULL;
static long	global_list_prog_size = 0;

static char	**global_list_learning = NULL;
static long	global_list_learning_size = -1;

static char	**global_list_learning_argv = NULL;
static long	global_list_learning_argv_size = -1;

static char	**global_list_folder = NULL;
static long	global_list_folder_size = 0;

static long	global_list_progs_bytes = 0;
static long	global_list_folders_bytes = 0;


static char	**global_list_deny = NULL;
static long	global_list_deny_size = -1;




static long	global_statistics_execve_counter = 0;
static long	global_statistics_execve_deny_counter = 0;
static long	global_statistics_execve_allow_counter = 0;
static long	global_statistics_execve_first_step_counter = 0;
static long	global_statistics_execve_sec_step_counter = 0;
static long	global_statistics_execve_path_wrong_counter = 0;


/* Kernel HASH ermitteln */
static ssize_t	KERNEL_SIZE = 0;
static char	KERNEL_HASH[HASH_STRING_LENGTH];
static char	*KERNEL_PATH;



/* look in the function
	"exec_second_step(const char *filename)"
for the variable initramfs_start_delay
*/
//static int initramfs_start_delay = -12;


/*--------------------------------------------------------------------------------*/
/* proto. */
struct struct_file_info {
	bool		retval;
	bool		toctou;
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
	char	hash_raw[DIGIT];

};



/*--------------------------------------------------------------------------------*/
/* proto. /proc/safer.info */
struct  safer_info_struct {
	ibool	safer_mode;
	ibool	ONLY_SHOW_DENY;
	ibool	printk_allowed;
	ibool	printk_deny;
	ibool	learning_mode;
	ibool	lock_mode;
	long	global_list_prog_size;
	long	global_list_folder_size;
	char	**global_list_prog;
	char	**global_list_folder;
	long	global_hash_size;
	long	global_list_progs_bytes;
	long	global_list_folders_bytes;

	long	global_statistics_execve_counter;
	long	global_statistics_execve_deny_counter;
	long	global_statistics_execve_allow_counter;
	long	global_statistics_execve_first_step_counter;
	long	global_statistics_execve_sec_step_counter;
	long	global_statistics_execve_path_wrong_counter;
	ssize_t	KERNEL_SIZE;
	char	KERNEL_HASH[HASH_STRING_LENGTH];
};



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


	if (str_search[strlen(str_search) -1] == '/' ) return false;


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
		return SIZE_ERROR;

	if (!S_ISREG(file_inode(file)->i_mode)) {
		fput(file);
		return SIZE_ERROR;
	}

	if (deny_write_access(file)) {
		fput(file);
		return SIZE_ERROR;
	}

	i_size = i_size_read(file_inode(file));
	if (i_size < 1) {
		allow_write_access(file);
		fput(file);
		return SIZE_ERROR;
	}

	/* The file is too big for sane activities. */
	if (i_size > INT_MAX) {
		allow_write_access(file);
		fput(file);
		return SIZE_ERROR;
	}

	allow_write_access(file);
	fput(file);
	return (ssize_t) i_size;
}




/*--------------------------------------------------------------------------------*/
static struct struct_hash_sum get_hash_sum(char buffer[], ssize_t max)
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




static struct struct_file_info get_file_info(const char *fname, ssize_t max)
{

	/*
	 * Folgendes Angriffs Szenario
	 * Angreifer laedt Mal-Software
	 * Sofort danach wird die Mal-software geloescht oder veraendert
	 * orginal Software tritt an die Stelle
	 *
	 * 1. struct file holen. keine link attacken mehr moeglich 
	 * 2  Code markiert Inode
	 * 3. Kernel_read_file. 
	 * 4. Code prueft Inode. Wenn Pruefung nicht bestanden
	 *    TOCOU Attacke.
	 *
	 * 5. Gleiches Szenario. Nur andersherum. Erst gute Datei
	 *    dann Schadsoftware. In beiden Faellen ist das Check flag nicht gesetzt
	 *    Annahme Toctou Attacke
	 */

	/*
	 * 1. inode is set		check
	 * 2. error: read		back to kernel
	 * 3. error: HASH fehlerhaft	back to kernel
	 * 4. read and HASH OK		check

	 * 5. toctou			back to kernel, not allowed
	 */


	void				*data = NULL;
	struct struct_file_info		struct_file_info;
	ssize_t				error;

	/* in inode schreiben */
	struct inode *inode;
	struct path path;

	struct file *file;


	mutex_lock(&kernel_read_from_path_lock);

	/* ------------------------------------------------------------------------------------- */
	struct_file_info.file_size = get_file_size(fname);
	if (struct_file_info.file_size == SIZE_ERROR) {
		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.toctou = false;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}


	/* ------------------------------------------------------------------------------------- */
	error = kern_path(fname, LOOKUP_FOLLOW, &path);
	if (error) {
		struct_file_info.toctou = false;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}

	file = dentry_open(&path, O_RDONLY, current_cred());
	path_put(&path); /* dentry_open add own reference */

	if (IS_ERR(file)) {
		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.toctou = false;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}

	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode)) {
		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.toctou = false;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}


	if (test_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags)) {
		memcpy(struct_file_info.hash_string, inode->i_boettcher_hash, DIGIT * 2);
		struct_file_info.hash_string[DIGIT * 2] = '\0';

		struct_file_info.user_id = get_current_user()->uid.val;
		scnprintf(struct_file_info.str_user_id, sizeof(struct_file_info.str_user_id), "%d", struct_file_info.user_id);

		struct_file_info.file_size = i_size_read(inode);
		scnprintf(struct_file_info.str_file_size, sizeof(struct_file_info.str_file_size), "%ld", struct_file_info.file_size);

		struct_file_info.fname = fname;

		if (printk_allowed == true)
			printk("SAFER: Has alredy been checked: a:%s;%s;%s;%s\n",
					struct_file_info.str_user_id,
					struct_file_info.str_file_size,
					struct_file_info.hash_string,
					struct_file_info.fname);

		fput(file);

		struct_file_info.toctou = false;
		struct_file_info.retval = true;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}

	set_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);



	/* ------------------------------------------------------------------------------------- */
	if (struct_file_info.file_size < max)
		max = struct_file_info.file_size;

	/* read. no link attack */
	error = kernel_read_file(file, 0, &data, INT_MAX, NULL, READING_POLICY);

	if (error < 0) {
		// error: read (z.B. -E2BIG, -EIO)

		if (error == -ENOENT)
			printk("SAFER ERROR: File not found\n");
		
		else if (error == -EACCES)
			printk("SAFER ERROR: No right\n");
		
		else if (error == -EINVAL)
			printk("SAFER ERROR: wrong arg.\n");
		
		else
			printk("SAFER ERROR: unknown\n");

		clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);
		fput(file);

		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.toctou = false;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}


	/* ------------------------------------------------------------------------------------- */
	/* TOCTOU ? */

	/* userland delete file */
	//if (inode->i_nlink == 0)
	//	struct_file_info.toctou = true;

	/* userland write etc. file! */
	if (!test_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags))
		struct_file_info.toctou = true;

	else
		struct_file_info.toctou = false;


	if (struct_file_info.toctou == true) {

		clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);

		vfree(data);
		fput(file);

		/* toctou attacke if not set! */
		printk("SAFER: TOCTOU-ATTACKE: a:%s;%s;%s;%s\n",
			struct_file_info.str_user_id,
			struct_file_info.str_file_size,
			struct_file_info.hash_string,
			struct_file_info.fname);

		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.toctou = true;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}

	/* ------------------------------------------------------------------------------------- */
	struct_file_info.fname = fname;
	struct_file_info.user_id = get_current_user()->uid.val;
	scnprintf(struct_file_info.str_user_id, sizeof(struct_file_info.str_user_id), "%d", struct_file_info.user_id);

	/* look: begin */
	scnprintf(struct_file_info.str_file_size, sizeof(struct_file_info.str_file_size), "%ld", struct_file_info.file_size);


	/* ------------------------------------------------------------------------------------- */
	/* HASH */
	char *buffer = data;
	struct struct_hash_sum struct_hash_sum = get_hash_sum(buffer, max);
	vfree(data);


	/* ------------------------------------------------------------------------------------- */
	if (struct_hash_sum.retval == false) {
		clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);
		fput(file);

		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.toctou = false;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_from_path_lock);
		return struct_file_info;
	}

	/* ------------------------------------------------------------------------------------- */
	strscpy(struct_file_info.hash_string, struct_hash_sum.hash_string, HASH_STRING_LENGTH);

	memcpy(inode->i_boettcher_hash, struct_file_info.hash_string, DIGIT * 2);

	/* ------------------------------------------------------------------------------------- */

	fput(file);


	if (printk_allowed == true)
		printk("SAFER: STAT STEP FIRST Check a:%s;%s;%s;%s\n",
				struct_file_info.str_user_id,
				struct_file_info.str_file_size,
				struct_file_info.hash_string,
				struct_file_info.fname);


	/* ------------------------------------------------------------------------------------- */
	struct_file_info.toctou = false;
	struct_file_info.retval = true;

	mutex_unlock(&kernel_read_from_path_lock);

	return struct_file_info;
}



/*--------------------------------------------------------------------------------*/
static void learning_argv(struct struct_file_info *struct_file_info,
			char **argv,
			long argv_len,
			char ***list,
			long *list_len)

{

	char	*str_learning =  NULL;
	int	string_length = 0;


	if (argv_len == 1) return;

	// file not exist or empty 
	if (struct_file_info->retval == false) return;


	// init list, max lines
	// Only One 
	if (*list_len == -1) {
		*list = kzalloc(sizeof(char *) * LEARNING_ARGV_MAX, GFP_KERNEL);
		if (*list == NULL) {
			return;
		}
		else *list_len = 0;
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

	if (search(str_learning, *list, *list_len) == true) {
		kfree(str_learning);
		return;
	}

	/* if ring buffer = 0, old free */
	if ( (*list)[*list_len] != NULL) {
		kfree((*list)[*list_len]);
	}

	(*list)[*list_len] = str_learning;

	*list_len += 1;
	// check argv_len > lerning_argv_max
	if (*list_len > LEARNING_ARGV_MAX - 1) {
		*list_len = 0;
	}

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


	/* init pointer list*/
	if (*list_len == -1) {
		*list = kzalloc(sizeof(char *) * LEARNING_MAX, GFP_KERNEL);
		if (*list == NULL) {
			return;
		}
		else *list_len = 0;
	}

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

	if (search(str_learning, *list, *list_len) == true) {
		kfree(str_learning);
		return;
	}

	/* ring buffer = 0, old free */
	if ( (*list)[*list_len] != NULL) {
		kfree((*list)[*list_len]);
	}

	(*list)[*list_len] = str_learning;

	*list_len += 1;
	// check _len > lerning_max
	if (*list_len > LEARNING_MAX - 1) {
		*list_len = 0;
	}

	return;
}





static void deny_list(struct struct_file_info *struct_file_info,
		char ***list,
		long *list_len)
{

	char	*str_deny =  NULL;
	int	string_length = 0;



	if (struct_file_info->fname[0] != '/') return;



	/* init pointer list*/
	if (*list_len == -1) {
		*list = kzalloc(sizeof(char *) * DENY_MAX, GFP_KERNEL);
		if (*list == NULL) {
			return;
		}
		else *list_len = 0;
	}



	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen(struct_file_info->hash_string);
	string_length += strlen("a:;;;") + 1;


	str_deny = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_deny) {
		return;
	}


	strcpy(str_deny, "a:");
	strcat(str_deny, struct_file_info->str_user_id);
	strcat(str_deny, ";");
	strcat(str_deny, struct_file_info->str_file_size);
	strcat(str_deny, ";");
	strcat(str_deny, struct_file_info->hash_string);
	strcat(str_deny, ";");
	strcat(str_deny, struct_file_info->fname);


	if (search(str_deny, *list, *list_len) == true) {
		kfree(str_deny);
		return;
	}


	/* ring buffer = 0, old free */
	if ( (*list)[*list_len] != NULL) {
		kfree((*list)[*list_len]);
	}

	(*list)[*list_len] = str_deny;

	*list_len += 1;
	// check _len > lerning_max
	if (*list_len > DENY_MAX - 1) {
		*list_len = 0;
	}

	return;
}


static void deny_list_toctou(struct struct_file_info *struct_file_info,
		char ***list,
		long *list_len)
{

	char	*str_deny =  NULL;
	int	string_length = 0;



	if (struct_file_info->fname[0] != '/') return;



	/* init pointer list*/
	if (*list_len == -1) {
		*list = kzalloc(sizeof(char *) * DENY_MAX, GFP_KERNEL);
		if (*list == NULL) {
			return;
		}
		else *list_len = 0;
	}



	string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->str_file_size);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen(struct_file_info->hash_string);
	string_length += strlen("a:;;;ALERT TOCTOU: ") + 1;


	str_deny = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_deny) {
		return;
	}


	strcpy(str_deny, "ALERT TOCTOU: a:");
	strcat(str_deny, struct_file_info->str_user_id);
	strcat(str_deny, ";");
	strcat(str_deny, struct_file_info->str_file_size);
	strcat(str_deny, ";");
	strcat(str_deny, struct_file_info->hash_string);
	strcat(str_deny, ";");
	strcat(str_deny, struct_file_info->fname);


	if (search(str_deny, *list, *list_len) == true) {
		kfree(str_deny);
		return;
	}


	/* ring buffer = 0, old free */
	if ( (*list)[*list_len] != NULL) {
		kfree((*list)[*list_len]);
	}

	(*list)[*list_len] = str_deny;

	*list_len += 1;
	// check _len > lerning_max
	if (*list_len > DENY_MAX - 1) {
		*list_len = 0;
	}

	return;
}





/*--------------------------------------------------------------------------------*/
static void print_prog_arguments(struct struct_file_info *struct_file_info,
				char **argv,
				long argv_len,
				long org_argv_len)
{

	if (struct_file_info->retval == false) return;

	printk("USER ID:%s;%s;%s;%s\n",(*struct_file_info).str_user_id,
					(*struct_file_info).str_file_size,
					(*struct_file_info).hash_string,
					(*struct_file_info).fname);

	printk("ORG LEN:%ld \n", org_argv_len);


	for (int n = 0; n < argv_len; n++) {
		/*
		size_hash_sum = get_file_size_hash_read(argv[n], hash_alg, digit);
		printk("argv[%d]:%ld:%s:%s\n", n, size_hash_sum.file_size, size_hash_sum.hash_string, argv[n]);
		*/
		printk("argv[%d]:%.1000s\n", n, argv[n]);

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
user_wildcard_filename_allowed(struct struct_file_info *struct_file_info,
		char **list,
		long list_len,
		const char *step)

{

	if (list_len == 0) return true;

	/* user allowed */
	int string_length = strlen(struct_file_info->fname);
	string_length += strlen("a:*;") + 1;

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_KERNEL);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "a:*;");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
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


		struct_param_info = get_file_info(argv[2], KERNEL_READ_SIZE);

		/* toctou attack: not allowed */
		if (struct_param_info.toctou == true) {
			deny_list_toctou(&struct_param_info,
					&global_list_deny,
					&global_list_deny_size);
			return false;
		}

		/* error: read, hash. back to kernel */
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

		struct_param_info = get_file_info(str_class_name, KERNEL_READ_SIZE);
		/* toctou attack: not allowed */
		if (struct_param_info.toctou == true) {
			deny_list_toctou(&struct_param_info,
					&global_list_deny,
					&global_list_deny_size);

			return false;
		}

		/* error: read, hash. back to kernel */
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
			printk("%s USER/SCRIPT DENY   : a:%s;%s;%s;%s\n", step,
									struct_param_info.str_user_id,
									struct_param_info.str_file_size,
									struct_param_info.hash_string,
									struct_param_info.fname);

		kfree(str_class_name);

		return false;
	}


	/* other */
	struct struct_file_info struct_other_file_info = get_file_info(argv[1], KERNEL_READ_SIZE);
	if (struct_other_file_info.retval == false)
		return true;


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
		printk("%s USER/SCRIPT DENY   : a:%s;%s;%s;%s\n", step,
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

	/* user wildcard allowed filename */
	if (user_wildcard_filename_allowed(struct_file_info,
					global_list_prog,
					global_list_prog_size,
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
	/* Since kernel 6.15, there's an error when starting a "initramfs"
	Solution: Delay activation of "exec_second_step"
	Reason:  "get_file_info" is not working so early in the system startup process.


	if initramfs not start. change <initramfs_start_delay>
	However, I will not change "get_file_info".
	This will probably cost more than this short delay and the initial query.
	*/
/*	if (initramfs_start_delay < 0) {
		initramfs_start_delay++;
		printk("FILE NAME DELAY: %s\n", filename);
		return true;
	}
*/

	if (system_state < SYSTEM_RUNNING)
		return true;


	ssize_t file_size = get_file_size(filename);
	if (file_size == SIZE_ERROR) {

		/* file not exist. */
		if (verbose_file_unknown)
			printk("STAT STEP SEC  : USER/PROG.  UNKNOWN : a:%d;;;%s\n",
				get_current_user()->uid.val,
				filename);

		global_statistics_execve_path_wrong_counter++;
		return true;
	}



	bool retval;
	struct struct_file_info struct_file_info;


	struct_file_info = get_file_info(filename, KERNEL_READ_SIZE);


	/* toctou attack: not allowed */
	if (struct_file_info.toctou == true) {
		deny_list_toctou(&struct_file_info,
				&global_list_deny,
				&global_list_deny_size);
		return false;
	}

	/* error: read, hash. back to kernel */
	if (struct_file_info.retval == false)
		return true;
	/*-------------------------------------------------------------------------- */





	global_statistics_execve_sec_step_counter++;


	if (learning_mode == true) {

		/*
		works too
		accept silent learning losses
		*/
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
	if (retval == false) goto not_allowed;




/*-------------------------------------------------------------------------------------------*/

	/* deny wildcard user */
	retval = user_wildcard_deny(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"STAT STEP SEC  :");
	if (retval == false) goto not_allowed;


/*-------------------------------------------------------------------------------------------*/

	/* group deny folder */
	retval = group_folder_deny(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* deny group */
	/* if global_list_prog_size = 0, safer_mode not true */
	retval = group_deny(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* deny folder */
	retval = user_folder_deny(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* deny user */
	retval = user_deny(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* allowed wildcard folder */
	if (user_wildcard_folder_allowed(&struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}



	/* user wildcard allowed filename */
	if (user_wildcard_filename_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}





	/* allowed wildcard user */
	if (user_wildcard_allowed(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* group allowed folder */
	if (group_folder_allowed(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* allowed group */
	if (group_allowed(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* allowed user folder */
	if (user_folder_allowed(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* allowed user */
	if (user_allowed(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* group allowed interpreter */
	if (group_interpreter_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* user allowed interpreter */
	if (user_interpreter_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"STAT STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	if (printk_deny == true) {
		printk("STAT STEP FIRST: USER/PROG.  DENY   : a:%s;%s;%s;%s\n", struct_file_info.str_user_id,
										struct_file_info.str_file_size,
										struct_file_info.hash_string,
										struct_file_info.fname);
	}

	/* filter end */
not_allowed:
	global_statistics_execve_deny_counter++;

	if (ONLY_SHOW_DENY == true) {
		return true;
	}

	return false;

}





/*--------------------------------------------------------------------------------*/
static bool allowed_exec(const char *filename,
			struct user_arg_ptr argv)
{

	global_statistics_execve_counter++;


	const char __user	*str;
	char			**argv_list = NULL;
	long			argv_list_len = 0;
	long			str_len;
	bool			retval;
	long			org_argv_list_len = 0;

	/*-------------------------------------------------------------------------- */
	/* Nur einmal */
	if (KERNEL_SIZE == 0) {
		/* 
		 * GFP_KERNEL: Der Standard-Flag fuer Speicherallokation im Prozess-Kontext.
		 * Erlaubt dem Kernel zu schlafen, falls gerade kein RAM frei ist.
		 * Linux Kernel Pfad bauen. vmlinuz-
		*/
		
		KERNEL_PATH = kasprintf(GFP_KERNEL, "/boot/vmlinuz-%s", utsname()->release);

		if (KERNEL_PATH) {
			struct struct_file_info struct_kernel_file_info = get_file_info(KERNEL_PATH, 500000000);
			if (struct_kernel_file_info.retval == true) {
				KERNEL_SIZE = struct_kernel_file_info.file_size;
				strcpy(KERNEL_HASH, struct_kernel_file_info.hash_string);

				printk("KERNEL-INFO  : %s\n", KERNEL_PATH);
				printk("KERNEL SIZE  : %ld\n", KERNEL_SIZE);
				printk("KERNEL HASH  : %s\n", KERNEL_HASH);

				/*KERNEL_PATH wird nicht freigegeben*/
				/* WICHTIG: Den Heap-Speicher manuell freigeben! */
				/* kfree(path); */
			}
		}
		else printk("ERROR: GENERATE KERNEL PATH\n");
	}


	/*-------------------------------------------------------------------------- */
	ssize_t file_size = get_file_size(filename);
	if (file_size == SIZE_ERROR) {

		/* file not exist. */
		if (verbose_file_unknown)
			printk("STAT STEP FIRST: USER/PROG.  UNKNOWN : a:%d;;;%s\n",
				get_current_user()->uid.val,
				filename);

		global_statistics_execve_path_wrong_counter++;
		return true;
	}

	/*-------------------------------------------------------------------------- */
	struct struct_file_info struct_file_info = get_file_info(filename, KERNEL_READ_SIZE);

	/* toctou attack: not allowed */
	if (struct_file_info.toctou == true) {
		deny_list_toctou(&struct_file_info,
				&global_list_deny,
				&global_list_deny_size);
		return false;
	}

	/* error: read, hash. back to kernel */
	if (struct_file_info.retval == false)
		return true;
	/*-------------------------------------------------------------------------- */


	/* NOTICE long Para. */
	argv_list_len = count(argv, MAX_ARG_STRINGS);
	org_argv_list_len = argv_list_len;

	if ((printk_allowed == true) || (printk_deny == true)) {
		for (int n = 0; n < argv_list_len; n++) {
			str = get_user_arg_ptr(argv, n);
			str_len = strnlen_user(str, MAX_ARG_STRLEN);
			if (str_len > 10000) {
				printk("STAT STEP FIRST: NOTICE: PROG.: %s, ARGV:[%d], LENGTH:[%ld] > 5000\n",
													filename,
													n,
													str_len);
			}
		}
	}

	/*-------------------------------------------------------------------------- */
	/* argv -> kernel space */
	/* NOT ALL argv */
	if (argv_list_len > ARGV_MAX)
		argv_list_len = ARGV_MAX;


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
		/* if error */
		if (!argv_list[n]) {
			for (int n_ = 0; n_ < n; n_++) {
				kfree(argv_list[n_]);
			}
			kfree(argv_list);
			return false;
		}

		retval = copy_from_user(argv_list[n], str, str_len);
	}


	/*-------------------------------------------------------------------------- */
	if (verbose_param_mode == true) {
		print_prog_arguments(	&struct_file_info,
					argv_list,
					argv_list_len,
					org_argv_list_len);
	}


	/*-------------------------------------------------------------------------- */
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
				&global_list_learning_argv_size);

		mutex_unlock(&learning_lock);

	}


	global_statistics_execve_first_step_counter++;

	/*-------------------------------------------------------------------------- */
	if (safer_mode == true) {
		retval = exec_first_step(&struct_file_info,
					argv_list,
					argv_list_len);

		if (retval == false) {

			deny_list(&struct_file_info,
				&global_list_deny,
				&global_list_deny_size);

			if (ONLY_SHOW_DENY == true)
			retval = true;
		}
		else
			global_statistics_execve_allow_counter++;
	}
	else
		retval = true;

	/*-------------------------------------------------------------------------- */
	/* Free all Elements in argv_list */
	for (int n = 0; n < argv_list_len; n++)
		kfree(argv_list[n]);

	kfree(argv_list);

	return retval;
}










/*-------------------------------------------------------------------------------*/
static int proc_safer_active(	const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (safer_mode == true) {
			printk("MODE: SAFER ON\n");
		}
		else {
			printk("MODE: SAFER OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}




static int proc_safer_printk_deny(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (printk_deny == true) {
			printk("MODE: SAFER PRINTK DENY ON\n");
		}
		else {
			printk("MODE: SAFER PRINTK DENY OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}


static int proc_safer_printk_allowed(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (printk_allowed == true) {
			printk("MODE: SAFER PRINTK ALLOWED ON\n");
		}
		else {
			printk("MODE: SAFER PRINTK ALLOWED OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}



static int proc_safer_learning(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (learning_mode == true) {
			printk("MODE: learning ON\n");
		}
		else {
			printk("MODE: learning OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}



static int proc_safer_lock(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (lock_mode == true) {
			printk("MODE: NO MORE CHANGES ALLOWED\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}



static int proc_safer_show_deny(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (ONLY_SHOW_DENY == true) {
			printk("MODE: SAFER PRINTK ONLY SHOW DENY ON\n");
		}
		else {
			printk("MODE: SAFER PRINTK ONLY SHOW DENY OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}




static int proc_safer_param_verbose(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);


	if (write && retval == 0) {
		if (verbose_param_mode == true) {
			printk("MODE: verbose parameter mode ON\n");
		}
		else {
			printk("MODE: verbose parameter mode OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}




static int proc_safer_show_unknown_file(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);


	if (write && retval == 0) {
		if (verbose_file_unknown == true) {
			printk("MODE: SAFER PRINTK VERBOSE UNKNOWN FILE ON\n");
		}
		else {
			printk("MODE: SAFER PRINTK VERBOSE UNKNOWN FILE OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}





static char safer_prog_string[2048];
static long list_prog_size;
static long list_prog_start = -1;
static long list_progs_bytes;
static char **list_prog_temp = NULL;


static int proc_safer_prog(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dostring(table, write, buffer, lenp, ppos);

	if (write && retval != 0) {
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	/* if String = number then init */
	/* string to number */
	long list_prog_size_temp = 0;
	retval = kstrtol(safer_prog_string, 10, &list_prog_size_temp);
	if (retval == 0) {
		if (list_prog_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_prog_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_prog_start != -1) {
			printk("FREE: list_prog_temp, %ld, %ld\n",list_prog_start, list_prog_size );
			for (int n = 0; n < list_prog_start; n++) {
				if (list_prog_temp[n] != NULL) {
					kfree(list_prog_temp[n]);
					list_prog_temp[n] = NULL;
				}
			}
			kfree(list_prog_temp);
			list_prog_temp = NULL;
		}


		list_prog_temp = kzalloc(list_prog_size_temp * sizeof(char *), GFP_KERNEL);
		/* Create not ok */
		if (list_prog_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_prog_size = list_prog_size_temp;
		list_prog_start = 0;
		list_progs_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}


	if (list_prog_start == -1) { 
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	int str_len = strlen(safer_prog_string);
	list_prog_temp[list_prog_start] = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);

	if (list_prog_temp == NULL) {
		for (int n = 0; n < list_prog_start; n++) {
			kfree(list_prog_temp[n]);
			list_prog_temp[n] = NULL;
		}

		kfree(list_prog_temp);
		list_prog_temp = NULL;
		list_prog_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	list_progs_bytes += str_len;

	strcpy(list_prog_temp[list_prog_start], safer_prog_string);

	list_prog_start++;

	/* list full */
	if (list_prog_start >= list_prog_size) {
		list_prog_start = -1;
		/* clear */
		/* old list */
		char **global_list_prog_temp = global_list_prog;
		char global_list_prog_size_temp = global_list_prog_size;

		/* global = new */
		global_list_prog = list_prog_temp;
		global_list_prog_size = list_prog_size;
		global_list_progs_bytes = list_progs_bytes;
		list_prog_temp = NULL;

		printk("FILE LIST ELEMENTS: %ld\n", global_list_prog_size);
		printk("FILE LIST BYTES   : %ld\n", global_list_progs_bytes);

		if (global_list_prog_size_temp > 0) {
			for (int n = 0; n < global_list_prog_size_temp; n++) {
				if (global_list_prog_temp[n] != NULL) {
					kfree(global_list_prog_temp[n]);
					global_list_prog_temp[n] = NULL;
				}
			}
			kfree(global_list_prog_temp);
			global_list_prog_temp = NULL;
		}
	}
	mutex_unlock(&control);

	return 0;
}




static char safer_folder_string[2048];
static long list_folder_size;
static long list_folder_start = -1;
static long list_folders_bytes;
static char **list_folder_temp = NULL;


static int proc_safer_folder(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dostring(table, write, buffer, lenp, ppos);

	if (write && retval != 0) {
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}


	/* if String = number then init */
	/* string to number */
	long list_folder_size_temp = 0;
	retval = kstrtol(safer_folder_string, 10, &list_folder_size_temp);
	if (retval == 0) {
		if (list_folder_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_folder_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_folder_start != -1) {
			printk("FREE: list_folder_temp, %ld, %ld\n",list_folder_start, list_folder_size );
			for (int n = 0; n < list_folder_start; n++) {
				if (list_folder_temp[n] != NULL) {
					kfree(list_folder_temp[n]);
					list_folder_temp[n] = NULL;
				}
			}
			kfree(list_folder_temp);
			list_folder_temp = NULL;
		}

		list_folder_temp = kzalloc(list_folder_size_temp * sizeof(char *), GFP_KERNEL);
		/* Create not ok */
		if (list_folder_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_folder_size = list_folder_size_temp;
		list_folder_start = 0;
		list_folders_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}


	if (list_folder_start == -1) { 
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	int str_len = strlen(safer_folder_string);
	list_folder_temp[list_folder_start] = kzalloc((str_len + 1) * sizeof(char), GFP_KERNEL);

	if (list_folder_temp == NULL) {
		for (int n = 0; n < list_folder_start; n++) {
			kfree(list_folder_temp[n]);
			list_folder_temp[n] = NULL;
		}

		kfree(list_folder_temp);
		list_folder_temp = NULL;
		list_folder_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	list_folders_bytes += str_len;

	strcpy(list_folder_temp[list_folder_start], safer_folder_string);

	list_folder_start++;

	/* list full */
	if (list_folder_start >= list_folder_size) {
		list_folder_start = -1;
		/* clear */
		/* old list */
		char **global_list_folder_temp = global_list_folder;
		char global_list_folder_size_temp = global_list_folder_size;

		/* global = new */
		global_list_folder = list_folder_temp;
		global_list_folder_size = list_folder_size;
		global_list_folders_bytes = list_folders_bytes;
		list_folder_temp = NULL;

		printk("FOLDER LIST ELEMENTS: %ld\n", global_list_folder_size);
		printk("FOLDER LIST BYTES   : %ld\n", global_list_folders_bytes);

		if (global_list_folder_size_temp > 0) {
			for (int n = 0; n < global_list_folder_size_temp; n++) {
				if (global_list_folder_temp[n] != NULL) {
					kfree(global_list_folder_temp[n]);
					global_list_folder_temp[n] = NULL;
				}
			}
			kfree(global_list_folder_temp);
			global_list_folder_temp = NULL;
		}
	}

	mutex_unlock(&control);

	return 0;
}









static const struct ctl_table safer_table[] = {
	{
		.procname       = "safer_folder",
		.data           = &safer_folder_string,
		.maxlen         = sizeof(safer_folder_string),
		.mode           = 0600,
		.proc_handler   = proc_safer_folder,
	},
	{
		.procname       = "safer_prog",
		.data           = &safer_prog_string,
		.maxlen         = sizeof(safer_prog_string),
		.mode           = 0600,
		.proc_handler   = proc_safer_prog,
	},
	{
		.procname       = "safer_active",
		.data           = &safer_mode,
		.maxlen         = sizeof(int),
		.mode           = 0600,
		.proc_handler   = proc_safer_active,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_printk_deny",
		.data		= &printk_deny,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_printk_deny,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_printk_allowed",
		.data		= &printk_allowed,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_printk_allowed,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_learning",
		.data		= &learning_mode,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_learning,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_lock",
		.data		= &lock_mode,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_lock,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_show_deny",
		.data		= &ONLY_SHOW_DENY,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_show_deny,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_param_verbose",
		.data		= &verbose_param_mode,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_param_verbose,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_show_unknown_file",
		.data		= &verbose_file_unknown,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_show_unknown_file,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
};


//static int __init safer_sysctl_init(void)
//{
	// Reg. PATH /proc/sys/kernel/safer
//	register_sysctl_init("kernel/safer", safer_table);
//	return 0;
//}
//postcore_initcall(safer_sysctl_init);


/*############################################################### */
static int safer_info_display(struct seq_file *proc_show, void *v)
{
	long n;

	seq_printf(proc_show, "INFO SAFER\n\n");

	seq_printf(proc_show, "KERNEL INFO\n");
	seq_printf(proc_show, "Peter Boettcher, Muelheim, GER.\n");

	if (KERNEL_PATH) {
		seq_printf(proc_show, "KERNEL NAME: %s\n", KERNEL_PATH);
	}
	seq_printf(proc_show, "KERNEL DATE: %s\n", utsname()->version);

	seq_printf(proc_show, "KERNEL SIZE: %ld\n", KERNEL_SIZE);
	seq_printf(proc_show, "KERNEL HASH: %s\n\n", KERNEL_HASH);


	seq_printf(proc_show, "SYSCALL <EXECVE>            : %ld\n\n", global_statistics_execve_counter);

	seq_printf(proc_show, "SYSCALL <EXECVE> first      : %ld\n", global_statistics_execve_first_step_counter);
	seq_printf(proc_show, "SYSCALL <EXECVE> sec.       : %ld\n\n", global_statistics_execve_sec_step_counter);

	seq_printf(proc_show, "SYSCALL <EXECVE> ALLOWED    : %ld\n", global_statistics_execve_allow_counter);
	seq_printf(proc_show, "SYSCALL <EXECVE> DENY       : %ld\n\n", global_statistics_execve_deny_counter);

	seq_printf(proc_show, "SYSCALL <EXECVE> PATH WRONG : %ld\n\n", global_statistics_execve_path_wrong_counter);


	if (safer_mode == true)
		seq_printf(proc_show, "MODE SAFER                  : ON\n");
	else	seq_printf(proc_show, "MODE SAFER                  : OFF\n");

	if (ONLY_SHOW_DENY == true)
		seq_printf(proc_show, "ONLY_SHOW_DENY              : ON\n");
	else	seq_printf(proc_show, "ONLY_SHOW_DENY              : OFF\n");

	if (printk_allowed == true)
		seq_printf(proc_show, "MODE PRINTK ALLOWED         : ON\n");
	else	seq_printf(proc_show, "MODE PRINTK ALLOWED         : OFF\n");

	if (printk_deny == true)
		seq_printf(proc_show, "MODE PRINTK DENY            : ON\n");
	else	seq_printf(proc_show, "MODE PRINTK DENY            : OFF\n");

	if (learning_mode == true)
		seq_printf(proc_show, "MODE LEARNING               : ON\n");
	else	seq_printf(proc_show, "MODE LEARNING               : OFF\n");

	if (lock_mode == false)
		seq_printf(proc_show, "MODE SAFER LOCK             : OFF\n");
	else	seq_printf(proc_show, "MODE SAFER LOCK             : ON\n");


	seq_printf(proc_show, "PROG. LIST SIZE             : %ld\n", global_list_prog_size);
	seq_printf(proc_show, "FOLDER LIST SIZE            : %ld\n", global_list_folder_size);


	seq_printf(proc_show, "PROG. LIST BYTES            : %ld\n", global_list_progs_bytes);
	seq_printf(proc_show, "FOLDER LIST BYTES           : %ld\n", global_list_folders_bytes);


	seq_printf(proc_show, "MODE SEARCH                 : BSEARCH\n");

	seq_printf(proc_show, "HASH SIZE MAX               : %d\n", KERNEL_READ_SIZE);


	seq_printf(proc_show, "\n\n");

	seq_printf(proc_show, "FOLDER:\n\n");



	if (global_list_folder_size != 0) {
		for (n = 0; n < global_list_folder_size; n++) {
			if (global_list_folder[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_folder[n]);
		}
	}

	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "FILES:\n\n");


	if (global_list_prog_size != 0) {
		for (n = 0; n < LIST_MAX; n++) {
			if (global_list_prog[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_prog[n]);
		}
	}


	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "DENY FILES:\n\n");



	if (global_list_deny_size >= 0) {
		for (n = 0; n < DENY_MAX; n++) {
			if (global_list_deny[n] == NULL)
				break;
			seq_printf(proc_show, "%s\n", global_list_deny[n]);
		}
	}



	return 0;
}



//static int __init safer_info_show(void)
//{
	/*
	* Status information is confidential
	* 0 = 0444
	* otherwise octal
	*/
//	proc_create_single("safer.info", 0400, NULL, safer_info_display);
//	return 0;
//}
//fs_initcall(safer_info_show);



/*############################################################### */
static int safer_learning_display(struct seq_file *proc_show, void *v)
{
	long	n;

	seq_printf(proc_show, "INFO LEARNING PROGS\n\n");
	seq_printf(proc_show, "<LEARNING LIST> is organized as a RING\n\n");
	seq_printf(proc_show, "Learning LIST MAX            : %d\n", LEARNING_MAX);
	seq_printf(proc_show, "FILE learning LIST           : %ld\n", global_list_learning_size);


	//if (global_list_learning_size == 0) return;

	for (n = 0; n < LEARNING_MAX; n++) {
		if (global_list_learning[n] == NULL) break;

		seq_printf(proc_show, "%s\n", global_list_learning[n]);
	}


	seq_printf(proc_show, "\n\nARGV:\n");
	seq_printf(proc_show, "<ARGV LEARNING LIST> is organized as a RING\n\n");
	seq_printf(proc_show, "ARGV learning LIST MAX       : %d\n", LEARNING_ARGV_MAX);
	seq_printf(proc_show, "ARGV learning LIST           : %ld\n", global_list_learning_argv_size);


	if (global_list_learning_argv == NULL)
		return 0;

	for (n = 0; n < LEARNING_ARGV_MAX; n++) {
		if (global_list_learning_argv[n] == NULL) break;

		seq_printf(proc_show, "%s\n", global_list_learning_argv[n]);
	}

	return 0;





}



//static int __init safer_learning_show(void)
static int __init safer_init(void)
{
	/*
	* Status information is confidential
	* 0 = 0444
	* otherwise octal
	*/


	register_sysctl_init("kernel/safer", safer_table);

	proc_create_single("safer.info", 0400, NULL, safer_info_display);
	proc_create_single("safer.learning", 0400, NULL, safer_learning_display);
	return 0;
}
late_initcall(safer_init);
//fs_initcall(safer_learning_show);






/* ########################################################################### */

/* Der Notifier-Callback: Wird vom Kernel-Thread aufgerufen */
/*---------------------------------------------------------------------------*/
/* Timer-Task */
/*---------------------------------------------------------------------------*/

static struct workqueue_struct *timer_wq;
static struct delayed_work periodic_work;

static void timer_work_handler(struct work_struct *work)
{

	printk("Hallo Safer\n");

	queue_delayed_work(timer_wq, &periodic_work, 60 * HZ);

}




static int __init pbpb_periodic_timer_init(void)
{
	// Erstellt eine dedizierte Workqueue
	timer_wq = alloc_workqueue("t_wq", WQ_MEM_RECLAIM, 0);
	if (!timer_wq)
		return -ENOMEM;

	INIT_DELAYED_WORK(&periodic_work, timer_work_handler);

	// Initialer Start in der eigenen Queue
	/*queue_delayed_work(timer_wq, &periodic_work, 60 * HZ); */
	queue_delayed_work(timer_wq, &periodic_work, 60 * HZ);

	return 0;
}
late_initcall(pbpb_periodic_timer_init);



//######################################################################################

