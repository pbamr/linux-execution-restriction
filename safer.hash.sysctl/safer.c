/* Copyright (c) 2022/03/28, 2026.09.09, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.03.28, 2026.09.09, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

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
	Date		: 2022.04.22 - 2026.09.09

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 7.2.1

			  Lenovo X230, T460, T470, T490, Fujitsu Futro S xxx, AMD Ryzen
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

#include <linux/sched/signal.h>

#include <linux/acpi.h>
#include <linux/reboot.h>

#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/kdev_t.h>

#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>

#include <linux/freezer.h>
#include <linux/cgroup.h>




#define HOST		0
#define CONTAINER	1


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
#define SHELL_PARAMETER_MAX 16


#define LEARNING_ARGV_MAX 5000
#define LEARNING_MAX 50000
#define LEARNING_KONFIG_MAX 500
#define DENY_MAX 10000

#define LIST_MAX 50000
#define LIST_MIN 1


#define KERNEL_READ_SIZE 5000000

//#define RET_SHELL -1
#define CONTROL_ERROR -1
#define SIZE_ERROR -1


/* sysctl MAX MIN */
typedef int ibool;


/*--------------------------------------------------------------------------------*/
static DEFINE_MUTEX(learning_lock);
static DEFINE_MUTEX(control);
static DEFINE_MUTEX(kernel_read_lock);
static DEFINE_MUTEX(konfig_container_lock);
static DEFINE_MUTEX(konfig_host_lock);


static ibool	learning_mode = true;
static ibool	printk_deny = true;
static ibool	printk_allowed = false;
static ibool	printk_config = false;

static ibool	safer_mode = false;
static ibool	safer_mode_full_check = true;
static ibool	ONLY_SHOW_DENY = false;



static ibool	lock_mode = false;
static ibool	verbose_param_mode = false;
static ibool	verbose_file_unknown = true;


/* programme */
static char	**global_list_prog = NULL;
static long	global_list_prog_size = 0;
static long	global_list_progs_bytes = 0;

/* folder */
static char	**global_list_folder = NULL;
static long	global_list_folder_size = 0;
static long	global_list_folders_bytes = 0;


/* konfig files. which konfig files are check? */
static char	**global_list_host_sconfig_file = NULL;
static long	global_list_host_sconfig_file_size = 0;
static long	global_list_host_sconfig_file_bytes = 0;


/* konfig files check, list. size;hash;path. input */
static char	**global_list_host_config_file_check = NULL;
static long	global_list_host_config_file_check_size = 0;
static long	global_list_host_config_file_check_bytes = 0;


static char	**global_list_konfig_pattern = NULL;
static long	global_list_konfig_pattern_size = 0;
static long	global_list_konfig_pattern_bytes = 0;




/* learning list */
static char	**global_list_learning = NULL;
static long	global_list_learning_size = -1;

/* learning list argumente */
static char	**global_list_learning_argv = NULL;
static long	global_list_learning_argv_size = -1;

/* konfig files learning, list. size;hash;path. out /proc/ */
static char	**global_list_konfig_file_learning = NULL;
static long	global_list_konfig_file_learning_size = -1;




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

/*
 * SECURITY HARD-PATCH: Integrity Enforcement Engine
 *
 * DESIGN-IMPLIKATIONEN (Warum filp_open() verwendet wird):
 * 1. AUTOMATISCHE NAMENSPACE-ISOLATION:
 *    Da filp_open() im Thread-Kontext (current) des Aufrufers ausgefuehrt wird,
 *    loest das Kernel-VFS den Pfad ("/etc/passwd") implizit und vollautomatisch
 *    innerhalb der Mount-/Chroot-Grenzen des jeweiligen Containers auf.
 *    Kein manuelles Namespace-Routing erforderlich.
 *
 * 2. 100% TOCTOU-SICHER (Anti-Time-of-Check-to-Time-of-Use):
 *    Das Path-Walking und der anschließende Zugriff erfolgen komplett ueber die
 *    Kernel-internen RAM-Caches (Dentry- und Inode-Cache). Es wird das fluechtige
 *    In-Memory-Objekt gegriffen, BEVOR Daten auf den physischen Datentraeger
 *    geschrieben werden. Userspace-Prozesse haben keine Chance, den Zeiger
 *    waehrend der Prüfung zu manipulieren.
 *
 * Rueckgabewert: Liefert direkt die fluechtige In-Memory-'size' aus dem VFS-Cache.
 */


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

	shash = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(hash), GFP_ATOMIC);
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









static struct struct_file_info get_file_info_new(const char *fname, ssize_t max)
{

	/*
	  toctou oder page cache vergiftung, ist egal.wird durch hash erkannt
	 */


	void				*data = NULL;
	struct struct_file_info		struct_file_info;
	ssize_t				error;

	/* in inode schreiben */
	struct inode *inode;
	struct path path;

	struct file *file;


	mutex_lock(&kernel_read_lock);

	/* ------------------------------------------------------------------------------------- */
	struct_file_info.file_size = get_file_size(fname);
	if (struct_file_info.file_size == SIZE_ERROR) {
		//struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_lock);
		return struct_file_info;
	}




	/* ------------------------------------------------------------------------------------- */
	error = kern_path(fname, LOOKUP_FOLLOW, &path);
	if (error) {
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_lock);
		return struct_file_info;
	}

	file = dentry_open(&path, O_RDONLY, current_cred());
	path_put(&path); /* dentry_open add own reference */

	if (IS_ERR(file)) {
		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_lock);
		return struct_file_info;
	}

	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode)) {
		struct_file_info.file_size = SIZE_ERROR;
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_lock);
		return struct_file_info;
	}

	if (safer_mode_full_check == false) {
		if (test_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags)) {
			memcpy(struct_file_info.hash_string, inode->i_boettcher_hash, DIGIT * 2);
			struct_file_info.hash_string[DIGIT * 2] = '\0';

			struct_file_info.user_id = get_current_user()->uid.val;
			scnprintf(struct_file_info.str_user_id, sizeof(struct_file_info.str_user_id), "%d", struct_file_info.user_id);

			struct_file_info.file_size = i_size_read(inode);
			scnprintf(struct_file_info.str_file_size, sizeof(struct_file_info.str_file_size), "%ld", struct_file_info.file_size);

			struct_file_info.fname = fname;

			if (printk_allowed == true)
				printk("SAFER: HAS ALREADY BEEN READ      : a:%s;%s;%s;%s\n",
					struct_file_info.str_user_id,
					struct_file_info.str_file_size,
					struct_file_info.hash_string,
					struct_file_info.fname);

			fput(file);

			struct_file_info.retval = true;
			mutex_unlock(&kernel_read_lock);
			return struct_file_info;
		}
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
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_lock);
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
		struct_file_info.retval = false;
		mutex_unlock(&kernel_read_lock);
		return struct_file_info;
	}

	/* ------------------------------------------------------------------------------------- */
	strscpy(struct_file_info.hash_string, struct_hash_sum.hash_string, HASH_STRING_LENGTH);

	memcpy(inode->i_boettcher_hash, struct_file_info.hash_string, DIGIT * 2);

	/* ------------------------------------------------------------------------------------- */

	fput(file);


	if (printk_allowed == true)
		printk("SAFER: FIRST READ                 : a:%s;%s;%s;%s\n",
			struct_file_info.str_user_id,
			struct_file_info.str_file_size,
			struct_file_info.hash_string,
			struct_file_info.fname);


	/* ------------------------------------------------------------------------------------- */
	struct_file_info.retval = true;

	mutex_unlock(&kernel_read_lock);

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
		*list = kzalloc(sizeof(char *) * LEARNING_ARGV_MAX, GFP_ATOMIC);
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


	str_learning = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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
		*list = kzalloc(sizeof(char *) * LEARNING_MAX, GFP_ATOMIC);
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


	str_learning = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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


static void learning_konfig(char *str_learning_konfig,
				char ***list,
				long *list_len)
{

	/* init pointer list*/
	if (*list_len == -1) {
		*list = kzalloc(sizeof(char *) * LEARNING_MAX, GFP_ATOMIC);
		if (*list == NULL) {
			return;
		}
		else *list_len = 0;
	}

	if (search(str_learning_konfig, *list, *list_len) == true) {
		kfree(str_learning_konfig);
		return;
	}

	/* ring buffer = 0, old free */
	if ( (*list)[*list_len] != NULL) {
		kfree((*list)[*list_len]);
	}

	(*list)[*list_len] = str_learning_konfig;

	*list_len += 1;
	// check _len > lerning_max
	if (*list_len > LEARNING_KONFIG_MAX - 1) {
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
		*list = kzalloc(sizeof(char *) * DENY_MAX, GFP_ATOMIC);
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


	str_deny = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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



/*--------------------------------------------------------------------------------*/
static void print_prog_arguments(struct struct_file_info *struct_file_info,
				char **argv,
				long argv_len,
				long org_argv_len)
{

	if (struct_file_info->retval == false) return;

	printk("SAFER: USER ID:%s;%s;%s;%s\n",(*struct_file_info).str_user_id,
		(*struct_file_info).str_file_size,
		(*struct_file_info).hash_string,
		(*struct_file_info).fname);

	printk("SAFER: ORG LEN:%ld\n", org_argv_len);


	for (int n = 0; n < argv_len; n++) {
		/*
		size_hash_sum = get_file_size_hash_read(argv[n], hash_alg, digit);
		printk("argv[%d]:%ld:%s:%s\n", n, size_hash_sum.file_size, size_hash_sum.hash_string, argv[n]);
		*/
		printk("SAFER: argv[%d]:%.1000s\n", n, argv[n]);

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

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "d:*;");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG. DENY: a:%s;%s;%s;%s\n", step, 
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

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "a:*;");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_allowed == true)

			printk("%s USER/PROG ALLOW: a:%s;%s;%s;%s\n", step,
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

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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

			printk("%s USER/PROG ALLOW: a:%s;%s;%s;%s\n", step, 
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

	char *str_folder = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_folder)
		return false;

	strcpy(str_folder, "a:*;");
	strcat(str_folder, struct_file_info->fname);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == true) {
		if (printk_allowed == true)

			printk("%s USER/PROG ALLOW: a:%s;%s;%s;%s\n", step,
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

	char *str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "d:*;");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_folder(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG. DENY: a:%s;%s;%s;%s\n", step,
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

	if (list_len == 0)
		return true;



	char *str_user_file = NULL;



	/* user allowed */
	int string_length = strlen(struct_file_info->str_user_id);
	string_length += strlen(struct_file_info->fname);
	string_length += strlen("d:;") + 1;

	str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_user_file)
		return false;

	strcpy(str_user_file, "d:");
	strcat(str_user_file, struct_file_info->str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->fname);

	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_deny == true)
			printk("%s USER/PROG. DENY: a:%s;%s;%s;%s\n", step,
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

		str_group_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_file)
			return false;

		strcpy(str_group_file, "gd:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->fname);

		if (besearch_file(str_group_file, list, list_len) == true) {
			if (printk_deny == true)
				printk("%s GROUP/PROG DENY: gd:%s;%s;%s;%s\n", step,
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

	str_folder = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_folder)
		return false;

	strcpy(str_folder, "d:");
	strcat(str_folder, struct_file_info->str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, struct_file_info->fname);

	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == true) {
		if (printk_deny == true)

			printk("%s USER/PROG. DENY: a:%s;%s;%s;%s\n", step,
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
		str_group_folder = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_folder)
			return false;

		strcpy(str_group_folder, "gd:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, struct_file_info->fname);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == true) {
			if (printk_deny == true)

				printk("%s GROUP/PROG DENY: gd:%s;%s;%s;%s\n", step,
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

	str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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

			printk("%s USER/PROG ALLOW: a:%s;%s;%s;%s\n", step,
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
		str_group_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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

				printk("%s GROUP/PRG ALLOW: ga:%s;%s;%s;%s\n", step,
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

	str_folder = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (!str_folder) return false;

	strcpy(str_folder, "a:");
	strcat(str_folder, struct_file_info->str_user_id);
	strcat(str_folder, ";");
	strcat(str_folder, struct_file_info->fname);
	/* Importend! Need qsorted list */
	if (besearch_folder(str_folder, list, list_len) == true) {
		if (printk_allowed == true)

			printk("%s USER/PROG ALLOW: a:%s;%s;%s;%s\n", step,
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
		str_group_folder = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_folder)
			return false;

		strcpy(str_group_folder, "ga:");
		strcat(str_group_folder, str_group_id);
		strcat(str_group_folder, ";");
		strcat(str_group_folder, struct_file_info->fname);


		/* Importend! Need qsorted list */
		if (besearch_folder(str_group_folder, list, list_len) == true) {
			if (printk_allowed == true)

				printk("%s GROUP/PRG ALLOW: ga:%s;%s;%s;%s\n", step,
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

	str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
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

			printk("%s USER/PROG ALLOW: ai:%s;%s;%s;%s\n", step,
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
user_shell_allowed(struct struct_file_info *struct_file_info,
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
	string_length += strlen("as:;;;") + 1;

	str_user_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
	if (str_user_file == NULL)
		return false;

	strcpy(str_user_file, "as:");
	strcat(str_user_file, struct_file_info->str_user_id);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->str_file_size);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->hash_string);
	strcat(str_user_file, ";");
	strcat(str_user_file, struct_file_info->fname);


	if (besearch_file(str_user_file, list, list_len) == true) {
		if (printk_allowed == true)

			printk("%s USER/SHELL ALLOW: as:%s;%s;%s;%s\n", step,
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
		string_length += strlen("gas:;;;") +1;

		//if (str_group_file != NULL) kfree(str_group_file);
		str_group_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_file)
			return false;

		strcpy(str_group_file, "gas:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->hash_string);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->fname);

		if (besearch_file(str_group_file, list, list_len) == true) {
			if (printk_allowed == true)

				printk("%s GROUP/SHELL ALLOW: gas:%s;%s;%s;%s\n", step,
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
group_shell_allowed(struct struct_file_info *struct_file_info,
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
		string_length += strlen("gas:;;;") +1;

		//if (str_group_file != NULL) kfree(str_group_file);
		str_group_file = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
		if (!str_group_file)
			return false;

		strcpy(str_group_file, "gas:");
		strcat(str_group_file, str_group_id);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->str_file_size);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->hash_string);
		strcat(str_group_file, ";");
		strcat(str_group_file, struct_file_info->fname);

		if (besearch_file(str_group_file, list, list_len) == true) {
			if (printk_allowed == true)

				printk("%s GROUP/PRG SHELL: gas:%s;%s;%s;%s\n", step,
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
			if (user_shell_allowed(struct_file_info,
						list,
						list_len,
						step) == false)
				if (group_shell_allowed(struct_file_info,
							list,
							list_len,
							step) == false)
					return false;


	/*--------------------------------------------------------------------------------*/
	/*
	if (printk_deny == true)
		printk("%s SHELL: USER/SCRIPT: check a:%s;%s;%s;%s\n", step,
			struct_file_info->str_user_id,
			struct_file_info->str_file_size,
			struct_file_info->hash_string,
			struct_file_info->fname);
	*/


	/*--------------------------------------------------------------------------------*/
	/* Feststellen ob shell */
	char *user_shell_string = kasprintf(GFP_ATOMIC, "as:%s;%s;%s;%s",struct_file_info->str_user_id,
									struct_file_info->str_file_size,
									struct_file_info->hash_string,
									struct_file_info->fname);

	char *group_shell_string = kasprintf(GFP_ATOMIC, "gas:%s;%s;%s;%s",struct_file_info->str_user_id,
									struct_file_info->str_file_size,
									struct_file_info->hash_string,
									struct_file_info->fname);

	if (besearch_file(user_shell_string, list, list_len) == true ||
		besearch_file(group_shell_string, list, list_len) == true) {

			/* ab hier in jedem fall shell */
			/* inline code pruefen */
			kfree(user_shell_string);
			kfree(group_shell_string);


	/*--------------------------------------------------------------------------------*/
			/* wichtig wenn nur interaktiv. zb einfach nur bash */
			if (argv_len == 1)
				return true;

	/*--------------------------------------------------------------------------------*/
			/* wenn mehr parameter -> pech */
			if (argv_len >= SHELL_PARAMETER_MAX) {
				return false;
			}

	/*--------------------------------------------------------------------------------*/
			if (global_list_konfig_pattern_size == 0)
				return false;


	/*--------------------------------------------------------------------------------*/
			/* baue string */
			/* ab argument 1 */
			int string_length = strlen(struct_file_info->fname) + 1;

			//if (argv_len > 10) argv_len = 10;
			for (int n = 1; n < argv_len; n++) {
				string_length += strlen(argv[n]);
				string_length += sizeof(":");
			}

			char *str_check = kzalloc(string_length * sizeof(char), GFP_ATOMIC);
			if (!str_check)
				return false;

			strcpy(str_check, struct_file_info->fname);
			strcat(str_check, ":");

			for (int n = 1; n < argv_len; n++) {
				strcat(str_check, argv[n]);
				strcat(str_check, ":");
			}

			char *pos = str_check;
			char *schalter_start;

			/* Suche das " :- " -> Das ist der Beginn eines Arguments */
			while ((schalter_start = strstr(pos, ":-")) != NULL) {

				/* Springe hinter den Doppelpunkt (schalter_start zeigt jetzt auf das '-')  */
				schalter_start++; 
				/* Suche das Ende dieses Arguments (den naechsten Doppelpunkt) */
				char *schalter_ende = strchr(schalter_start, ':');

				if (!schalter_ende) {
					kfree(str_check);
					return true; /* Abbruch, falls der String unvollstaendig ist */
				}

				/* Pruefe, ob das 'c' in diesem isolierten Schalter-Argument steckt */
				/* (Erkennt zuverlassig -c, -ac, -cc, etc.) */
				if (memchr(schalter_start, 'c', schalter_ende - schalter_start) != NULL) {
					/* Treffer! Das -c aktiv. */
					/* restlichen Text (ab schalter_ende) */
					for (int n = 0; n <  global_list_konfig_pattern_size; n++) {
						if (global_list_konfig_pattern[n] != NULL) {
							if (strstr(schalter_ende, global_list_konfig_pattern[n]) != NULL) {

								if (printk_deny == true)
									printk("SAFER: STEP FIRST: DENY SHELL INLINE  : %s\n", str_check);

								kfree(str_check);
								return false; /* Gefunden */
							}
						}
					}

					/* Da das aktive -c gefunden, Suche ende */
					/*  Danach egal */
					if (printk_allowed == true)
						printk("SAFER: STEP FIRST: ALLOWED SHELL INLINE  : %s\n", str_check);

					kfree(str_check);
					return true;
				}

				/*
				  Wenn kein 'c' in diesem Argument war (z.B. bei ':-a:'),
				  suche ab dem aktuellen Doppelpunkt weiter nach dem naechsten Argument.
				*/
				pos = schalter_ende;
			}

			/* kein -c gefunden */
			if (printk_allowed == true)
				printk("SAFER: STEP FIRST: ALLOWED SHELL INLINE  : %s\n", str_check);

			kfree(str_check);
			return true;
	}

	kfree(user_shell_string);
	kfree(group_shell_string);



//bearbeiten
//jedes argument pruefen


	/*--------------------------------------------------------------------------------*/
	/* java ? */
	/* if not bash */
	if (argv_len == 1)
		return false;


	struct struct_file_info struct_param_info;

	/* java */
	if (strncmp(argv[1], "-jar", sizeof("-jar")) == 0) {
		if (argv_len != 3) return false;


		struct_param_info = get_file_info_new(argv[2], KERNEL_READ_SIZE);


		/* error: read, hash. back to kernel */
		if (struct_param_info.retval == false) {
			if (printk_deny == true)
				printk("SAFER: STEP FIRST: PROG. UNKNOWN  : a:%d;;;%s\n",
					struct_param_info.user_id,
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

		deny_list(&struct_param_info,
			&global_list_deny,
			&global_list_deny_size);


		return false;

	}


	/* java */
	if (strncmp(argv[1], "-classpath", sizeof("-classpath")) == 0) {
		if (argv_len != 4) return false;

		long str_length;
		str_length = strlen(argv[2]);
		str_length += strlen(argv[3]);
		str_length += strlen("/.class") + 1;

		char *str_class_name = kzalloc(str_length * sizeof(char), GFP_ATOMIC);
		if (str_class_name == NULL) return false;

		strcpy(str_class_name, argv[2]);
		strcat(str_class_name, "/");
		strcat(str_class_name, argv[3]);
		strcat(str_class_name, ".class");


		struct_param_info = get_file_info_new(str_class_name, KERNEL_READ_SIZE);
		/* error: read, hash. back to kernel */
		if (struct_param_info.retval == false) {
			if (printk_deny == true)
				printk("SAFER: STEP FIRST: PROG. UNKNOWN  : a:%s;;;%s\n",
					struct_param_info.str_user_id,
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

		deny_list(&struct_param_info,
			&global_list_deny,
			&global_list_deny_size);

		kfree(str_class_name);

		return false;
	}


	/* other */
	struct struct_file_info struct_other_file_info = get_file_info_new(argv[1], KERNEL_READ_SIZE);
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
		printk("%s USER/SCRIPT DENY   : a:%s;%s;%s;%s\n", step,
			struct_other_file_info.str_user_id,
			struct_other_file_info.str_file_size,
			struct_other_file_info.hash_string,
			struct_other_file_info.fname);

	deny_list(&struct_other_file_info,
		&global_list_deny,
		&global_list_deny_size);

	/* not found */
	return false;
}




/*--------------------------------------------------------------------------------*/
static bool exec_first_step(struct struct_file_info *struct_file_info,
			    char **argv,
			    long argv_len)
{


	if (safer_mode == false)
		if (learning_mode == false)
			return true;


	/* deny wildcard folder */
	if (user_wildcard_folder_deny(	struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"SAFER: STEP FIRST:") == false)
		return false;


/* wildcard deny user */
	if (user_wildcard_deny(	struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"SAFER: STEP FIRST:") == false)
		return false;

	/* group deny folder */
	if (group_folder_deny(	struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP FIRST:") == false)
		return false;

	/* deny group */
	/* if global_list_prog_size = 0, safer_mode not true */
	if (group_deny(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP FIRST:") == false)
		return false;

	/* deny folder */
	if (user_folder_deny(struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP FIRST:") == false)
		return false;

	/* deny user */
	if (user_deny(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP FIRST:") == false)
		return false;

/*--------------------------------------------------------------------------------*/

	/* user wildcard allowed folder */
	if (user_wildcard_folder_allowed(struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"SAFER: STEP FIRST:") == true)
		return true;

	/* user wildcard allowed filename */
	if (user_wildcard_filename_allowed(struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"SAFER: STEP FIRST:") == true)
		return true;


	/* all wildcard user */
	if (user_wildcard_allowed(struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"SAFER: STEP FIRST:") == true)
		return true;

	/* group allowed folder */
	if (group_folder_allowed(struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP FIRST:") == true)
		return true;

	/* allowed group */
	if (group_allowed(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP FIRST:") == true)
		return true;

	/* user allowed folder */
	if (user_folder_allowed(struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP FIRST:") == true)
		return true;

	/* allowed user */
	if (user_allowed(struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP FIRST:") == true)
		return true;

	/* user allowed interpreter and allowed group script file*/
	/* 0 allowed */
	/* -1 deny */
	if (param_file(struct_file_info,
			argv,
			argv_len,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP FIRST:") == true)
		return true;

	if (printk_deny == true)
		printk("SAFER: STEP FIRST: USER/PROG. DENY: a:%s;%s;%s;%s\n",
			struct_file_info->str_user_id,
			struct_file_info->str_file_size,
			struct_file_info->hash_string,
			struct_file_info->fname);

	//deny_list(&struct_file_info,
	//	&global_list_deny,
	//	&global_list_deny_size);


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

			printk("SAFER: STEP SEC  : PROG. UNKNOWN  : a:%d;;;%s\n",
				get_current_user()->uid.val,
				filename);

		global_statistics_execve_path_wrong_counter++;
		return true;
	}


	if (safer_mode == false)
		if (learning_mode == false)
			return true;


	bool retval;
	struct struct_file_info struct_file_info;


	struct_file_info = get_file_info_new(filename, KERNEL_READ_SIZE);

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
					"SAFER: STEP SEC  :");
	if (retval == false) goto not_allowed;




/*-------------------------------------------------------------------------------------------*/

	/* deny wildcard user */
	retval = user_wildcard_deny(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"SAFER: STEP SEC  :");
	if (retval == false) goto not_allowed;


/*-------------------------------------------------------------------------------------------*/

	/* group deny folder */
	retval = group_folder_deny(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* deny group */
	/* if global_list_prog_size = 0, safer_mode not true */
	retval = group_deny(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* deny folder */
	retval = user_folder_deny(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* deny user */
	retval = user_deny(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP SEC  :");
	if (retval == false) goto not_allowed;

/*-------------------------------------------------------------------------------------------*/

	/* allowed wildcard folder */
	if (user_wildcard_folder_allowed(&struct_file_info,
					global_list_folder,
					global_list_folder_size,
					"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}



	/* user wildcard allowed filename */
	if (user_wildcard_filename_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}





	/* allowed wildcard user */
	if (user_wildcard_allowed(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* group allowed folder */
	if (group_folder_allowed(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* allowed group */
	if (group_allowed(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* allowed user folder */
	if (user_folder_allowed(&struct_file_info,
				global_list_folder,
				global_list_folder_size,
				"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* allowed user */
	if (user_allowed(&struct_file_info,
			global_list_prog,
			global_list_prog_size,
			"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* group allowed interpreter */
	if (group_interpreter_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* user allowed interpreter */
	if (user_interpreter_allowed(&struct_file_info,
					global_list_prog,
					global_list_prog_size,
					"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* group allowed interpreter */
	if (group_shell_allowed(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	/* user allowed interpreter */
	if (user_shell_allowed(&struct_file_info,
				global_list_prog,
				global_list_prog_size,
				"SAFER: STEP SEC  :") == true) {
		global_statistics_execve_allow_counter++;
		return true;
	}

	if (printk_deny == true) {

		printk("SAFER: STEP SEC  : USER/PROG. DENY: a:%s;%s;%s;%s\n",
			struct_file_info.str_user_id,
			struct_file_info.str_file_size,
			struct_file_info.hash_string,
			struct_file_info.fname);
	}

	if (mutex_trylock(&learning_lock)) {
		deny_list(&struct_file_info,
			&global_list_deny,
			&global_list_deny_size);

		mutex_unlock(&learning_lock);
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
static bool check_etc_passwd(void)
{
	struct		file *konf_file;
	char		*buffer;
	char		*line;
	char		*next_line;
	loff_t		pos = 0;
	ssize_t		bytes_read;


	ssize_t KONFIG_FILE_SIZE = get_file_size("/etc/passwd");

	// Oeffnet die Datei im Namespace des ausloesenden Prozesses
	konf_file = filp_open("/etc/passwd", O_RDONLY | O_NONBLOCK, 0);
	if (IS_ERR(konf_file)) {
		//force_sig(SIGKILL);
		return true;
	}

	buffer = kmalloc(KONFIG_FILE_SIZE, GFP_ATOMIC);
	if (!buffer) {
		fput(konf_file);
		return true;
	}

	bytes_read = kernel_read(konf_file, buffer, KONFIG_FILE_SIZE, &pos);
	fput(konf_file); // Datei-Referenz sofort nach dem Lesen im Kernel freigeben

	if (bytes_read <= 0) {
		kfree(buffer);
		return true;
	}

	buffer[bytes_read - 1] = '\0';


	next_line = buffer;

	while ((line = strsep(&next_line, "\n")) != NULL) {

		if (strlen(line) == 0)
			continue;

		char *username = strsep(&line, ":");

		char *password = strsep(&line, ":");

		char *uid_str  = strsep(&line, ":");

		if (!username || !password || !uid_str)
			continue;

		if (strcmp(uid_str, "0") == 0 && strcmp(username, "root") != 0) {

			if (printk_deny == true) {
				printk("SAFER: CONTAINER: FILE: /etc/passwd, CORRUPT\n");
				printk("SAFER: %s:x:%s\n", username, uid_str);
			}

			kfree(buffer);
			return false;
		}
	}

	kfree(buffer);
	return true;

}






/*--------------------------------------------------------------------------------*/
static bool check_etc_group_0(void)
{
	struct file	*konf_file;
	char		*buffer;
	char		*line;
	char		*next_line;
	loff_t		pos = 0;
	ssize_t		bytes_read;

	ssize_t KONFIG_FILE_SIZE = get_file_size("/etc/group");

	// Oeffnet die Datei im Namespace des ausloesenden Prozesses
	konf_file = filp_open("/etc/group", O_RDONLY | O_NONBLOCK, 0);
	if (IS_ERR(konf_file)) {
		return true;
	}

	buffer = kmalloc(KONFIG_FILE_SIZE, GFP_ATOMIC);
	if (!buffer) {
		fput(konf_file);
		return true;
	}

	bytes_read = kernel_read(konf_file, buffer, KONFIG_FILE_SIZE, &pos);
	fput(konf_file); // Datei-Referenz sofort nach dem Lesen im Kernel freigeben

	if (bytes_read <= 0) {
		kfree(buffer);
		return true;
	}

	buffer[bytes_read - 1] = '\0';

	next_line = buffer;

	// Pruefen, ob die Zeile exakt mit der legitimen Root-Gruppe beginnt, keine zusaetzliche user
	while ((line = strsep(&next_line, "\n")) != NULL) {

		if (strlen(line) == 0)
			continue;

		if (strncmp(line, "root:x:0:", 9) == 0) {

			if (strlen(line) > 9) {
				if (printk_deny == true) {
					printk("SAFER: CONTAINER: FILE: /etc/group, CORRUPT\n");
					printk("SAFER: %s\n", line);
				}

				kfree(buffer);
				return false;
			}
		}
	}

	kfree(buffer);
	return true;

}


static bool check_etc_group_1(void)
{
	struct		file *konf_file;
	char		*buffer;
	char		*line;
	char		*next_line;
	loff_t		pos = 0;
	ssize_t		bytes_read;


	ssize_t KONFIG_FILE_SIZE = get_file_size("/etc/group");

	// Oeffnet die Datei im Namespace des ausloesenden Prozesses
	konf_file = filp_open("/etc/group", O_RDONLY | O_NONBLOCK, 0);
	if (IS_ERR(konf_file)) {
		return true;
	}

	buffer = kmalloc(KONFIG_FILE_SIZE, GFP_ATOMIC);
	if (!buffer) {
		fput(konf_file);
		return true;
	}

	bytes_read = kernel_read(konf_file, buffer, KONFIG_FILE_SIZE, &pos);
	fput(konf_file); // Datei-Referenz sofort nach dem Lesen im Kernel freigeben

	if (bytes_read <= 0) {
		kfree(buffer);
		return true;
	}

	buffer[bytes_read - 1] = '\0';


	next_line = buffer;

	while ((line = strsep(&next_line, "\n")) != NULL) {

		if (strlen(line) == 0)
			continue;

		char *groupname = strsep(&line, ":");

		char *password = strsep(&line, ":");

		char *guid_str  = strsep(&line, ":");

		if (!groupname || !password || !guid_str)
			continue;

		if (strcmp(guid_str, "0") == 0 && strcmp(groupname, "root") != 0) {

			if (printk_deny == true) {
				printk("SAFER: CONTAINER: FILE: /etc/group, CORRUPT\n");
				printk("SAFER: %s:x:%s\n", groupname, guid_str);
			}

			kfree(buffer);
			return false;
		}
	}

	kfree(buffer);

	return true;

}



static bool check_etc_shadow(void)
{
	struct		file *konf_file;
	char		*buffer;
	loff_t		pos = 0;
	ssize_t		bytes_read;


	ssize_t KONFIG_FILE_SIZE = get_file_size("/etc/shadow");

	// Oeffnet die Datei im Namespace des ausloesenden Prozesses
	konf_file = filp_open("/etc/shadow", O_RDONLY | O_NONBLOCK, 0);
	if (IS_ERR(konf_file)) {
		return true;
	}

	buffer = kmalloc(KONFIG_FILE_SIZE, GFP_ATOMIC);
	if (!buffer) {
		fput(konf_file);
		return true;
	}

	bytes_read = kernel_read(konf_file, buffer, KONFIG_FILE_SIZE, &pos);
	fput(konf_file); // Datei-Referenz sofort nach dem Lesen im Kernel freigeben

	if (bytes_read <= 0) {
		kfree(buffer);
		return true;
	}

	buffer[bytes_read - 1] = '\0';


	if (	strstr(buffer, "root:*:") != NULL ||
		strstr(buffer, "root:!") != NULL) {
			kfree(buffer);
			return true;
	}

	if (printk_deny == true) {
		printk("SAFER: CONTAINER: FILE: /etc/shadow, CORRUPT\n");
	}

	kfree(buffer);
	return false;

}



static bool check_etc_gshadow(void)
{
	struct		file *konf_file;
	char		*buffer;
	loff_t		pos = 0;
	ssize_t		bytes_read;


	ssize_t KONFIG_FILE_SIZE = get_file_size("/etc/gshadow");

	// Oeffnet die Datei im Namespace des ausloesenden Prozesses
	konf_file = filp_open("/etc/gshadow", O_RDONLY | O_NONBLOCK, 0);
	if (IS_ERR(konf_file)) {
		return true;
	}

	buffer = kmalloc(KONFIG_FILE_SIZE, GFP_ATOMIC);
	if (!buffer) {
		fput(konf_file);
		return true;
	}

	bytes_read = kernel_read(konf_file, buffer, KONFIG_FILE_SIZE, &pos);
	fput(konf_file); // Datei-Referenz sofort nach dem Lesen im Kernel freigeben

	if (bytes_read <= 0) {
		kfree(buffer);
		return true;
	}

	buffer[bytes_read - 1] = '\0';


	if (	strstr(buffer, "root:*::") != NULL ||
		strstr(buffer, "root:!::") != NULL) {
			kfree(buffer);
			return true;
	}

	if (printk_deny == true) {
		printk("SAFER: CONTAINER: FILE: /etc/gshadow, CORRUPT\n");
	}

	kfree(buffer);
	return false;

}




static int get_kontext(const char *filename)
{
	if (current->cgroups) {
		struct cgroup *cgrp = current->cgroups->dfl_cgrp;

		if (cgrp) {
			/* systemd slic, container */
			if (cgroup_parent(cgrp) != NULL) {
				/* container check, virtualisiertem Cgroup-Namespace */
				if (current->nsproxy && current->nsproxy->cgroup_ns != &init_cgroup_ns) {
					return CONTAINER;
				}

				// HOST */
				return HOST;
			}
			/* Wenn cgroup_parent == NULL, sind wir auf der obersten Host-Ebene. */
			else {
				//printk(KERN_EMERG "HOSST: PID: %d %s\n", current->pid, filename);
				return HOST;
			}
		}
	}

	// Legacy
	// Keine cgroups aktiv (z.B. per Bootparameter)
	// container (Fallback ohne cgroups)
	//if (task_active_pid_ns(current) != &init_pid_ns) {
	//	return CONTAINER;
	//}

	if (current->nsproxy->mnt_ns == init_task.nsproxy->mnt_ns) {
		return HOST;	// HOST
	}

	return CONTAINER;	// container
}






/*--------------------------------------------------------------------------------*/
static bool allowed_exec(const char *filename,
			struct user_arg_ptr argv)
{


	if (system_state < SYSTEM_RUNNING)
		return true;


	/*-------------------------------------------------------------------------- */
	//try_to_freeze();
	//if (freezing(current) || pm_freezing)
	//	return true;
	/*-------------------------------------------------------------------------- */


	global_statistics_execve_counter++;


	const char __user	*str;
	char			**argv_list = NULL;
	long			argv_list_len = 0;
	long			str_len;
	bool			retval;
	long			org_argv_list_len = 0;
	int			kontext = 0;


	/*-------------------------------------------------------------------------- */
	/* Nur einmal */
	if (KERNEL_SIZE == 0) {
		/* 
		 * GFP_ATOMIC: Der Standard-Flag fuer Speicherallokation im Prozess-Kontext.
		 * Erlaubt dem Kernel zu schlafen, falls gerade kein RAM frei ist.
		 * Linux Kernel Pfad bauen. vmlinuz-
		*/
		
		KERNEL_PATH = kasprintf(GFP_ATOMIC, "/boot/vmlinuz-%s", utsname()->release);

		if (KERNEL_PATH) {
			struct struct_file_info struct_kernel_file_info = get_file_info_new(KERNEL_PATH, 500000000);
			if (struct_kernel_file_info.retval == true) {
				KERNEL_SIZE = struct_kernel_file_info.file_size;
				strcpy(KERNEL_HASH, struct_kernel_file_info.hash_string);

				printk("KERNEL INFO  : %s\n", KERNEL_PATH);
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

			printk("SAFER: STEP FIRST: PROG. UNKNOWN  : a:%d;;;%s\n",
				get_current_user()->uid.val,
				filename);

		global_statistics_execve_path_wrong_counter++;
		return true;
	}



	if (safer_mode == false)
		if (learning_mode == false)
			return true;




	/*-------------------------------------------------------------------------- */
	kontext = get_kontext(filename);


	/* container kontext */
	/* pruefe semantisch */
	if (kontext == CONTAINER) {
//printk(KERN_EMERG "kontext container\n");
		if (safer_mode == true) {

			if (mutex_trylock(&konfig_container_lock)) {

				if (printk_config == true) {
					printk("SAFER: CONTAINER: FILE: /etc/passw, SIZE: %ld\n", get_file_size("/etc/passwd"));
				}

				if (check_etc_passwd() == false) {
					mutex_unlock(&konfig_container_lock);
					if (ONLY_SHOW_DENY == false)
						return false;
				}

				if (check_etc_group_0() == false) {
					mutex_unlock(&konfig_container_lock);
					if (ONLY_SHOW_DENY == false)
						return false;
				}

				if (check_etc_group_1() == false) {
					mutex_unlock(&konfig_container_lock);
					if (ONLY_SHOW_DENY == false)
						return false;
				}

				if (check_etc_shadow() == false) {
					mutex_unlock(&konfig_container_lock);
					if (ONLY_SHOW_DENY == false)
						return false;
				}

				if (check_etc_gshadow() == false) {
					mutex_unlock(&konfig_container_lock);
					if (ONLY_SHOW_DENY == false)
						return false;
				}

				mutex_unlock(&konfig_container_lock);
			}
		}
	}


	/*-------------------------------------------------------------------------- */
	/* einlesen der Konfig Dateien, und Hash bilden */
	/* HOST */

	if (kontext == HOST && global_list_host_sconfig_file_size > 0 && strstr(filename, "/proc/") == NULL) {

		if (mutex_trylock(&konfig_host_lock)) {
			for (int n = 0; n < global_list_host_sconfig_file_size; n++) {

				struct		file *file;
				char		*buffer;
				loff_t		pos = 0;
				ssize_t		bytes_read;

				ssize_t FILE_SIZE = get_file_size(global_list_host_sconfig_file[n]);

				if (FILE_SIZE == SIZE_ERROR) {
					mutex_unlock(&konfig_host_lock);
					goto skonfig_fail_out;
				}

				// Oeffnet die Datei im Namespace des ausloesenden Prozesses
				file = filp_open(global_list_host_sconfig_file[n], O_RDONLY | O_NONBLOCK, 0);
				if (IS_ERR(file)) {
					mutex_unlock(&konfig_host_lock);
					goto skonfig_fail_out;
				}

				buffer = kmalloc(FILE_SIZE, GFP_ATOMIC);
				if (!buffer) {
					fput(file);
					mutex_unlock(&konfig_host_lock);
					goto skonfig_fail_out;
				}


				bytes_read = kernel_read(file, buffer, FILE_SIZE, &pos);
				fput(file); // Datei-Referenz sofort nach dem Lesen im Kernel freigeben

				if (bytes_read <= 0) {
					kfree(buffer);
					mutex_unlock(&konfig_host_lock);
					goto skonfig_fail_out;
				}


				struct struct_hash_sum struct_hash_sum = get_hash_sum(buffer, bytes_read);
				kfree(buffer);

				if (struct_hash_sum.retval == false) {
					mutex_unlock(&konfig_host_lock);
					goto skonfig_fail_out;
				}

				if (printk_config == true)
					printk("SAFER: HOST-KONFIG: %ld;%s;%s, %s\n", FILE_SIZE, struct_hash_sum.hash_string, global_list_host_sconfig_file[n], filename);


				if (learning_mode == true) {
					/* works too */
					/* muss hier nicht wieder freigegeben werden werden */
					char *str_learning_konfig = kasprintf(GFP_ATOMIC, "KONFIG:%ld;%s;%s",
									FILE_SIZE,
									struct_hash_sum.hash_string,
									global_list_host_sconfig_file[n]);

						learning_konfig(str_learning_konfig,
								&global_list_konfig_file_learning,
								&global_list_konfig_file_learning_size);
					}


				if (safer_mode == true) {
					char *str_konfig_check = kasprintf(GFP_ATOMIC, "KONFIG:%ld;%s;%s",
									FILE_SIZE,
									struct_hash_sum.hash_string,
									global_list_host_sconfig_file[n]);

					if (besearch_file(str_konfig_check, global_list_host_config_file_check, global_list_host_config_file_check_size) == true) {
						kfree(str_konfig_check);

						if (printk_config == true)
							printk("SAFER: HOST-KONFIG: FILE OK: %s\n", str_konfig_check);

					}
					else {
						if (printk_deny == true)
							printk("SAFER: HOST-KONFIG: FILE ERROR: %s\n", str_konfig_check);

						kfree(str_konfig_check);
						mutex_unlock(&konfig_host_lock);

						if (ONLY_SHOW_DENY == false) {
							//flush_all_drives();
							/* sicher keine gefahr fuer ftl */
							emergency_sync();
							emergency_restart();
						}
					}
				}
			}

			mutex_unlock(&konfig_host_lock);
		}
	}


skonfig_fail_out:


//printk(KERN_EMERG "nach skonfig\n");

	/*-------------------------------------------------------------------------- */
	/* lesen */
	struct struct_file_info struct_file_info = get_file_info_new(filename, KERNEL_READ_SIZE);

	/* error: read, hash. back to kernel */
	if (struct_file_info.retval == false)
		return true;

	/*-------------------------------------------------------------------------- */
	/* NOTICE long Para. */
	argv_list_len = count(argv, MAX_ARG_STRINGS);
	org_argv_list_len = argv_list_len;

/*
	parameter pruefen. zeichen max.
	if ((printk_allowed == true) || (printk_deny == true)) {
		for (int n = 0; n < argv_list_len; n++) {
			str = get_user_arg_ptr(argv, n);
			str_len = strnlen_user(str, MAX_ARG_STRLEN);
			if (str_len > 10000) {

				printk("SAFER: STEP FIRST: NOTICE: PROG.  : %s, ARGV:[%d], LENGTH:[%ld] > 5000\n",
					filename,
					n,
				str_len);
			}
		}
	}
*/

	/*-------------------------------------------------------------------------- */
	/* argv -> kernel space */
	/* NOT ALL argv */
	if (argv_list_len > ARGV_MAX)
		argv_list_len = ARGV_MAX;


	/* Init List */
	argv_list = kzalloc(argv_list_len * sizeof(char *), GFP_ATOMIC);
	if (!argv_list) {
		return false;
	}

	for (int n = 0; n < argv_list_len; n++) {
		/*Address User String */
		str = get_user_arg_ptr(argv, n);
		str_len = strnlen_user(str, MAX_ARG_STRLEN);

		argv_list[n] = kzalloc((str_len + 1) * sizeof(char), GFP_ATOMIC);
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
		if (mutex_trylock(&learning_lock)) {
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
static int proc_safer_full_check(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (safer_mode_full_check == true) {
			printk("SAFER: MODE: SAFER FULL CHECK ON\n");
		}
		else {
			printk("SAFER: MODE: SAFER FULL CHECK OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}


ibool safer_mode_temp;
static int proc_safer_active(	const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	if (global_list_host_config_file_check == NULL) {
		safer_mode = false;
		printk("MODE: SAFER EROR\n");
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	if (global_list_prog == NULL) {
		safer_mode = false;
		printk("MODE: SAFER EROR\n");
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {

		if (safer_mode_temp == true) {
			safer_mode = true;
			printk("SAFER: MODE: SAFER PROG. ON\n");
		}
		else {
			safer_mode = false;
			printk("SAFER: MODE: SAFER PROG. OFF\n");
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
			printk("SAFER: MODE: SAFER PRINTK DENY ON\n");
		}
		else {
			printk("SAFER: MODE: SAFER PRINTK DENY OFF\n");
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
			printk("SAFER: MODE: SAFER PRINTK ALLOWED ON\n");
		}
		else {
			printk("SAFER: MODE: SAFER PRINTK ALLOWED OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}


static int proc_safer_printk_config(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true) return CONTROL_ERROR;

	if (!mutex_trylock(&control)) return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (printk_config == true) {
			printk("SAFER: MODE: SAFER PRINTK CONFIG ALLOWED ON\n");
		}
		else {
			printk("SAFER: MODE: SAFER PRINTK CONFIG ALLOWED OFF\n");
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
			printk("SAFER: MODE: learning ON\n");
		}
		else {
			printk("SAFER: MODE: learning OFF\n");
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
			printk("SAFER: MODE: NO MORE CHANGES ALLOWED\n");
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
			printk("SAFER: MODE: SAFER PRINTK ONLY SHOW DENY ON\n");
		}
		else {
			printk("SAFER: MODE: SAFER PRINTK ONLY SHOW DENY OFF\n");
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
			printk("SAFER: MODE: verbose parameter mode ON\n");
		}
		else {
			printk("SAFER: MODE: verbose parameter mode OFF\n");
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
			printk("SAFER: MODE: SAFER PRINTK VERBOSE UNKNOWN FILE ON\n");
		}
		else {
			printk("SAFER: MODE: SAFER PRINTK VERBOSE UNKNOWN FILE OFF\n");
		}
	}

	mutex_unlock(&control);

	return retval;
}





static char safer_prog_string[PATH_MAX];
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
			printk("SAFER: FREE list_prog_temp, %ld, %ld\n",
				list_prog_start, list_prog_size );

			for (int n = 0; n < list_prog_start; n++) {
				if (list_prog_temp[n] != NULL) {
					kfree(list_prog_temp[n]);
					list_prog_temp[n] = NULL;
				}
			}
			kfree(list_prog_temp);
			list_prog_temp = NULL;
		}


		list_prog_temp = kzalloc(list_prog_size_temp * sizeof(char *), GFP_ATOMIC);
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
	list_prog_temp[list_prog_start] = kzalloc((str_len + 1) * sizeof(char), GFP_ATOMIC);

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

		printk("SAFER: FILE LIST ELEMENTS: %ld\n", global_list_prog_size);
		printk("SAFER: FILE LIST BYTES   : %ld\n", global_list_progs_bytes);

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



static char safer_konfig_pattern_string[PATH_MAX];
static long list_konfig_pattern_size;
static long list_konfig_pattern_start = -1;
static long list_konfig_pattern_bytes;
static char **list_konfig_pattern_temp = NULL;
static int proc_safer_konfig_pattern(const struct ctl_table *table,
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
	long list_konfig_pattern_size_temp = 0;
	retval = kstrtol(safer_konfig_pattern_string, 10, &list_konfig_pattern_size_temp);
	if (retval == 0) {
		if (list_konfig_pattern_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_konfig_pattern_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_konfig_pattern_start != -1) {
			printk("SAFER: FREE list_konfig_pattern_temp, %ld, %ld\n",
				list_konfig_pattern_start, list_konfig_pattern_size );

			for (int n = 0; n < list_konfig_pattern_start; n++) {
				if (list_konfig_pattern_temp[n] != NULL) {
					kfree(list_konfig_pattern_temp[n]);
					list_konfig_pattern_temp[n] = NULL;
				}
			}
			kfree(list_konfig_pattern_temp);
			list_konfig_pattern_temp = NULL;
		}


		list_konfig_pattern_temp = kzalloc(list_konfig_pattern_size_temp * sizeof(char *), GFP_ATOMIC);
		/* Create not ok */
		if (list_konfig_pattern_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_konfig_pattern_size = list_konfig_pattern_size_temp;
		list_konfig_pattern_start = 0;
		list_konfig_pattern_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}


	if (list_konfig_pattern_start == -1) { 
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	int str_length = strlen(safer_konfig_pattern_string);

	/*
	  Wenn string groesser 1, letztes zeichen abschneiden
	  Zusaetzlich string_length fuer alloc verkleinern
	*/

	if (str_length > 1) {
		str_length--;
		safer_konfig_pattern_string[str_length] = '\0';
	}

	list_konfig_pattern_temp[list_konfig_pattern_start] = kzalloc((str_length + 1) * sizeof(char), GFP_ATOMIC);

	if (list_konfig_pattern_temp == NULL) {
		for (int n = 0; n < list_konfig_pattern_start; n++) {
			kfree(list_konfig_pattern_temp[n]);
			list_konfig_pattern_temp[n] = NULL;
		}

		kfree(list_konfig_pattern_temp);
		list_konfig_pattern_temp = NULL;
		list_konfig_pattern_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	list_konfig_pattern_bytes += str_length;

	strcpy(list_konfig_pattern_temp[list_konfig_pattern_start], safer_konfig_pattern_string);

	list_konfig_pattern_start++;

	/* list full */
	if (list_konfig_pattern_start >= list_konfig_pattern_size) {
		list_konfig_pattern_start = -1;
		/* clear */
		/* old list */
		char **global_list_konfig_pattern_temp = global_list_konfig_pattern;
		char global_list_konfig_pattern_size_temp = global_list_konfig_pattern_size;

		/* global = new */
		global_list_konfig_pattern = list_konfig_pattern_temp;
		global_list_konfig_pattern_size = list_konfig_pattern_size;
		global_list_konfig_pattern_bytes = list_konfig_pattern_bytes;
		list_konfig_pattern_temp = NULL;

		printk("SAFER: FILE LIST ELEMENTS PATTERN: %ld\n", global_list_konfig_pattern_size);
		printk("SAFER: FILE LIST BYTES PATTERN   : %ld\n", global_list_konfig_pattern_bytes);

		if (global_list_konfig_pattern_size_temp > 0) {
			for (int n = 0; n < global_list_konfig_pattern_size_temp; n++) {
				if (global_list_konfig_pattern_temp[n] != NULL) {
					kfree(global_list_konfig_pattern_temp[n]);
					global_list_konfig_pattern_temp[n] = NULL;
				}
			}
			kfree(global_list_konfig_pattern_temp);
			global_list_konfig_pattern_temp = NULL;
		}
	}
	mutex_unlock(&control);

	return 0;
}






static char safer_folder_string[PATH_MAX];
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
			printk("SAFER: FREE list_folder_temp, %ld, %ld\n",
				list_folder_start, list_folder_size );

			for (int n = 0; n < list_folder_start; n++) {
				if (list_folder_temp[n] != NULL) {
					kfree(list_folder_temp[n]);
					list_folder_temp[n] = NULL;
				}
			}
			kfree(list_folder_temp);
			list_folder_temp = NULL;
		}

		list_folder_temp = kzalloc(list_folder_size_temp * sizeof(char *), GFP_ATOMIC);
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
	list_folder_temp[list_folder_start] = kzalloc((str_len + 1) * sizeof(char), GFP_ATOMIC);

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

		printk("SAFER: FOLDER LIST ELEMENTS: %ld\n", global_list_folder_size);
		printk("SAFER: FOLDER LIST BYTES   : %ld\n", global_list_folders_bytes);

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




static char safer_host_sconfig_file_string[PATH_MAX];
static long list_host_sconfig_file_size;
static long list_host_sconfig_file_start = -1;
static long list_host_sconfig_file_bytes;
static char **list_host_sconfig_file_temp = NULL;

static int proc_safer_host_sconfig_file(const struct ctl_table *table,
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
	long list_host_sconfig_file_size_temp = 0;
	retval = kstrtol(safer_host_sconfig_file_string, 10, &list_host_sconfig_file_size_temp);
	if (retval == 0) {
		if (list_host_sconfig_file_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_host_sconfig_file_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_host_sconfig_file_start != -1) {
			printk("SAFER: FREE LIST SCONFIG_FILE_TEMP, %ld, %ld\n",
				list_host_sconfig_file_start,
				list_host_sconfig_file_size );

			for (int n = 0; n < list_host_sconfig_file_start; n++) {
				if (list_host_sconfig_file_temp[n] != NULL) {
					kfree(list_host_sconfig_file_temp[n]);
					list_host_sconfig_file_temp[n] = NULL;
				}
			}
			kfree(list_host_sconfig_file_temp);
			list_host_sconfig_file_temp = NULL;
		}

		list_host_sconfig_file_temp = kzalloc(list_host_sconfig_file_size_temp * sizeof(char *), GFP_ATOMIC);
		/* Create not ok */
		if (list_host_sconfig_file_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_host_sconfig_file_size = list_host_sconfig_file_size_temp;
		list_host_sconfig_file_start = 0;
		list_host_sconfig_file_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}


	if (list_host_sconfig_file_start == -1) { 
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	int str_len = strlen(safer_host_sconfig_file_string);


	list_host_sconfig_file_temp[list_host_sconfig_file_start] = kzalloc((str_len + 1) * sizeof(char), GFP_ATOMIC);

	if (list_host_sconfig_file_temp == NULL) {
		for (int n = 0; n < list_host_sconfig_file_start; n++) {
			kfree(list_host_sconfig_file_temp[n]);
			list_host_sconfig_file_temp[n] = NULL;
		}

		kfree(list_host_sconfig_file_temp);
		list_host_sconfig_file_temp = NULL;
		list_host_sconfig_file_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	list_host_sconfig_file_bytes += str_len;

	strcpy(list_host_sconfig_file_temp[list_host_sconfig_file_start], safer_host_sconfig_file_string);

	list_host_sconfig_file_start++;

	/* list full */
	if (list_host_sconfig_file_start >= list_host_sconfig_file_size) {
		list_host_sconfig_file_start = -1;
		/* clear */
		/* old list */
		char **global_list_host_sconfig_file_temp = global_list_host_sconfig_file;
		char global_list_host_sconfig_file_size_temp = global_list_host_sconfig_file_size;

		/* global = new */
		global_list_host_sconfig_file = list_host_sconfig_file_temp;
		global_list_host_sconfig_file_size = list_host_sconfig_file_size;
		global_list_host_sconfig_file_bytes = list_host_sconfig_file_bytes;
		list_host_sconfig_file_temp = NULL;

		printk("SAFER: SCONFIG_FILE LIST ELEMENTS: %ld\n", global_list_host_sconfig_file_size);
		printk("SAFER: SCONFIG_FILE LIST BYTES   : %ld\n", global_list_host_sconfig_file_bytes);

		if (global_list_host_sconfig_file_size_temp > 0) {
			for (int n = 0; n < global_list_host_sconfig_file_size_temp; n++) {
				if (global_list_host_sconfig_file_temp[n] != NULL) {
					kfree(global_list_host_sconfig_file_temp[n]);
					global_list_host_sconfig_file_temp[n] = NULL;
				}
			}
			kfree(global_list_host_sconfig_file_temp);
			global_list_host_sconfig_file_temp = NULL;
		}
	}

	mutex_unlock(&control);

	return 0;
}




static char safer_host_config_file_check_string[PATH_MAX];
static long list_host_config_file_check_size;
static long list_host_config_file_check_start = -1;
static long list_host_config_file_check_bytes;
static char **list_host_config_file_check_temp = NULL;

static int proc_safer_host_config_file_check(const struct ctl_table *table,
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
	long list_host_config_file_check_size_temp = 0;
	retval = kstrtol(safer_host_config_file_check_string, 10, &list_host_config_file_check_size_temp);
	if (retval == 0) {
		if (list_host_config_file_check_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_host_config_file_check_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_host_config_file_check_start != -1) {
			printk("SAFER: FREE LIST CHECK HOST_CONFIG_FILE_TEMP, %ld, %ld\n",
				list_host_config_file_check_start, 
				list_host_config_file_check_size );

			for (int n = 0; n < list_host_config_file_check_start; n++) {
				if (list_host_config_file_check_temp[n] != NULL) {
					kfree(list_host_config_file_check_temp[n]);
					list_host_config_file_check_temp[n] = NULL;
				}
			}
			kfree(list_host_config_file_check_temp);
			list_host_config_file_check_temp = NULL;
		}

		list_host_config_file_check_temp = kzalloc(list_host_config_file_check_size_temp * sizeof(char *), GFP_ATOMIC);
		/* Create not ok */
		if (list_host_config_file_check_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_host_config_file_check_size = list_host_config_file_check_size_temp;
		list_host_config_file_check_start = 0;
		list_host_config_file_check_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}


	if (list_host_config_file_check_start == -1) { 
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	int str_len = strlen(safer_host_config_file_check_string);
	list_host_config_file_check_temp[list_host_config_file_check_start] = kzalloc((str_len + 1) * sizeof(char), GFP_ATOMIC);

	if (list_host_config_file_check_temp == NULL) {
		for (int n = 0; n < list_host_config_file_check_start; n++) {
			kfree(list_host_config_file_check_temp[n]);
			list_host_config_file_check_temp[n] = NULL;
		}

		kfree(list_host_config_file_check_temp);
		list_host_config_file_check_temp = NULL;
		list_host_config_file_check_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}

	list_host_config_file_check_bytes += str_len;

	strcpy(list_host_config_file_check_temp[list_host_config_file_check_start], safer_host_config_file_check_string);

	list_host_config_file_check_start++;

	/* list full */
	if (list_host_config_file_check_start >= list_host_config_file_check_size) {
		list_host_config_file_check_start = -1;
		/* clear */
		/* old list */
		char **global_list_host_config_file_check_temp = global_list_host_config_file_check;
		char global_list_host_config_file_check_size_temp = global_list_host_config_file_check_size;

		/* global = new */
		global_list_host_config_file_check = list_host_config_file_check_temp;
		global_list_host_config_file_check_size = list_host_config_file_check_size;
		global_list_host_config_file_check_bytes = list_host_config_file_check_bytes;
		list_host_config_file_check_temp = NULL;

		printk("SAFER: HOST CONFIG_FILE CHECK LIST ELEMENTS: %ld\n", global_list_host_config_file_check_size);
		printk("SAFER: HOST CONFIG_FILE CHECK LIST BYTES   : %ld\n", global_list_host_config_file_check_bytes);

		if (global_list_host_config_file_check_size_temp > 0) {
			for (int n = 0; n < global_list_host_config_file_check_size_temp; n++) {
				if (global_list_host_config_file_check_temp[n] != NULL) {
					kfree(global_list_host_config_file_check_temp[n]);
					global_list_host_config_file_check_temp[n] = NULL;
				}
			}
			kfree(global_list_host_config_file_check_temp);
			global_list_host_config_file_check_temp = NULL;
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
		.data           = &safer_mode_temp,
		.maxlen         = sizeof(int),
		.mode           = 0600,
		.proc_handler   = proc_safer_active,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname       = "safer_full_check",
		.data           = &safer_mode_full_check,
		.maxlen         = sizeof(int),
		.mode           = 0600,
		.proc_handler   = proc_safer_full_check,
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
	{
		.procname	= "safer_host_sconfig_file",
		.data		= &safer_host_sconfig_file_string,
		.maxlen		= sizeof(safer_host_sconfig_file_string),
		.mode		= 0600,
		.proc_handler	= proc_safer_host_sconfig_file,
	},
	{
		.procname	= "safer_host_config_file_check",
		.data		= &safer_host_config_file_check_string,
		.maxlen		= sizeof(safer_host_config_file_check_string),
		.mode		= 0600,
		.proc_handler	= proc_safer_host_config_file_check,
	},
	{
		.procname	= "safer_printk_config",
		.data		= &printk_config,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_printk_config,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "safer_konfig_pattern",
		.data		= &safer_konfig_pattern_string,
		.maxlen		= sizeof(safer_konfig_pattern_string),
		.mode		= 0600,
		.proc_handler	= proc_safer_konfig_pattern,
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

	if (safer_mode_full_check == true)
		seq_printf(proc_show, "MODE SAFER FULL CHECK       : ON\n");
	else	seq_printf(proc_show, "MODE SAFER FULL CHECK       : OFF\n");


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


	/* ----------------------------------------- */
	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "FOLDER:\n\n");

	if (global_list_folder_size > 0) {
		for (n = 0; n < global_list_folder_size; n++) {
			if (global_list_folder[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_folder[n]);
		}
	}

	/* ----------------------------------------- */
	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "PROG FILES:\n\n");


	if (global_list_prog_size > 0) {
		for (n = 0; n < global_list_prog_size; n++) {
			if (global_list_prog[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_prog[n]);
		}
	}

	/* ----------------------------------------- */
	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "KONFIG-SFILE:\n\n");


	if (global_list_host_sconfig_file_size > 0) {
		for (n = 0; n < global_list_host_sconfig_file_size; n++) {
			if (global_list_host_sconfig_file[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_host_sconfig_file[n]);
		}
	}


	/* ----------------------------------------- */
	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "KONFIG-FILE:\n\n");


	if (global_list_host_config_file_check_size > 0) {
		for (n = 0; n < global_list_host_config_file_check_size; n++) {
			if (global_list_host_config_file_check[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_host_config_file_check[n]);
		}
	}

	/* ----------------------------------------- */
	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "PATTER INLINE:\n\n");


	if (global_list_konfig_pattern_size > 0) {
		for (n = 0; n < global_list_konfig_pattern_size; n++) {
			if (global_list_konfig_pattern[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_konfig_pattern[n]);
		}
	}




	/* ----------------------------------------- */
	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "DENY FILES:\n\n");

	/* ----------------------------------------- */
	if (global_list_deny_size > 0) {
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


	/* ----------------------------------------------- */
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


	/* ----------------------------------------------- */
	seq_printf(proc_show, "INFO LEARNING KONFIG\n\n");
	seq_printf(proc_show, "<LEARNING KONFIG LIST> is organized as a RING\n\n");
	seq_printf(proc_show, "Learning KONFIG LIST MAX            : %d\n", LEARNING_KONFIG_MAX);
	seq_printf(proc_show, "FILE KONFIG learning LIST           : %ld\n", global_list_konfig_file_learning_size);


	if (global_list_konfig_file_learning == NULL)
		return 0;


	for (n = 0; n < LEARNING_KONFIG_MAX; n++) {
		if (global_list_konfig_file_learning[n] == NULL) break;

		seq_printf(proc_show, "%s\n", global_list_konfig_file_learning[n]);
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

