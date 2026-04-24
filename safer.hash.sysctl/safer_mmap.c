// SPDX-License-Identifier: GPL-2.0-only



/* Copyright (c) 2026.04.28, 2026.04.24, Peter Boettcher, Germany/NRW,
 *  Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2026.03.28, 2026.04.20, Peter Boettcher, Germany/NRW, Muelheim Ruhr,
 * mail:peter.boettcher@gmx.net

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



/* my changes ########################################################## */
/*
 * Add all my changes in your mm/mmap.c
 * You can find these under "my changes".
 * Simply search for "my changes" in the source code.
 */


/* my changes ########################################################## */





#include <crypto/internal/hash.h>
#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hex.h>



/*
 * 
 * LEARNING_lib	= 10
 * CHECK_lib	= 11
 *
 */



#define LEARNING	10		//(1 << 0)
#define CHECK		11		//(1 << 1)






/* HASH ?*/

/* Your choice */
/*
 * #define HASH_ALG "md5"
 * #define DIGIT 16
 * #define HASH_STRING_LENGTH ((DIGIT * 2) + 1)
 */


#define HASH_ALG "sha256"
#define DIGIT 32
#define HASH_STRING_LENGTH ((DIGIT * 2) + 1)

/*
 * #define HASH_ALG "sha512"
 * #define DIGIT 64
 * #define HASH_STRING_LENGTH ((DIGIT * 2) + 1)
 */


#define LEARNING_MAX 50000
#define DENY_MAX 10000
#define LIST_MAX 50000


#define LIST_MIN 1
#define KERNEL_READ_SIZE 2123457
#define CONTROL_ERROR -1

#define TRUE 1
#define FALSE 0



//typedef int ibool;



/* --------------------------------------------------------------------- */


static DEFINE_MUTEX(mmap_lock);
static DEFINE_MUTEX(control);


static int	safer_mode = FALSE;
static int	learning_mode = TRUE;
static int	printk_deny = TRUE;
static int	printk_allowed = FALSE;
static int	ONLY_SHOW_DENY = FALSE;
static int	lock_mode = FALSE;



static char	**global_list_lib;
static long	global_list_lib_count;
static long	global_list_lib_bytes;


static char	**global_list_lib_deny;
static long	global_list_lib_count_deny = -1;

static char	**global_list_learning_lib;
static long	global_list_learning_lib_count = -1;





static char lib_path_buffer[PATH_MAX + 1];
static char string_test[PATH_MAX + HASH_STRING_LENGTH + 22 + 2];


/* Reserviert 4KB pro CPU-Kern statisch im RAM */
/* static DEFINE_PER_CPU(u8[PAGE_SIZE], buffer); */








/* --------------------------------------------------------------------- */
static int is_executable_binary(struct file *file,
				unsigned long vm_flags,
				unsigned long prot)
{


	/* Mappings mit Execute-Berechtigung pruefen */
	if (vm_flags)
		if (VM_EXEC)
			return 0;

	/* Ist Datei? */
	if (!file)
		return 0;

	if (prot & PROT_EXEC)
		return 1;


	return 0;
}



/* --------------------------------------------------------------------- */
static bool besearch_file(char *str_search, char **list, long elements)
{
	long left, right;
	long middle;
	long int_ret;

	left = 0;
	right = elements - 1;

	while (left <= right) {
		middle = (left + right) / 2;

		int_ret = strcmp(list[middle], str_search);

		if (int_ret == 0)
			return true;
		else if (int_ret < 0)
			left = middle + 1;
		else if (int_ret > 0)
			right = middle - 1;
	}

	return false;
}




/* --------------------------------------------------------------------- */
static
bool search(char *str_search, char **list, long elements)
{
	long n;

	for (n = 0; n < elements; n++) {
		if (strncmp(list[n], str_search, strlen(list[n])) == 0)
			return true;
	}

	return false;
}



/* ---------------------------------------------------------------------- */
static
bool get_hash_sum(struct file *file, struct inode *inode,
		  u8 *hashraw, loff_t max)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;

	/* 512 Bytes sind sicher fuer den Stack und Compiler-freundlich */
	char buffer[256];
	loff_t pos = 0;
	size_t total_hashed = 0;


	int retval;

	/* Crypto-INIt */
	tfm = crypto_alloc_shash(HASH_ALG, 0, 0);
	if (IS_ERR(tfm))
		return false;

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return false;
	}

	desc->tfm = tfm;
	retval = crypto_shash_init(desc);
	if (retval) {
		kfree(desc);
		crypto_free_shash(tfm);
		return false;
	}



	int err = deny_write_access(file);

	if (err) {
		kfree(desc);
		crypto_free_shash(tfm);
		return false;
	}

	/* Schleife fuer krumme Werte */
	while (total_hashed < max) {
		/* Berechne den exakten Rest
		 * (auch bei krummen Zahlen < 512)
		 */

		size_t to_read = min((size_t)sizeof(buffer), max - total_hashed);

		ssize_t n = kernel_read(file, buffer, to_read, &pos);

		/* Fehler oder unerwartetes Ende */
		if (n <= 0) {
			kfree(desc);
			crypto_free_shash(tfm);
			return false;
		}

		/* Nur die tatsaechlich gelesenen Bytes hashen */
		retval = crypto_shash_update(desc, buffer, n);
		if (retval)
			break;

		total_hashed += (size_t) n;
	}

	allow_write_access(file);


	/* Hash in den Zielpuffer */
	if (!retval) {
		if (crypto_shash_final(desc, hashraw)) {
			kfree(desc);
			crypto_free_shash(tfm);
			return true;
		}
	}

	kfree(desc);
	crypto_free_shash(tfm);
	return false;
}



/* --------------------------------------------------------------------- */
static void hashraw_to_hashstring(const u8 *hash_raw, char *hash_string)
{
	bin2hex(hash_string, hash_raw, 32);
	hash_string[64] = '\0';
}




/* --------------------------------------------------------------------- */
static
bool learning(char *string_test, char ***list, long *list_len)
{

	/* init pointer list/array 50000 */
	if (*list_len == -1) {
		*list = kmalloc(sizeof(char *) * LEARNING_MAX, GFP_KERNEL);
		if (*list == NULL)
			return false;
		else
			*list_len = 0;
	}

	/* if string found return */
	if (search(string_test, *list, *list_len) == true)
		return true;

	char *string_learning = kstrdup(string_test, GFP_KERNEL);
	if (string_learning == NULL)
		return false;


	/* wenn umlauf */
	if ((*list)[*list_len] != NULL)
		kfree((*list)[*list_len]);

	(*list)[*list_len] = string_learning;

	*list_len += 1;

	// check _len > lerning_max
	if (*list_len > LEARNING_MAX - 1)
		*list_len = 0;

	return true;

}


/* --------------------------------------------------------------------- */
static
bool deny_list(char *string_test, char ***list, long *list_len)
{

	/* init pointer list/array 50000 */
	if (*list_len == -1) {
		*list = kmalloc(sizeof(char *) * LEARNING_MAX, GFP_KERNEL);
		if (*list == NULL)
			return false;
		else
			*list_len = 0;
	}

	/* if string found return */
	if (search(string_test, *list, *list_len) == true)
		return true;

	char *string_learning = kstrdup(string_test, GFP_KERNEL);
	if (string_learning == NULL)
		return false;


	/* wenn umlauf */
	if ((*list)[*list_len] != NULL)
		kfree((*list)[*list_len]);

	(*list)[*list_len] = string_learning;

	*list_len += 1;

	// check _len > lerning_max
	if (*list_len > LEARNING_MAX - 1)
		*list_len = 0;

	return true;

}





/* --------------------------------------------------------------------- */
static
bool file_allowed(char *string_test, char ***list, long *list_count)
{

	bool retval = besearch_file(string_test,
				*list,
				*list_count);

	return retval;
}



/* --------------------------------------------------------------------- */
static bool checkfile(struct file *file, unsigned long vm_flags,
			unsigned long prot, int safer_mode,
			int learning_mode, int ONLY_SHOW_DENY)
{

	bool toctou;


	if (safer_mode == FALSE)
		if (learning_mode == FALSE)
			return true;




	if (is_executable_binary(file, vm_flags, prot) != 1)
		return true;

	if (current->mm && current->mm->exe_file == file)
		return true;

	/*
	 * file_path schreibt  von hinten nach vorne
	 * fp ist ein Zeiger auf Anfang String. 0.............Anfang
	 */
	char *fp = file_path(file, lib_path_buffer, PATH_MAX);

	loff_t string_length = strlen(fp);

	if (string_length < 1)
		return true;

	struct inode *inode = file_inode(file);


	/* Wenn Learning TRUE und safer_mode ist FALSE */
	if (learning_mode == TRUE) {
		if (safer_mode == FALSE) {

			if (test_bit(LEARNING, (unsigned long *)&inode->i_boettcher_flags)) {

				if (printk_allowed == TRUE)
					pr_info("STAT STEP THIRD: LIBRARY LEARNING CHECK OK     : so;%lld;%s\n", string_length, fp);

				return true;
			}
		}

		else {
			if (printk_allowed == TRUE) {
				if (test_bit(LEARNING, (unsigned long *)&inode->i_boettcher_flags))
					pr_info("STAT STEP THIRD: LIBRARY LEARNING CHECK OK     : so;%lld;%s\n", string_length, fp);
			}
		}
	}



	/* Pruefe, Flag im RAM-Inode */
	/* Wenn erlaubt RETURN */
	if (safer_mode == TRUE) {
		if (test_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags)) {
			if (printk_allowed == TRUE)
				pr_info("STAT STEP THIRD: LIBRARY ALLOWED SAFER CHECK OK: so;%lld;%s\n", string_length, fp);

			return true;
		}
	}


	/* max. file read? */
	loff_t size = i_size_read(inode);

	loff_t max = size;

	if (size > KERNEL_READ_SIZE)
		max = KERNEL_READ_SIZE;


	/* kommt HASH Verfahren ab */
	char hash_raw[DIGIT];
	char hash_string[HASH_STRING_LENGTH];


	/* --------------------------------------------------------------------- */
	set_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);

	/* --------------------------------------------------------------------- */
	if (get_hash_sum(file, inode, hash_raw, max) == 0)
		hashraw_to_hashstring(hash_raw, hash_string);
	else {
		clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);
		return true;
	}

	/* --------------------------------------------------------------------- */
	if (!test_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags))
		toctou = true;

	else
		toctou = false;


	/* --------------------------------------------------------------------- */
	if (toctou == true) {

		clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);

		if (printk_deny == TRUE)
			pr_info("STAT STEP THIRD: LIBRARY TOCTOU   : %s\n", string_test);

		deny_list(string_test,
			&global_list_lib_deny,
			&global_list_lib_count_deny);

		return false;

	}

	clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);



	/* --------------------------------------------------------------------- */

	/* kostet zwar mehr, als strscpy und umwandeln.
	 * ist aber egal. da nicht allzu oft aufgerufe
	 */
	scnprintf(string_test, sizeof(string_test), "so;%lld;%s;%s",
		size, hash_string, fp);

	if (learning_mode == TRUE) {
		bool retval = learning(string_test,
			&global_list_learning_lib,
			&global_list_learning_lib_count);


		if (retval == true) {
			/*
			 * wenn noch nicht in list gewesen. ->set
			 * wenn inode aus mem und inode neu. ->set
			 * wurde lib geaendert. ->set
			 * dann zweimal in list. mit unterschiedlichem HASH
			 */

			set_bit(LEARNING, (unsigned long *)&inode->i_boettcher_flags);

			if (printk_allowed == TRUE)
					pr_info("STAT STEP THIRD: LIBRARY LEARNING FIRST CHECK  : %s\n", string_test);

			//pr_info("SAFER LIB Nur TEST: %lld\n", inode->i_boettcher_flags);
		}
	}

	if (safer_mode == TRUE) {
		bool retval = file_allowed(string_test,
					&global_list_lib,
					&global_list_lib_count);

		if (retval == false) {

			clear_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);

			if (printk_deny == TRUE)
				pr_info("STAT STEP THIRD: LIBRARY DENY   : %s\n", string_test);


			deny_list(string_test,
				&global_list_lib_deny,
				&global_list_lib_count_deny);


			/* Nur wenn safer_mode TRUE */
			if (ONLY_SHOW_DENY == TRUE)
				return true;

			return false;
		}

		/* allowed */
		set_bit(CHECK, (unsigned long *)&inode->i_boettcher_flags);


		if (printk_allowed == TRUE)
			pr_info("STAT STEP THIRD: LIBRARY ALLOWED: %s\n", string_test);

		return true;
	}

	return true;
}





/* ##################################################################### */
static char safer_lib_string[2048];
static long list_lib_size;
static long list_lib_start = -1;
static long list_lib_bytes;
static char **list_lib_temp;


static int proc_safer_lib(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == true)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;



	int retval = proc_dostring(table, write, buffer, lenp, ppos);


	if (write && retval != 0) {
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}


	/* if String = number then init */
	/* string to number */
	long list_lib_size_temp = 0;

	retval = kstrtol(safer_lib_string, 10, &list_lib_size_temp);

	if (retval == 0) {
		if (list_lib_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_lib_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}


		if (list_lib_start != -1) {
			pr_warn("MODE: SAFER LIBRARY FREE: list temp, %ld, %ld\n",
				list_lib_start, list_lib_size);

			for (int n = 0; n < list_lib_start; n++) {
				if (list_lib_temp[n] != NULL) {
					kfree(list_lib_temp[n]);
					list_lib_temp[n] = NULL;
				}
			}

			kfree(list_lib_temp);
			list_lib_temp = NULL;
		}

		/* Zeiger arry */
		list_lib_temp = kzalloc(list_lib_size_temp * sizeof(char *),
					GFP_KERNEL);

		/* Create not ok */
		if (list_lib_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_lib_size = list_lib_size_temp;
		list_lib_start = 0;
		list_lib_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}



	if (list_lib_start == -1) {
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}


	list_lib_temp[list_lib_start] = kstrdup(safer_lib_string, GFP_KERNEL);

	if (list_lib_temp[list_lib_start] == NULL) {
		for (int n = 0; n < list_lib_start; n++) {
			kfree(list_lib_temp[n]);
			list_lib_temp[n] = NULL;
		}

		kfree(list_lib_temp);
		list_lib_temp = NULL;
		list_lib_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}



	/* count bytes and strings */
	list_lib_bytes += strlen(safer_lib_string);
	list_lib_start++;


	/* list full */
	if (list_lib_start >= list_lib_size) {
		list_lib_start = -1;
		/* clear */
		/* old list */
		char **global_list_lib_temp = global_list_lib;

		char global_list_lib_size_temp = global_list_lib_count;

		/* global = new */
		global_list_lib = list_lib_temp;
		global_list_lib_count = list_lib_size;
		global_list_lib_bytes = list_lib_bytes;
		list_lib_temp = NULL;

		pr_warn("SAFER LIBRARIES LIST ELEMENTS: %ld\n",
			global_list_lib_count);

		pr_warn("SAFER LIBRARIES LIST BYTES   : %ld\n",
			global_list_lib_bytes);

		if (global_list_lib_size_temp > 0) {
			for (int n = 0; n < global_list_lib_size_temp; n++) {
				if (global_list_lib_temp[n] != NULL) {
					kfree(global_list_lib_temp[n]);
					global_list_lib_temp[n] = NULL;
				}
			}
			kfree(global_list_lib_temp);
			global_list_lib_temp = NULL;
		}
	}

	mutex_unlock(&control);

	return 0;
}



static int proc_safer_active(const struct ctl_table *table,
				int write,
				void *buffer,
				size_t *lenp,
				loff_t *ppos)
{

	if (lock_mode == TRUE)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (safer_mode == TRUE)
			pr_warn("MODE: SAFER LIBRARIES ON\n");
		else
			pr_warn("MODE: SAFER LIBRARIES OFF\n");
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

	if (lock_mode == TRUE)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (printk_deny == TRUE)
			pr_warn("MODE: SAFER LIBRARIES PRINTK DENY ON\n");
		else
			pr_warn("MODE: SAFER LIBRARIES PRINTK DENY OFF\n");
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

	if (lock_mode == TRUE)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (printk_allowed == TRUE)
			pr_warn("MODE: SAFER LIBRARIES PRINTK ALLOWED ON\n");
		else
			pr_warn("MODE: SAFER LIBRARIES PRINTK ALLOWED OFF\n");
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

	if (lock_mode == TRUE)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (learning_mode == TRUE)
			pr_warn("MODE: SAFER LIBRARIES learning ON\n");
		else
			pr_warn("MODE: SAFER LIBRARIES learning OFF\n");
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

	if (lock_mode == TRUE)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (lock_mode == TRUE)
			pr_warn("MODE: SAFER LIBRARIES: NO MORE CHANGES ALLOWED\n");
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

	if (lock_mode == TRUE)
		return CONTROL_ERROR;

	if (!mutex_trylock(&control))
		return CONTROL_ERROR;

	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (ONLY_SHOW_DENY == TRUE)
			pr_warn("MODE: SAFER LIBRARIES PRINTK ONLY SHOW DENY ON\n");
		else
			pr_warn("MODE: SAFER LIBRARIES PRINTK ONLY SHOW DENY OFF\n");
	}

	mutex_unlock(&control);

	return retval;
}



static const struct ctl_table safer_table[] = {
	{
		.procname       = "safer_lib",
		.data           = &safer_lib_string,
		.maxlen         = sizeof(safer_lib_string),
		.mode           = 0600,
		.proc_handler   = proc_safer_lib,
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
};



/*############################################################### */
static int safer_info_lib_display(struct seq_file *proc_show, void *v)
{
	long n;

	seq_puts(proc_show, "INFO SAFER LIBRARIES\n\n");

	seq_puts(proc_show, "KERNEL INFO LIBRARIES\n");



	if (safer_mode == TRUE)
		seq_puts(proc_show, "MODE SAFER                  : ON\n");
	else
		seq_puts(proc_show, "MODE SAFER                  : OFF\n");

	if (ONLY_SHOW_DENY == TRUE)
		seq_puts(proc_show, "ONLY_SHOW_DENY              : ON\n");
	else
		seq_puts(proc_show, "ONLY_SHOW_DENY              : OFF\n");

	if (printk_allowed == TRUE)
		seq_puts(proc_show, "MODE PRINTK ALLOWED         : ON\n");
	else
		seq_puts(proc_show, "MODE PRINTK ALLOWED         : OFF\n");

	if (printk_deny == TRUE)
		seq_puts(proc_show, "MODE PRINTK DENY            : ON\n");
	else
		seq_puts(proc_show, "MODE PRINTK DENY            : OFF\n");

	if (learning_mode == TRUE)
		seq_puts(proc_show, "MODE LEARNING               : ON\n");
	else
		seq_puts(proc_show, "MODE LEARNING               : OFF\n");

	if (lock_mode == FALSE)
		seq_puts(proc_show, "MODE SAFER LOCK             : OFF\n");
	else
		seq_puts(proc_show, "MODE SAFER LOCK             : ON\n");


	seq_printf(proc_show,       "LIBRARIES LIST SIZE         : %ld\n", global_list_lib_count);
	seq_printf(proc_show,       "LIBRARIES LIST BYTES        : %ld\n", global_list_lib_bytes);


	seq_puts(proc_show,         "MODE SEARCH LIBRARIES       : BSEARCH\n");

	seq_printf(proc_show,       "HASH SIZE MAX               : %d\n", KERNEL_READ_SIZE);


	seq_puts(proc_show, "\n\n");

	seq_puts(proc_show, "\n\n");
	seq_puts(proc_show, "LIBRARIES:\n\n");

	if (global_list_lib_count != 0) {
		for (n = 0; n < LIST_MAX; n++) {
			if (global_list_lib[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_lib[n]);
		}
	}




	seq_puts(proc_show, "\n\nINFO DENY LIBRARIES\n\n");

	if (global_list_lib_deny == NULL)
		return 0;

	for (n = 0; n < DENY_MAX; n++) {
		if (global_list_lib_deny[n] == NULL)
			break;

		seq_printf(proc_show, "%s\n", global_list_lib_deny[n]);
	}


	return 0;
}





/*############################################################### */
static int safer_learning_lib_display(struct seq_file *proc_show, void *v)
{
	long	n;


	seq_puts(proc_show,    "\n\nINFO LEARNING LIBRARIES\n\n");
	seq_puts(proc_show,    "<LEARNING LIST> is organized as a RING\n\n");
	seq_printf(proc_show,  "Learning LIST MAX                 : %d\n", LEARNING_MAX);
	seq_printf(proc_show,  "LIBRARIES learning LIST           : %ld\n", global_list_learning_lib_count);

	if (global_list_learning_lib == NULL)
		return 0;

	for (n = 0; n < LEARNING_MAX; n++) {
		if (global_list_learning_lib[n] == NULL)
			break;

		seq_printf(proc_show, "%s\n", global_list_learning_lib[n]);
	}


	return 0;
}






//static int __init safer_learning_show(void)
static int __init safer_lib_init(void)
{
	/*
	 * Status information is confidential
	 * 0 = 0444
	 * otherwise octal
	 */


	register_sysctl_init("kernel/safer_lib", safer_table);

	proc_create_single("safer.lib.info", 0400, NULL, safer_info_lib_display);
	proc_create_single("safer.lib.learning", 0400, NULL, safer_learning_lib_display);
	return 0;
}
late_initcall(safer_lib_init);
//fs_initcall(safer_learning_show);















