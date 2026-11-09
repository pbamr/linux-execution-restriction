
#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>




//#include <linux/limits.h>  // Für PATH_MAX
//#include <linux/dcache.h>  // Für d_path (falls benötigt)


#define HOST		0
#define CONTAINER	1

#define LEARNING_MAX 50000
#define LIST_MAX 50000
#define DENY_MAX 10000


#define LIST_MIN 1

#define CONTROL_ERROR -1

#define TRUE 1
#define FALSE 0

#define AF_UNIX 1




static DEFINE_MUTEX(learning_lock);
static DEFINE_MUTEX(deny_lock);
static DEFINE_MUTEX(control);



static int	safer_mode = false;
static int	learning_mode = true;
static int	printk_deny = true;
static int	lock_mode = false;
static int	ONLY_SHOW_DENY = false;

static int	printk_allowed = false;
static int	printk_allowed_root = false;



static char	**global_list_socket;
static long	global_list_socket_count;

static char	**global_list_socket_deny;
static long	global_list_socket_count_deny = -1;



static long	global_list_socket_bytes;
static char	**global_list_learning_socket;
static long	global_list_learning_socket_count = -1;






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
static char *get_process_exe_path(char *buf, int buf_size)
{
	struct file *exe_file;
	char *path_ptr = NULL;

	// Versuche direkt das exe_file des aktuellen Tasks zu holen
	exe_file = get_task_exe_file(current);
	if (exe_file) {
		path_ptr = d_path(&exe_file->f_path, buf, buf_size);
		fput(exe_file);
	}

	return path_ptr;
}





static int safer_get_kontext(void)
{
	int kontext = HOST; // Standardwert festlegen, um RCU-Pfade zu vereinfachen

	rcu_read_lock();

	if (current->cgroups) {
		struct cgroup *cgrp = current->cgroups->dfl_cgrp;

		if (cgrp) {
			/* systemd slice, container */
			if (cgroup_parent(cgrp) != NULL) {
				/* container check, virtualisiertem Cgroup-Namespace */
				if (current->nsproxy && current->nsproxy->cgroup_ns != &init_cgroup_ns) {
					rcu_read_unlock();
					return CONTAINER;
				}

				// HOST */
				rcu_read_unlock();
				return HOST;
			}
			/* Wenn cgroup_parent == NULL, sind wir auf der obersten Host-Ebene. */
			else {
				rcu_read_unlock();
				return HOST;
			}
		}
	}

	// Legacy
	// Keine cgroups aktiv (z.B. per Bootparameter)
	// container (Fallback ohne cgroups)

	/* Sicherheitscheck für nsproxy im Legacy-Pfad */
	if (current->nsproxy) {
		if (current->nsproxy->mnt_ns == init_task.nsproxy->mnt_ns) {
			kontext = HOST;
		} else {
			kontext = CONTAINER;
		}
	} else {
		/* Fallback, falls nsproxy NULL ist (z.B. Task im Exit-Pfad) */
		kontext = HOST; 
	}

	rcu_read_unlock();
	return kontext;
}





static bool
safer_main_socket_connect_send(int family)
{
	uid_t euid;
	char *exe_path = NULL;

	/* --------------------------------------------------------------------- */
	if (safer_mode == false)
		if (learning_mode == false) {
			return true;
	}


	/* --------------------------------------------------------------------- */
	int kontext = safer_get_kontext();

	/* user id ermitteln */
	/* wenn root und HOST herausfiltern */
	if (current_cred())
		euid = from_kuid(&init_user_ns, current_cred()->euid);
	else return true;


	/* --------------------------------------------------------------------- */
	/* speicher anfordern. vielleicht seriallisieren. und auf datensegment legen */
	char *buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer)
		return true;

	/* Helper function. Path*/
	exe_path = get_process_exe_path(buffer, PATH_MAX);
	if (IS_ERR(exe_path)) {
		kfree(buffer);
		return true;
	}

	/* --------------------------------------------------------------------- */
	if (printk_allowed == TRUE) {
		if (kontext == HOST)
			printk("SAFER: SCS:HOST:a:%u;%s;%d\n", euid, exe_path, family);
		else
			printk("SAFER: SCS:CONT:a:%u;%s;%d\n", euid, exe_path, family);
	}

	if (printk_allowed_root == TRUE) {
		if (euid == 0) {
			if (kontext == HOST)
				printk("SAFER: SCS:HOST:a:%u:%s;%d\n", euid, exe_path, family);
			else
				printk("SAFER: SCS:CONT:a:%u:%s;%d\n", euid, exe_path, family);
		}
	}

	/* --------------------------------------------------------------------- */
	/* speicher anfordern. vielleicht seriallisieren. und auf datensegment legen */
	char *string_test = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!string_test) {
		kfree(buffer);
		return true;
	}

	if (kontext == HOST)
		scnprintf(string_test, PATH_MAX, "SCS:HOST:a:%u;%s;%d",
			euid, exe_path, family);
	else
		scnprintf(string_test, PATH_MAX, "SCS:CONT:a:%u;%s;%d",
			euid, exe_path, family);

	if (learning_mode == true) {
		if (mutex_trylock(&learning_lock)) {
			learning(string_test,
				&global_list_learning_socket,
				&global_list_learning_socket_count);

			mutex_unlock(&learning_lock);
		}
	}

	/* --------------------------------------------------------------------- */
	if (safer_mode == true) {
		/* filter 1 */
		if (kontext == HOST)
			scnprintf(string_test, PATH_MAX, "SCS:HOST:a:%u",
				euid);
		else
			scnprintf(string_test, PATH_MAX, "SCS:CONT:a:%u",
				euid);

		bool retval = besearch_file(string_test,
					global_list_socket,
					global_list_socket_count);

		if (retval == true) {
			if (printk_allowed == true) {
				if (kontext == HOST)
					printk("SAFER: ALLOWED: SCS:HOST:a:%u;%s;%d\n",
						euid, exe_path, family);
				else
					printk("SAFER: ALLOWED: SCS:CONT:a:%u;%s;%d\n",
						euid, exe_path, family);
			}

			kfree(string_test);
			kfree(buffer);
			return true;
		}


		/* --------------------------------------------------------------------- */
		/* filter 2 */
		if (kontext == HOST)
			scnprintf(string_test, PATH_MAX, "SCS:HOST:a:%s;%d",
				exe_path, family);
		else
			scnprintf(string_test, PATH_MAX, "SCS:CONT:a:%s;%d",
				exe_path, family);

		retval = besearch_file(string_test,
					global_list_socket,
					global_list_socket_count);

		if (retval == true) {
			if (printk_allowed == true) {
				if (kontext == HOST)
					printk("SAFER: ALLOWED: SCS:HOST:a:%u;%s;%d\n",
						euid, exe_path, family);
				else
					printk("SAFER: ALLOWED: SCS:CONT:a:%u;%s;%d\n",
						euid, exe_path, family);
			}

			kfree(string_test);
			kfree(buffer);
			return true;
		}

		/* --------------------------------------------------------------------- */
		/* filter 3 */
		if (kontext == HOST)
			scnprintf(string_test, PATH_MAX, "SCS:HOST:a:%u;%s;%d",
				euid, exe_path, family);
		else
			scnprintf(string_test, PATH_MAX, "SCS:CONT:a:%u;%s;%d",
				euid, exe_path, family);

		retval = besearch_file(string_test,
					global_list_socket,
					global_list_socket_count);

		if (retval == true) {
			if (printk_allowed == true) {
				if (kontext == HOST)
					printk("SAFER: ALLOWED: SCS:HOST:a:%u;%s;%d\n",
						euid, exe_path, family);
				else
					printk("SAFER: ALLOWED: SCS:CONT:a:%u;%s;%d\n",
						euid, exe_path, family);
			}

			kfree(string_test);
			kfree(buffer);
			return true;
		}



		/* --------------------------------------------------------------------- */
		if (printk_deny == true) {
			if (kontext == HOST)
				printk("SAFER: DENY: SCS:HOST:a:%u;%s;%d\n",
					euid, exe_path, family);
			else
				printk("SAFER: DENY: SCS:CONT:a:%u;%s;%d\n",
					euid, exe_path, family);
		}

		if (mutex_trylock(&deny_lock)) {
			deny_list(string_test,
				&global_list_socket_deny,
				&global_list_socket_count_deny);

			mutex_unlock(&deny_lock);
		}

		kfree(string_test);
		kfree(buffer);

		if (ONLY_SHOW_DENY == true)
			return true;

		return false;

	}



	kfree(string_test);
	kfree(buffer);
	return true;

}






/* ################################################################################################################### */
static char safer_socket_string[2048];
static long list_socket_size;
static long list_socket_start = -1;
static long list_socket_bytes;
static char **list_socket_temp;


static int proc_safer_socket(const struct ctl_table *table,
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
	long list_socket_size_temp = 0;

	retval = kstrtol(safer_socket_string, 10, &list_socket_size_temp);

	if (retval == 0) {
		if (list_socket_size_temp < LIST_MIN) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		if (list_socket_size_temp > LIST_MAX) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}


		if (list_socket_start != -1) {
			pr_warn("MODE: SAFER SOCKET FREE: list SOCKET temp, %ld, %ld\n",
				list_socket_start, list_socket_size);

			for (int n = 0; n < list_socket_start; n++) {
				if (list_socket_temp[n] != NULL) {
					kfree(list_socket_temp[n]);
					list_socket_temp[n] = NULL;
				}
			}

			kfree(list_socket_temp);
			list_socket_temp = NULL;
		}

		/* Zeiger arry */
		list_socket_temp = kzalloc(list_socket_size_temp * sizeof(char *),
					GFP_KERNEL);

		/* Create not ok */
		if (list_socket_temp == NULL) {
			mutex_unlock(&control);
			return CONTROL_ERROR;
		}

		/* init */
		/* No realloc */
		list_socket_size = list_socket_size_temp;
		list_socket_start = 0;
		list_socket_bytes = 0;
		mutex_unlock(&control);
		return 0;
	}



	if (list_socket_start == -1) {
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}


	list_socket_temp[list_socket_start] = kstrdup(safer_socket_string, GFP_KERNEL);

	if (list_socket_temp[list_socket_start] == NULL) {
		for (int n = 0; n < list_socket_start; n++) {
			kfree(list_socket_temp[n]);
			list_socket_temp[n] = NULL;
		}

		kfree(list_socket_temp);
		list_socket_temp = NULL;
		list_socket_start = -1;
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}



	/* count bytes and strings */
	list_socket_bytes += strlen(safer_socket_string);
	list_socket_start++;


	/* list full */
	if (list_socket_start >= list_socket_size) {
		list_socket_start = -1;
		/* clear */
		/* old list */
		char **global_list_socket_temp = global_list_socket;

		char global_list_socket_size_temp = global_list_socket_count;

		/* global = new */
		global_list_socket = list_socket_temp;
		global_list_socket_count = list_socket_size;
		global_list_socket_bytes = list_socket_bytes;
		list_socket_temp = NULL;

		pr_warn("SAFER SOCKET LIST ELEMENTS: %ld\n",
			global_list_socket_count);

		pr_warn("SAFER SOCKET LIST BYTES   : %ld\n",
			global_list_socket_bytes);

		if (global_list_socket_size_temp > 0) {
			for (int n = 0; n < global_list_socket_size_temp; n++) {
				if (global_list_socket_temp[n] != NULL) {
					kfree(global_list_socket_temp[n]);
					global_list_socket_temp[n] = NULL;
				}
			}
			kfree(global_list_socket_temp);
			global_list_socket_temp = NULL;
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


	if (global_list_socket == NULL) {
		safer_mode = false;
		printk("MODE: SAFER EROR\n");
		mutex_unlock(&control);
		return CONTROL_ERROR;
	}





	int retval = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (write && retval == 0) {
		if (safer_mode == TRUE)
			pr_warn("MODE: SAFER SOCKET ON\n");
		else
			pr_warn("MODE: SAFER SOCKET OFF\n");
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
			pr_warn("MODE: SAFER SOCKET PRINTK DENY ON\n");
		else
			pr_warn("MODE: SAFER SOCKET PRINTK DENY OFF\n");
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
			pr_warn("MODE: SAFER SOCKET PRINTK ALLOWED ON\n");
		else
			pr_warn("MODE: SAFER SOCKET PRINTK ALLOWED OFF\n");
	}

	mutex_unlock(&control);

	return retval;
}

static int proc_safer_printk_allowed_root(const struct ctl_table *table,
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
		if (printk_allowed_root == TRUE)
			pr_warn("MODE: SAFER SOCKET PRINTK ALLOWED ROOT ON\n");
		else
			pr_warn("MODE: SAFER SOCKET PRINTK ALLOWED ROOT OFF\n");
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
			pr_warn("MODE: SAFER SOCKET learning ON\n");
		else
			pr_warn("MODE: SAFER SOCKET learning OFF\n");
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
			pr_warn("MODE: SAFER SOCKET: NO MORE CHANGES ALLOWED\n");
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
			pr_warn("MODE: SAFER  PRINTK ONLY SHOW DENY ON\n");
		else
			pr_warn("MODE: SAFER SOCKET PRINTK ONLY SHOW DENY OFF\n");
	}

	mutex_unlock(&control);

	return retval;
}



static const struct ctl_table safer_table[] = {
	{
		.procname       = "safer_socket",
		.data           = &safer_socket_string,
		.maxlen         = sizeof(safer_socket_string),
		.mode           = 0600,
		.proc_handler   = proc_safer_socket,
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
		.procname	= "safer_printk_allowed_root",
		.data		= &printk_allowed_root,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_safer_printk_allowed_root,
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
static int safer_info_socket_display(struct seq_file *proc_show, void *v)
{
	long n;

	seq_puts(proc_show, "INFO SAFER SOCKET\n\n");

	seq_puts(proc_show, "KERNEL INFO SOCKET\n");
	seq_puts(proc_show, "Peter Boettcher, Muelheim, GER.\n");



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


	seq_printf(proc_show, "socket LIST SIZE socket           : %ld\n", global_list_socket_count);
	seq_printf(proc_show, "socket LIST BYTES socket          : %ld\n", global_list_socket_bytes);


	seq_puts(proc_show,   "MODE SEARCH SOCKET                : BSEARCH\n");



	seq_puts(proc_show, "\n\n");

	seq_puts(proc_show, "\n\n");
	seq_puts(proc_show, "socket:\n\n");

	if (global_list_socket_count != 0) {
		for (n = 0; n < LIST_MAX; n++) {
			if (global_list_socket[n] == NULL)
				break;

			seq_printf(proc_show, "%s\n", global_list_socket[n]);
		}
	}




	seq_puts(proc_show, "\n\nINFO DENY KERNEL SOCKET\n\n");

	if (global_list_socket_deny == NULL)
		return 0;

	for (n = 0; n < DENY_MAX; n++) {
		if (global_list_socket_deny[n] == NULL)
			break;

		seq_printf(proc_show, "%s\n", global_list_socket_deny[n]);
	}



	return 0;
}





/* ##################################################################### */
static int safer_learning_socket_display(struct seq_file *proc_show, void *v)
{
	long	n;


	seq_puts(proc_show,   "\n\nINFO LEARNING SOCKET \n\n");
	seq_puts(proc_show,   "<LEARNING LIST> is organized as a RING\n\n");
	seq_printf(proc_show, "Learning LIST MAX          : %d\n", LEARNING_MAX);
	seq_printf(proc_show, "SOCKET learning LIST       : %ld\n", global_list_learning_socket_count);


	if (global_list_learning_socket == NULL)
		return 0;

	for (n = 0; n < LEARNING_MAX; n++) {
		if (global_list_learning_socket[n] == NULL)
			break;

		seq_printf(proc_show, "%s\n", global_list_learning_socket[n]);
	}

	return 0;
}



//static int __init safer_learning_show(void)
static int __init safer_socket_init(void)
{
	/*
	 * Status information is confidential
	 * 0 = 0444
	 * otherwise octal
	 */


	register_sysctl_init("kernel/safer_socket", safer_table);

	proc_create_single("safer.socket.info", 0400, NULL, safer_info_socket_display);

	proc_create_single("safer.socket.learning", 0400, NULL, safer_learning_socket_display);
	return 0;
}
late_initcall(safer_socket_init);
//fs_initcall(safer_learning_show);












