/* Copyright (c) 2022/06/26, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net
 * Urheber: 2022.06.26, Peter Boettcher, Germany/NRW, Muelheim Ruhr, mail:peter.boettcher@gmx.net

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



   I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, VAKHTANG CHABUKIANI and the "LAS CUATRO JOYAS DEL BALLET CUBANO".
   Admirable ballet dancers.

 */



/*
	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.06.26

	Program		: safer_learning.c
	Path		: fs/


	Makefile
	obj-y		+= safer_learning.o
*/




#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>




/* decl. */
struct  safer_learning_struct {
	long file_learning_list_max;
	char **file_learning_list;
	long file_argv_list_max;
	char **file_argv_list;
};


static struct safer_learning_struct learning;
extern void safer_learning(struct safer_learning_struct *learning);



static int safer_learning_display(struct seq_file *proc_show, void *v)
{
	long	n;
	uid_t	user_id;


	user_id = get_current_user()->uid.val;
	if (user_id != 0) return(0);


	safer_learning(&learning);

	seq_printf(proc_show, "INFO learning\n\n");

	seq_printf(proc_show, "FILES:\n\n");
	seq_printf(proc_show, "FILE learning LIST MAX       : %ld\n", learning.file_learning_list_max);

	for (n = 0; n < learning.file_learning_list_max; n++) {
		seq_printf(proc_show, "%s\n", learning.file_learning_list[n]);
	}

	seq_printf(proc_show, "\n\nARGV:\n\n");
	seq_printf(proc_show, "ARGV learning LIST MAX       : %ld\n", learning.file_argv_list_max);

	for (n = 0; n < learning.file_argv_list_max; n++) {
		seq_printf(proc_show, "%s\n", learning.file_argv_list[n]);
	}


	return 0;
}



static int __init safer_learning_show(void)
{
	proc_create_single("safer.learning", 0, NULL, safer_learning_display);
	return 0;
}
fs_initcall(safer_learning_show);









