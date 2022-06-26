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

	Program		: safer_history.c
	Path		: fs/


	Makefile
	obj-y		+= safer_history.o
*/




#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>




/* decl. */
struct  safer_history_struct {
	long file_history_list_max;
	char **file_history_list;
	long file_argv_list_max;
	char **file_argv_list;
};


static struct safer_history_struct history;
extern void safer_history(struct safer_history_struct *history);



static int safer_history_display(struct seq_file *proc_show, void *v)
{
	long n;

	safer_history(&history);

	seq_printf(proc_show, "INFO history\n\n");

	seq_printf(proc_show, "FILES:\n\n");
	seq_printf(proc_show, "FILE history LIST MAX       : %ld\n", history.file_history_list_max);

	for (n = 0; n < history.file_history_list_max; n++) {
		seq_printf(proc_show, "%s\n", history.file_history_list[n]);
	}

	seq_printf(proc_show, "\n\nARGV:\n\n");
	seq_printf(proc_show, "ARGV history LIST MAX       : %ld\n", history.file_argv_list_max);

	for (n = 0; n < history.file_argv_list_max; n++) {
		seq_printf(proc_show, "%s\n", history.file_argv_list[n]);
	}


	return 0;
}



static int __init safer_history_show(void)
{
	proc_create_single("safer.history", 0, NULL, safer_history_display);
	return 0;
}
fs_initcall(safer_history_show);









