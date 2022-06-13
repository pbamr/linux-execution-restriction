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

	Program		: safer_info.c
	Path		: fs/


	Makefile
	obj-y				+= safer_info.o
*/




#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>




/* decl. */
struct info_safer_struct {
	bool safer_mode;
	bool printk_mode;
	bool safer_root_list_in_kernel;
	bool no_change;
	u8 search_mode;
	long file_list_max;
	long folder_list_max;
	char **file_list;
	char **folder_list;
};




static struct info_safer_struct info;
extern void info_safer(struct info_safer_struct *info);




static int info_safer_show(struct seq_file *proc_show, void *v)
{
	long n;

	info_safer(&info);
	seq_printf(proc_show, "INFO SAFER\n\n");

	if (info.safer_mode == true)
		seq_printf(proc_show, "MODE SAFER                  : ON\n");
	else	seq_printf(proc_show, "MODE SAFER                  : OFF\n");

	if (info.printk_mode == true)
		seq_printf(proc_show, "MODE PRINTK                 : ON\n");
	else	seq_printf(proc_show, "MODE PRINTK                 : OFF\n");

	if (info.safer_root_list_in_kernel == true)
		seq_printf(proc_show, "MODE SAFER ROOT LIST KERNEL : ON\n");
	else	seq_printf(proc_show, "MODE SAFER ROOT LIST KERNEL : OFF\n");

	if (info.no_change == true)
		seq_printf(proc_show, "MODE SAFER CHANGE ALLOWED   : ON\n");
	else	seq_printf(proc_show, "MODE SAFER CHANGE ALLOWED   : OFF\n");

	seq_printf(proc_show, "FILE LIST MAX               : %ld\n", info.file_list_max);
	seq_printf(proc_show, "FOLDER LIST MAX             : %ld\n", info.folder_list_max);

	seq_printf(proc_show, "MODE SEARCH                 : BSEARCH\n");

	seq_printf(proc_show, "\n\n");

	seq_printf(proc_show, "FOLDER:\n\n");
	for (n = 0; n < info.folder_list_max; n++) {
		seq_printf(proc_show, "%s\n", info.folder_list[n]);
	}

	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "FILES:\n\n");
	for (n = 0; n < info.file_list_max; n++) {
		seq_printf(proc_show, "%s\n", info.file_list[n]);
	}

	return 0;
}



static int __init safer_info(void)
{
	proc_create_single("info.safer", 0, NULL, info_safer_show);
	return 0;
}
fs_initcall(safer_info);

