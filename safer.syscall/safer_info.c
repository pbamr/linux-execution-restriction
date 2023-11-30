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



  I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, VAKHTANG CHABUKIANI and the "LAS CUATRO JOYAS DEL BALLET CUBANO".
  Admirable ballet dancers.

 */



/*
	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.03.28

	Program		: safer_info.c
	Path		: fs/


	Makefile
	obj-y		+= safer_info.o
*/




#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>




/* proto */
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






static struct safer_info_struct info;
extern void safer_info(struct safer_info_struct *info);




static int safer_info_display(struct seq_file *proc_show, void *v)
{
	long n;
	uid_t	user_id;

	user_id = get_current_user()->uid.val;
	if (user_id != 0) return(0);

	safer_info(&info);
	seq_printf(proc_show, "INFO SAFER\n\n");

	if (info.safer_mode == true)
		seq_printf(proc_show, "MODE SAFER                  : ON\n");
	else	seq_printf(proc_show, "MODE SAFER                  : OFF\n");

	if (info.printk_mode == true)
		seq_printf(proc_show, "MODE PRINTK                 : ON\n");
	else	seq_printf(proc_show, "MODE PRINTK                 : OFF\n");

	if (info.learning_mode == true)
		seq_printf(proc_show, "MODE LEARNING               : ON\n");
	else	seq_printf(proc_show, "MODE LEARNING               : OFF\n");

	if (info.change_mode == true)
		seq_printf(proc_show, "MODE SAFER CHANGE ALLOWED   : ON\n");
	else	seq_printf(proc_show, "MODE SAFER CHANGE ALLOWED   : OFF\n");


	seq_printf(proc_show, "FILE LIST MAX               : %ld\n", info.global_list_prog_len);
	seq_printf(proc_show, "FOLDER LIST MAX             : %ld\n", info.global_list_folder_len);

	seq_printf(proc_show, "MODE SEARCH                 : BSEARCH\n");

	seq_printf(proc_show, "\n\n");

	seq_printf(proc_show, "FOLDER:\n\n");
	for (n = 0; n < info.global_list_folder_len; n++) {
		seq_printf(proc_show, "%s\n", info.global_list_folder[n]);
	}

	seq_printf(proc_show, "\n\n");
	seq_printf(proc_show, "FILES:\n\n");
	for (n = 0; n < info.global_list_prog_len; n++) {
		seq_printf(proc_show, "%s\n", info.global_list_prog[n]);
	}

	return 0;
}



static int __init safer_info_show(void)
{
	proc_create_single("safer.info", 0, NULL, safer_info_display);
	return 0;
}
fs_initcall(safer_info_show);

