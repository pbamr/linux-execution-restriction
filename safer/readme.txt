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
	Date		: 2022.04.22, 2023.05.23 2023.11.26

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 6.6
			  Lenovo X230, T460, T470

	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer"
			: Control only works as root

			: USER and GROUPS
			  IMPORTANT: file size will test

			: Extension of SYSCALL <execve>
			  You found <replaces> under "pb_safer"

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas, csafer.c
			: Simple Control Program for Extension <SYSCALL execve>
			: It only works as <root>

	LIST		: If you use binary search, a sorted list ist required
			: ALLOWED and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable files in folder
			: Several thousand entries are then no problem.

	root		: ALLOWED LIST for root is fixed in the code


	Standard	: Safer Mode = ON
			: Log Mode = Logs all programs from init

			: 999900 = safer ON
			: 999901 = safer OFF
			: 999902 = State
			: 999903 = Log ON
			: 999904 = Log OFF

			: 999905 = LOCK changes

			: 999906 = learning on
			: 999907 = learning off


			: 999920 = Set FILE List
			: 999921 = Set FOLDER List


	Important	: ./foo is not allowed
			: But not absolutely necessary for me
			: It is not checked whether the program really exists
			: This is not necessary

			: "make bzImage" need this feature
			: The Solutions is Safer OFF

			: scripts will test
			  scripts will test in this form: "python Path/prog"
			  scripts in this form ar allowed: "/path/prog"


	FILE/FOLDER List: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

	PROG/FILE
			: a: allowed
			: d: deny

			: ga: group allowed
			: da: group deny

			: ai: interpreter
			      interpreter = arg/param/file only
			      First allowed Interpreter
			      Second allow Interpreter File


		FOLDER
			: a:  Folder allowed
			: d:  Folder deny

			: ga: group folder allowed
			: gd: group folder deny


		Example
			: string = USER-ID;FILE-SIZE;PATH
			: string = GROUP-ID;FILE-SIZEPATH
			: string = File Size

			: string = allow:USER-ID;FILE-SIZE;PATH
			: string = deny:GROUP-ID;PATH

			: a:USER-ID;Path
			: d:USER-ID;Path

			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path

			: ai:USER-ID;PATH

			: Example: user
			: a:100;1224;/bin/test		= allow file
			: a:100;1234;/bin/test1		= allow file
			: a:100;/usr/sbin/		= allow Folder

			: Example: user
			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny folder

			: Example: Group
			: ga:100;/usr/sbin/		= allow group folder
			: gd:100;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;1234;/usr/bin/mc	= allow group file

	Folder		: Example: User Folder. IMPORTAND: SLASH at the End is Folder
			  a:0;/Folder/			user allowed FOLDER
			  ga:0;/Folder/			group allowed FOLDER

			  d:0;/Folder/			user deny FOLDER
			  gd:0/Folder/			group deny FOLDER

	Interpreter
			: Interpreter <USER> ONLY. INTERPTETER FILE <USER> <GROUP> allowed

			: ai:1000;12342/usr/bin/python = allow INTERPRETER
			: a:1000;123422/usr/bin/hello.py = allow INTERPRETER FILE
			: ga:1000;123422/usr/bin/hello.py = allow INTERPRETER FILE

			  - Interpreter not allowed
			  - Interpreter + Interpreter File allowed
			  - Interpreter File allowed

			  python = allone = not allowed
			  python hello.py = allowed  is python allawed and hello.py is allowed
			  hello.py = allowed  is python allowed and hello.py allowed


			: Important:
			: java is special
			: ".jar" Files/Prog. only
			: -classpath is not allowed

			: It is up to the ADMIN to keep the list reasonable according to these rules!


	Thanks		: Linus Torvalds and others


	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, CARLA FRACCI, EVA EVDOKIMOVA, VAKHTANG CHABUKIANI and the
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Admirable ballet dancers.
	

*/

