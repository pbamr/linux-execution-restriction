	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.04.22, 2023.05.23

	Program		: safer.c
	Path		: fs/

	TEST		: Kernel 6.0 - 6.3
			  Lenovo X230, T460

	Attention	: Do not use safer.syscall. This version has yet to be edited.


	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer/applocker"
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

			: 999905 = Clear FILE List
			: 999906 = Clear FOLDER List

			: 999907 = ROOT LIST IN KERNEL ON
			: 999908 = ROOT LIST IN KERNEL OFF

			: 999909 = LOCK changes

			: 999910 = learning ON
			: 999911 = learning OFF

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

			: string = USER-ID;FILE-SIZE;PATH
			: string = GROUP-ID;FILE-SIZEPATH
			: string = File Size

			: string = allow:USER-ID;FILE-SIZE;PATH
			: string = deny:GROUP-ID;PATH

			: a:USER-ID;Path
			: d:USER-ID;Path

			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path

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

			: Example: User
			: user
			: as:1000;12342/usr/bin/python	= allow Scripts Language/Interpreter/check parameter/script program /without script-file is not allow 
			: as:1000;123422/usr/bin/ruby	= allow Scripts Language/Interpreter/check parameter/script program /without script-file is not allow

			: Example: Group
			: gas:1000;1234/usr/bin/python	= allow Scripts Language/Interpreter/check parameter/script program /without script-file is not allow
			: gas:1000;12343/usr/bin/php	= allow Scripts Language/Interpreter/check parameter/script program /without script-file is not allow

			: Important:
			: java is special
			: java need no "as or gas"

			: It is up to the ADMIN to keep the list reasonable according to these rules!


	Thanks		: Linus Torvalds and others
		


	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, CARLA FRACCI, EVA EVDOKIMOVA, VAKHTANG CHABUKIANI and the
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Admirable ballet dancers.
	Admirable ballet dancers.
