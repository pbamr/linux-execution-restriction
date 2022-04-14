	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.03.28

	Program		: safer.c
	Path		: fs/

	Functionality	: Program execution restriction
			: Like Windows Feature "Safer"
			: GROUPS and USER.

			: Extension of SYSCALL <execve>
			: Replaces function <execve> in exec.c. Line 2060

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas
			: Simple Control Program for Extension <SYSCALL execve>
			: It only works as ROOT

	LIST		: If you use binary search, a sorted list ist required
			: ALLOW and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable files in folder
			: Several thousand entries are then no problem.

	root		: ALLOW LIST for root is fixed in the code

	Standard	: Safer Mode = ON
			: Log Mode = Logs all programs from init

			: 999900 = safer ON
			: 999901 = safer OFF
			: 999902 = State
			: 999903 = Log ON
			: 999904 = Log OFF
			: 999905 = Search bsearch
			: 999906 = Search lin. search

			: 999907 = Clear ALLOW List
			: 999908 = Clear DENY List
			: 999909 = Clear GROUP ALLOW List
			: 999910 = Clear GROUP DENY List

			: 999920 = Set ALLOW List
			: 999921 = Set DENY List
			: 999922 = Set GROUP ALLOW List
			: 999923 = Set GROUP DENY List

	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings
			: string = allow/deny:USER-ID;PATH
			: string = allow/deny:GROUP-ID;PATH

			: Example:
			: a:100;/bin/test		= allow file
			: a:100;/bin/test1		= allow file
			: a:100;/usr/sbin/		= allow Folder

			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny file

			: ga:100;/usr/sbin/		= allow group folder
			: gd:100;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;/usr/bin/mc		= allow group file

			: The program turns it into USER-ID;PATH
			: 100;/bin/test1

			: It is up to the ADMIN to keep the list reasonable according to these rules!


	Important	: ./foo is not allowed
			: But not absolutely necessary for me
			: It is not checked whether the program really exists
			: Ths is not necessary

			: "make bzImage" need this feature
			: The Solutions is Safer OFF

	Thanks		: Linus Torvalds and others
			: Florian Klaempfl and others


			: I would like to remember ALICIA ALONSO and MAYA PLISETSKAYA. Two admirable ballet dancers.
