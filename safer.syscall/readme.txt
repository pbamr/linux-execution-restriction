	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.03.28, 2023.07.11

	Program		: safer.c
	Path		: fs/

	Functionality	: Program execution restriction
			: Like Windows Feature "Safer"
			: GROUPS and USER.

			: Extension of SYSCALL <execve>
			: Replaces function <execve> in exec.c. Line 2060

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas, csafer
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

	Control		:  0 = safer ON
			:  1 = safer OFF
			:  2 = State
			:  3 = Log ON
			:  4 = Log OFF
			
			:  5 = Clear FILE List
			:  6 = Clear FOLDER List

			:  7 = ROOT LIST IN KERNEL ON
			:  8 = ROOT LIST IN KERNEL OFF

			: 20 = Set FILE List
			: 21 = Set FOLDER List

	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings
			: string = allow/deny:USER-ID;FILE-SIZE;PATH
			: string = allow/deny:GROUP-ID;PATH

			: Example:
			: a:100;1234;/bin/test		= allow file
			: a:100;1234;/bin/test1		= allow file
			: a:100;1234;/usr/sbin/		= allow Folder

			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny file

			: ga:100;1234;/usr/sbin/	= allow group folder
			: gd:100;1234;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;1234;/usr/bin/mc	= allow group file


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
