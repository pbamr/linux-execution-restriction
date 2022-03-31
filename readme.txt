	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2022.03.28

	Program		: safer.c

	Functionality	: Programm execution restriction
			: Like Windows Feature "Safer"
			: Only User
			: No Groups. I don't need it at the moment

			: Extension of SYSCALL <execve>
			: Replaces function <execve> in exec.c. Line 2060

			: Program is compiled without ERRORS and WARNINGS

	Frontend	: fpsafer.pas
			: Simple Control Program for Extension <SYSCALL execve>
			: Only <root>

	LIST		: If you use binary search, a sorted list ist required.
			: ALLOW and DENY list
			: Files and Folder
			: If you use bsearch, you can also select all executable flles in folder.
			: Several thousand entries are then no problem.

	root		: ALLOW LIST for root is fixed in the code

	Standard	: Safer Mode = ON
			: Log Mode = Logs all programs from init

			: 0 = safer ON
			: 1 = safer OFF
			: 2 = State
			: 3 = Log ON
			: 4 = Log OFF
			: 5 = Clear ALLOW List
			: 6 = Clear DENY List
			: 7 = Set ALLOW List
			: 8 = Set DENY List

	Important	: ./foo is not allowed
			: But not absolutely necessary for me.
			: It is not checked whether the program really exists.
			: Ths is not necessary

			: Only "make bzImage" need this feature.
			: The Solutions is Safer OFF.


	Thanks		: Linus Torvalds and ......


			: I would like to remember ALICIA ALONSO and MAYA PLISETSKAYA. Two admirable ballet dancers.
