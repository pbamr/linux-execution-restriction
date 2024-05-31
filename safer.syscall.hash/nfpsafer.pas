(* Copyright (c) 2022/03/28, Peter Boettcher, Germany/NRW, Muelheim Ruhr
 * Urheber: 2022/03/28, Peter Boettcher, Germany/NRW, Muelheim Ruhr

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
 *)

 (* FreePascal:
  * fpc fpsafer.pas
  *
 *)
	
	
	
(*
	Frontend for Linux SYSCALL Extension <execve>

	Autor/Urheber	: Peter Boettcher
			: Muelheim Ruhr
			: Germany
	Date		: 2023.11.15 - 2024.05.26

	Program		: csafer.c
			: Simple Frontend

			: Control Program for Extension <SYSCALL execve>
			: It only works as ROOT

			: If you use binary search, a sorted list ist required.

	List		: ALLOW and DENY list


	Control		:  0 = safer ON
			:  1 = safer OFF
			:  2 = State
			:  3 = printk allowed LOG ON
			:  4 = printk allowed Log OFF
			:  5 = LOCK changes
			:  6 = learning ON
			:  7 = learning OFF
			:  8 = Verbose LOG ON
			:  9 = Verbose LOG OFF
			: 10 = Safer Show LOG ON
			: 11 = Safer Show LOG  OFF
			: 12 = printk deny on
			: 13 = printk deny off

			: 20 = Set FILE List
			: 21 = Set FOLDER List

	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings

			: a:USER-ID;SIZE;HASH;Path
			: d:USER-ID;SIZE;HASH;Path

			: ga:GROUP-ID;HASH;Path
			: gd:GROUP-ID;HASH;Path

			: ai:USER-ID;SIZE;HASH;PATH/python
			: a:ai:USER-ID;SIZE;HASH;PATH/python-script

			: Example:
			: a:100;1224;HASH;/bin/test		= allow file
			: a:100;1234;HASH;/bin/test1		= allow file
			: a:100;/usr/sbin/			= allow Folder

			: d:100;HASH;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/			= deny folder

			: ga:100;usr/sbin/			= allow group folder
			: gd:100;/usr/bin/			= deny group folder
			: gd:101;1234;HASH;/usr/bin/mc		= deny group file
			: ga:101;1234;HASH;/usr/bin/mc		= allow group file



			: ai:100;1234;HASH;/bin/python		= allow file
			: a:100;1234;HASH;/bin/test1.py		= allow file

	program start	:
			: python = allone      = not allowed
			: python /PATH/test.py = allowed
			: test1.py             = allowed



			: It is up to the ADMIN to keep the list reasonable according to these rules!


	I would like to remember ALICIA ALONSO, MAYA PLISETSKAYA, CARLA FRACCI, EVA EVDOKIMOVA, VAKHTANG CHABUKIANI and the
	"LAS CUATRO JOYAS DEL BALLET CUBANO". Admirable ballet dancers.


*)


	
{$mode objfpc}{$H+}
		
	
	
	
	
Uses
	linux,
	syscall,
	sysutils,
	strutils,
	dateUtils,
	classes;
	
	
	
{$define NEW_SYSCALLVERSION}
//{$define SYSCALL_VERSION}

	
	
	
const
	{$ifdef SYSCALL_VERSION}
		SYSCALL_NR	= 59;
	{$else NEW_SYSCALLVERSION}
		SYSCALL_NR	= 501;
	{$endif SYSCALL_VERSION}

	
	
	
var
	WORK_LIST	: array of ^char;
	NUMBER		: qword;
	
	LIST		: TStringList;
	N_LIST		: TStringList;
	n		: qword;
	




const
	SAFER_ON = 0;
	SAFER_OFF = 1;

	STAT = 2;

	PRINTK_ALLOWED_ON = 3;
	PRINTK_ALLOWED_OFF = 4;

	PRINTK_DENY_ON = 12;
	PRINTK_DENY_OFF = 13;

	SAFER_LOCK = 5;

	PRINTK_LEARNING_ON = 6;
	PRINTK_LEARNING_OFF = 7;

	PRINTK_ARGV_ON = 8;
	PRINTK_ARGV_OFF = 9;

	PRINTK_SHOW_ON = 10;
	PRINTK_SHOW_OFF = 11;

	LIST_PROG = 20;
	LIST_FOLDER = 21;

	SAFER_SORT = 30;










	
	
	
	
Procedure ErrorMessage;
begin
	writeln('fpsafer, 2022/03 Peter Boettcher, Germany, Muelheim Ruhr');
	writeln('VERSION            : PASCAL 0, fpc, LINUX VERSION');
	writeln;
	writeln('FreePascal Project : www.freepascal.org');
	writeln('LGPL               : www.gnu.org');
	writeln('Special Thanks     : Niklaus Wirth');
	writeln;
	writeln('SYSCALL     :  ',  SYSCALL_NR);
	writeln;
	writeln('Parameter   :  <SON>     Safer ON');
	writeln('Parameter   :  <SOFF>    Safer OFF');
	writeln;
	writeln('Parameter   :  <STAT>    Safer STAT');
	writeln;
	writeln('Parameter   :  <PAON>    Safer Printk ALLOWED ON');
	writeln('Parameter   :  <PAOFF>   Safer Printk ALLOWED OFF');
	writeln;
	writeln('Parameter   :  <PDON>    Safer Printk DENY ON');
	writeln('Parameter   :  <PDOFF>   Safer Printk DENY OFF');
	writeln;
	writeln('Parameter   :  <SLOCK>   Safer DO NOT allowed any more changes');
	writeln;
	writeln('Parameter   :  <SLON>    Safer MODE: LEARNING ON');
	writeln('Parameter   :  <SLOFF>   Safer MODE: LEARNING OFF');
	writeln;
	writeln('Parameter   :  <SVON>    Safer MODE: VERBOSE PARAM ON');
	writeln('Parameter   :  <SVOFF>   Safer MODE: VERBOSE PARAM OFF');
	writeln;
	writeln('Parameter   :  <SHOWON>  Safer MODE: SAFER SHOW ONLY ON');
	writeln('Parameter   :  <SHOWOFF> Safer MODE: SAFER SHOW ONLY OFF');
	writeln;
	writeln('Parameter   :  <PLIST>   Safer SET FILE LIST');
	writeln('            :  <safer list>');
	writeln;
	writeln('Parameter   :  <FLIST>   Safer SET FOLDER LIST');
	writeln('            :  <safer list>');
	writeln;
	writeln('Parameter   :  <SORT>    Safer LIST SORT');
	writeln('            :  <safer list>');
	writeln;
	writeln;
	halt(0);
end;
	
	
	
	
	
Function strncmp(str0 : ansistring; str1 : ansistring; Elements : qword) : integer;
begin
	exit(CompareStr(copy(str0, 0, Elements), copy(str1, 0, Elements)));
end;
	
	
	
	
	
	
	
	
//simple
begin
	if ParamCount = 1 then begin

		while true do begin

			if ParamStr(1) = 'SON' then begin NUMBER := SAFER_ON; break; end;
			if ParamStr(1) = 'SOFF' then begin NUMBER := SAFER_OFF; break; end;

			if ParamStr(1) = 'STAT' then begin NUMBER := STAT; break; end;

			if ParamStr(1) = 'PAON' then begin NUMBER := PRINTK_ALLOWED_ON; break; end;
			if ParamStr(1) = 'PAOFF' then begin NUMBER := PRINTK_ALLOWED_OFF; break; end;

			if ParamStr(1) = 'PDON' then begin NUMBER := PRINTK_DENY_ON; break; end;
			if ParamStr(1) = 'PDOFF' then begin NUMBER := PRINTK_DENY_OFF; break; end;;

			if ParamStr(1) = 'SLOCK' then begin NUMBER := SAFER_LOCK; break; end;

			if ParamStr(1) = 'SLON' then begin NUMBER := PRINTK_LEARNING_ON; break; end;
			if ParamStr(1) = 'SLOFF' then begin NUMBER := PRINTK_LEARNING_OFF; break; end;

			if ParamStr(1) = 'SVON' then begin NUMBER := PRINTK_ARGV_ON; break; end;
			if ParamStr(1) = 'SVOFF' then begin NUMBER := PRINTK_ARGV_OFF; break; end;

			if ParamStr(1) = 'SHOWON' then begin NUMBER := PRINTK_SHOW_ON; break; end;
			if ParamStr(1) = 'SHOWOFF' then begin NUMBER := PRINTK_SHOW_OFF; break; end;

			if ParamStr(1) = 'PLIST' then begin NUMBER := LIST_PROG; break; end;
			if ParamStr(1) = 'FLIST' then begin NUMBER := LIST_FOLDER; break; end;

			if ParamStr(1) = 'SORT' then begin NUMBER := SAFER_SORT; break; end;

			ErrorMessage;
		end;;



{$ifdef SYSCALL_VERSION}
		writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER));
{$else NEW_SYSCALLVERSION}
		writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER));
{$endif SYSCALL_VERSION}
		halt(0);
	end;
	
	if ParamCount = 2 then begin
		while true do begin
			if ParamStr(1) = 'PLIST' then begin NUMBER := LIST_PROG; break; end;
			if ParamStr(1) = 'FLIST' then begin NUMBER := LIST_FOLDER; end;
			if ParamStr(1) = 'SORT' then begin NUMBER := SAFER_SORT; end;
			ErrorMessage;
		end;

		case NUMBER of
			//FILES
			20:	begin
					LIST := TStringList.Create;
					LIST.Sorted := TRUE;
					LIST.Duplicates := dupIgnore;		//dupIgnore, dupAccept, dupError
					List.CaseSensitive := TRUE;
					try
						LIST.LoadFromFile(ParamStr(2));
					except
						LIST.Free;
						ErrorMessage;
					end;
					
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupIgnore;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to LIST.Count - 1 do begin
						if copy(LIST[n], 0, 2) = 'a:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(LIST[n], 0, 3) = 'ai:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						

						if copy(LIST[n], 0, 4) = 'gai:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						

						if copy(List[n], 0, 2) = 'd:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 3) = 'ga:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 3) = 'gd:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);					//RESERVIEREN
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));		//elements
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));				
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST[n]);
						writeln(WORK_LIST[n+1]);
					end;
					
					{$ifdef SYSCALL_VERSION}
					writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER, qword(WORK_LIST)));
					{$else NEW_SYSCALLVERSION}
					writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER, qword(WORK_LIST)));
					{$endif SYSCALL_VERSION}
					halt(0);
				end;
			
			//FOLDER
			21:	begin
					LIST := TStringList.Create;
					LIST.Sorted := TRUE;
					LIST.Duplicates := dupIgnore;		//dupIgnore, dupAccept, dupError
					List.CaseSensitive := TRUE;
					try
						LIST.LoadFromFile(ParamStr(2));
					except
						LIST.Free;
						ErrorMessage;
					end;
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupIgnore;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to LIST.Count - 1 do begin
						if copy(LIST[n], 0, 2) = 'a:' then begin
							if LIST[n][length(LIST[n])] <> '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 2) = 'd:' then begin
							if LIST[n][length(LIST[n])] <> '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 3) = 'ga:' then begin
							if LIST[n][length(LIST[n])] <> '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 3) = 'gd:' then begin
							if LIST[n][length(LIST[n])] <> '/' then continue;
							N_LIST.add(List[n]);
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);					//RESERVIEREN
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));		//elements
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));				
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST[n]);
						writeln(WORK_LIST[n+1]);
					end;
					
					{$ifdef SYSCALL_VERSION}
					writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER, qword(WORK_LIST)));
					{$else NEW_SYSCALLVERSION}
					writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER, qword(WORK_LIST)));
					{$endif SYSCALL_VERSION}
					halt(0);
				end;
				
			//FILES
			30:	begin
					LIST := TStringList.Create;
					LIST.Sorted := TRUE;
					LIST.Duplicates := dupIgnore;		//dupIgnore, dupAccept, dupError
					List.CaseSensitive := TRUE;
					try
						LIST.LoadFromFile(ParamStr(2));
					except
						LIST.Free;
						ErrorMessage;
					end;
					
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupIgnore;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to LIST.Count - 1 do begin
						if copy(LIST[n], 0, 2) = 'a:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						

						if copy(LIST[n], 0, 4) = 'gai:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(LIST[n], 0, 3) = 'ai:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						
						if copy(List[n], 0, 2) = 'd:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 3) = 'ga:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
							continue;
						end;
						
						if copy(List[n], 0, 3) = 'gd:' then begin
							if LIST[n][length(LIST[n])] = '/' then continue;
							N_LIST.add(List[n]);
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);					//RESERVIEREN
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));		//elements
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));				
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST[n]);
						writeln(WORK_LIST[n+1]);
					end;
					
					halt(0);
				end;
			
			
			else ErrorMessage;
		end;
		
		
	end;
	
	ErrorMessage;
end.
	

