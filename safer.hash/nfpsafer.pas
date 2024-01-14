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
	Date		: 2023.07.03
	
	Program		: fpsafer.pas
			: Simple Frontend
	
			: Control Program for Extension <SYSCALL execve>
			: It only works as ROOT
	
			: If you use binary search, a sorted list ist required.
	
	List		: ALLOW and DENY list
			: a: = ALLOW, d: = DENY
			: a:USER;Path
			: d:USER;Path
	
	
	Control		:  0 = safer ON
			:  1 = safer OFF
			:  2 = State
			:  3 = Log ON
			:  4 = Log OFF
			
			:  5 = Clear FILE List
			:  6 = Clear FOLDER List
			
			: 20 = Set FILE List
			: 21 = Set FOLDER List
	
	
	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings
	
			: string = allow:USER-ID;FILE-SIZE;PATH
			: string = deny:GROUP-ID;PATH
	
			: a:USER-ID;Path
			: d:USER-ID;Path
	
			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path
	
			: Example:
			: a:100;1234;/bin/test		= allow file
			: a:100;1234;/bin/test1		= allow file
			: a:100;/usr/sbin/		= allow Folder
	
			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny folder
	
			: ga:100;/usr/sbin/		= allow group folder
			: gd:100;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;1234;/usr/bin/mc	= allow group file
	
	
			: Example: User
			: user
			: as:1000;12342/usr/bin/python	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow 
			: as:1000;123422/usr/bin/ruby	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow

			: Example: Group
			: gas:1000;1234/usr/bin/python	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow
			: gas:1000;12343/usr/bin/php	= allow Scripts Language/Interpreter/check parameter/script program /without script file is not allow

			: Important:
			: java is special
			: java need no "as or gas"

			: It is up to the ADMIN to keep the list reasonable according to these rules!
	
	
	
	Thanks		: Niklaus Wirth
			: Florian Klaempfl and others
	
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
		SYSCALL_NR	= 459;
	{$endif SYSCALL_VERSION}

	
	
	
var
	WORK_LIST	: array of ^char;
	NUMBER		: qword;
	
	LIST		: TStringList;
	N_LIST		: TStringList;
	n		: qword;
	
	
	
	
	
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
	writeln('Parameter   :  0 Safer ON');
	writeln('Parameter   :  1 Safer OFF');
	writeln('Parameter   :  2 Safer STATE');
	writeln('Parameter   :  3 Safer Printk ON');
	writeln('Parameter   :  4 Safer Printk OFF');
	writeln;
	writeln;
	writeln('Parameter   :  5 Safer DO NOT allowed any more changes');
	writeln;

	writeln('Parameter   :  6 Safer LEARNING ON');
	writeln('Parameter   :  7 Safer LEARNING OFF');
	writeln;

	writeln('Parameter   :  8 Safer VERBOSE PARAM ON');
	writeln('Parameter   :  9 Safer VERBOSE PARAM OFF');
	writeln;

	writeln('Parameter   : 10 Safer SAFER SHOW ONLY ON');
	writeln('Parameter   : 11 Safer SAFER SHOW ONLY OFF');
	writeln;

	writeln('Parameter   : 20 Safer SET FILE LIST');
	writeln('            :    <safer list>');
	writeln;
	writeln('Parameter   : 21 Safer SET FOLDER LIST');
	writeln('            :    <safer list>');
	writeln;
	writeln('Parameter   : 30 Safer SORT LIST');
	writeln('            :    <safer list>');

	writeln;

	writeln;
	writeln;
	halt(1);
end;
	
	
	
	
	
Function strncmp(str0 : ansistring; str1 : ansistring; Elements : qword) : integer;
begin
	exit(CompareStr(copy(str0, 0, Elements), copy(str1, 0, Elements)));
end;
	
	
	
	
	
	
	
	
//simple
begin
	if ParamCount = 1 then begin
		if TryStrToQword(ParamStr(1), NUMBER) = FALSE then ErrorMessage;
		if NUMBER > 11 then ErrorMessage;
		
		
		
{$ifdef SYSCALL_VERSION}
		writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999900 + NUMBER));
{$else NEW_SYSCALLVERSION}
		writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER));
{$endif SYSCALL_VERSION}
		halt(0);
	end;
	
	if ParamCount = 2 then begin
		if TryStrToQword(ParamStr(1), NUMBER) = FALSE then ErrorMessage;
		
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
	

