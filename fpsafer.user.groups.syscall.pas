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
	Date		: 2022.03.28
	
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
			:  5 = Search bsearch
			:  6 = Search linar search
			
			:  7 = Clear ALLOW List
			:  8 = Clear DENY List
			:  9 = Clear GROUP ALLOW LIST
			: 10 = CLEAR GROUP DENY LIST
			
			: 20 = Set ALLOW List
			: 21 = Set DENY List
			: 22 = Set GROUP ALLOW LIST
			: 23 = Set GROUP DENY LIST
	
	
	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings
	
			: string = allow/deny:USER-ID;PATH
			: string = allow/deny:GROUP-ID;PATH
	
			: a:USER-ID;Path
			: d:USER-ID;Path
	
			: ga:GROUP-ID;Path
			: gd:GROUP-ID;Path
	
			: Example:
			: a:100;/bin/test		= allow file
			: a:100;/bin/test1		= allow file
			: a:100;/usr/sbin/		= allow Folder
	
			: d:100;/usr/sbin/test		= deny file
			: d:100;/usr/sbin/		= deny folder
	
			: ga:100;/usr/sbin/		= allow group folder
			: gd:100;/usr/bin/		= deny group folder
			: gd:101;/usr/bin/mc		= deny group file
			: ga:101;/usr/bin/mc		= allow group file
	
			: The program turns it into USER-ID;PATH
			: 100;/bin/test1
	
			: It is up to the ADMIN to keep the list reasonable according to these rules!
	
	
	
	Thanks		: Niklaus Wirth
			: Florian Klaempfl and others
	
	I would like to remember ALICIA ALONSO and MAYA PLISETSKAYA. Two admirable ballet dancers.


*)


	
{$mode objfpc}{$H+}
		
	
	
	
	
Uses
	linux,
	syscall,
	sysutils,
	strutils,
	dateUtils,
	classes;
	
	
	
	
	
	
const
	SYSCALL_NR	= 501;		//59;		//syscall execv
	
	
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
	writeln('Parameter   :  0 Safer ON');
	writeln('Parameter   :  1 Safer OFF');
	writeln('Parameter   :  2 Safer STATE');
	writeln('Parameter   :  3 Safer Printk ON');
	writeln('Parameter   :  4 Safer Printk OFF');
	writeln('Parameter   :  5 Safer SEARCH MODE bsearch');
	writeln('Parameter   :  6 Safer SEARCH MODE LINEAR Search');
	writeln;
	writeln('Parameter   :  7 Safer CLEAR ALLOW LIST');
	writeln('Parameter   :  8 Safer CLEAR DENY LIST');
	writeln;
	writeln('Parameter   :  9 Safer CLEAR ALLOW GROUP LIST');
	writeln('Parameter   : 10 Safer CLEAR DENY GROUP LIST');
	writeln;
	writeln('Parameter   : 20 Safer SET ALLOW LIST');
	writeln('            :    <safer list>');
	writeln;
	writeln('Parameter   : 21 Safer SET DENY LIST');
	writeln('            :    <safer list>');
	writeln;
	writeln('Parameter   : 22 Safer SET ALLOW GROUP LIST');
	writeln('            :    <safer list>');
	writeln;
	writeln('Parameter   : 23 Safer SET DENY GROUP LIST');
	writeln('            :    <safer list>');

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
		if NUMBER > 10 then ErrorMessage;
		
		writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER));
		halt(0);
	end;
	
	
	if ParamCount = 2 then begin
		if TryStrToQword(ParamStr(1), NUMBER) = FALSE then ErrorMessage;
		
		case NUMBER of
			//ALLOW List
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
					
					
					for n := LIST.Count - 1 downto 1 do begin
						if strncmp(LIST[n-1], LIST[n], length(LIST[n-1])) = 0 then LIST.delete(n);
					end;
					
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupAccept;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to List.Count - 1 do begin
						if copy(List[n], 0, 2) = 'a:' then begin
							N_LIST.add(copy(List[n], 3, length(List[n])));
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
						writeln('a:' + WORK_LIST[n+1]);
					end;
					
					writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER, qword(WORK_LIST)));
					
					halt(0);
				end;
			
			//DENY LIST
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
					
					for n := LIST.Count - 1 downto 1 do begin
						if strncmp(LIST[n-1], LIST[n], length(LIST[n-1])) = 0 then LIST.delete(n);
					end;
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupAccept;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to List.Count - 1 do begin
						if copy(List[n], 0, 2) = 'd:' then begin
							N_LIST.add(copy(List[n], 3, length(List[n])));
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST[n]);
						writeln('d:' + WORK_LIST[n+1]);
					end;
					
					writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER, qword(WORK_LIST)));
					
					halt(0);
				end;
			
			//GROUP ALLOW List
			22:	begin 
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
					
					for n := LIST.Count - 1 downto 1 do begin
						if strncmp(LIST[n-1], LIST[n], length(LIST[n-1])) = 0 then LIST.delete(n);
					end;
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupAccept;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to List.Count - 1 do begin
						if copy(List[n], 0, 3) = 'ga:' then begin
							N_LIST.add(copy(List[n], 4, length(List[n])));
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST[n]);
						writeln('ga:' + WORK_LIST[n+1]);
					end;
					
					writeln(do_SysCall(SYSCALL_NR, 999900 + NUMBER, qword(WORK_LIST)));
					
					halt(0);
				end;
			
			//GROUP DENY LIST
			23:	begin 
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
					
					for n := LIST.Count - 1 downto 1 do begin
						if strncmp(LIST[n-1], LIST[n], length(LIST[n-1])) = 0 then LIST.delete(n);
					end;
					
					N_LIST := TStringList.Create;
					N_LIST.Sorted := TRUE;
					N_LIST.Duplicates := dupAccept;
					N_List.CaseSensitive := TRUE;
					
					for n := 0 to List.Count - 1 do begin
						if copy(List[n], 0, 3) = 'gd:' then begin
							N_LIST.add(copy(List[n], 4, length(List[n])));
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST[n]);
						writeln('gd:' + WORK_LIST[n+1]);
					end;
					
					writeln(do_SysCall(SYSCALL_NR,  999900 + NUMBER, qword(WORK_LIST)));
					
					halt(0);
				end;
			
			else ErrorMessage;
		end;
		
		
	end;
	
	ErrorMessage;
end.
	

