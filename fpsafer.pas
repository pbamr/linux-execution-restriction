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
	
	
	Control		: 0 = safer ON
			: 1 = safer OFF
			: 2 = State
			: 3 = Log ON
			: 4 = Log OFF
			: 5 = Clear ALLOW List
			: 6 = Clear DENY List
			: 7 = Set ALLOW List
			: 8 = Set DENY List
	
	
	ALLOW/DENY List	: 2 DIM. dyn. char Array = string
			: String 0 = Number of strings
	
			: string = allow/deny:USER-ID;PATH
	
			: Example:
			: a:100;/bin/test		= file
			: a:100;/bin/test1		= file
			: a:100;/usr/sbin		= Folder
	
			: rules besearch
			: d:100;/usr/sbin/test		= file		avoid
			: d:100;/usr/sbin/test2		= file		avoid
	
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
	SYSCALL_NR	= 59;		//syscall execv
	
	
var
	WORK_LIST	: array of ^char;
	SUB_NUMBER	: qword;
	
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
	writeln;
	writeln('Parameter   :  5 Safer CLEAR ALLOW LIST');
	writeln;
	writeln('Parameter   :  6 Safer CLEAR DENY LIST');
	writeln;
	writeln('Parameter   :  7 Safer SET ALLOW LIST');
	writeln('            :    <safer list>');
	writeln;
	writeln('Parameter   :  8 Safer SET DENY LIST');
	writeln('            :    <safer list>');
	writeln;
	halt(1);
end;
	
	
	
	
	
//simple
begin
	if ParamCount = 1 then begin
		if TryStrToQword(ParamStr(1), SUB_NUMBER) = FALSE then ErrorMessage;
		if SUB_NUMBER > 6 then ErrorMessage;
		
		writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999999, SUB_NUMBER));
		halt(0);
	end;
	
	
	if ParamCount = 2 then begin
		if TryStrToQword(ParamStr(1), SUB_NUMBER) = FALSE then ErrorMessage;
		
		case SUB_NUMBER of
			//ALLOW List
			7:	begin 
					LIST := TStringList.Create;
					try
						LIST.LoadFromFile(ParamStr(2));
					except
						LIST.Free;
						ErrorMessage;
					end;
					
					LIST.Sorted := TRUE;
					
					
					N_LIST := TStringList.Create;
					for n := 0 to List.Count - 1 do begin
						if copy(List.Strings[n], 0, 2) = 'a:' then begin
							N_LIST.add(copy(List.Strings[n], 3, length(List.Strings[n])));
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					N_LIST.Sorted := TRUE;
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST.Strings[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST.Strings[n]);
						writeln('a:' + WORK_LIST[n+1]);
					end;
					
					writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999999, SUB_NUMBER, qword(WORK_LIST)));
					
					halt(0);
				end;
			
			//DENY LIST
			8:	begin 
					LIST := TStringList.Create;
					try
						LIST.LoadFromFile(ParamStr(2));
					except
						LIST.Free;
						ErrorMessage;
					end;
					
					LIST.Sorted := TRUE;
					
					
					N_LIST := TStringList.Create;
					for n := 0 to List.Count - 1 do begin
						if copy(List.Strings[n], 0, 2) = 'd:' then begin
							N_LIST.add(copy(List.Strings[n], 3, length(List.Strings[n])));
						end;
					end;
					
					if N_LIST.count = 0 then begin writeln('ERROR: NO ELEMENT IN LIST'); halt(0); end;
					N_LIST.Sorted := TRUE;
					
					setlength(WORK_LIST, N_LIST.COUNT + 1);
					WORK_LIST[0] := StrAlloc(length(IntToStr(N_LIST.COUNT)));
					StrpCopy(WORK_LIST[0], IntToStr(N_LIST.COUNT));
					
					writeln(WORK_LIST[0]);
					for n := 0 to N_LIST.COUNT - 1 do begin
						WORK_LIST[n+1] := StrAlloc(length(N_LIST.Strings[n]) + 1);
						StrpCopy(WORK_LIST[n+1], N_LIST.Strings[n]);
						writeln('d:' + WORK_LIST[n+1]);
					end;
					
					writeln(do_SysCall(SYSCALL_NR, 0, 0, 0, 999999, SUB_NUMBER, qword(WORK_LIST)));
					
					halt(0);
				end;
			
			else ErrorMessage;
		end;
		
		
	end;
	
	ErrorMessage;
end.
	

