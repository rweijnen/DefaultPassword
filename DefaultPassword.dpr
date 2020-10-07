program DefaultPassword;

{$APPTYPE CONSOLE}
{$R *.res}
{$R 'Win7UAC.res'}

{$IFDEF RELEASE}
   // Leave out Relocation Table in Release version
   {$SetPEFlags 1}
 {$ENDIF RELEASE}

// No need for RTTI
 {$WEAKLINKRTTI ON}
  {$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

{$R *.dres}

uses
  Windows,
  SysUtils,
  JwaWinType,
  JwaNtStatus,
  JwaNtSecApi,
  JwaNative;

var
  ObjAttributes: LSA_OBJECT_ATTRIBUTES;
  hLsaPolicy: Pointer;
  nts: NTSTATUS;
  PrivateData: PLSA_UNICODE_STRING;
  KeyName: LSA_UNICODE_STRING;
  Secret: String;
  KeyNameStr: String = 'DefaultPassword';
  stdin: THandle;

function GetCh: Char;
var
  CharsRead: Cardinal;
begin
  Win32Check(ReadConsole(stdin, @Result, 1, CharsRead, nil));
end;

function OldConsoleMode(handle: THandle): Cardinal;
begin
  Win32Check(GetConsoleMode(handle, Result));
end;

function KeyPressed: Boolean;
var
  i, numEvents: Cardinal;
  events: array of TInputRecord;
begin
  Result := False;
  Win32Check(GetNumberOfConsoleInputEvents(stdin, numEvents));
  if numEvents > 0 then
  begin
    SetLength(events, numEvents);
     Win32Check(PeekConsoleInput(stdin, events[0], numEvents, numEvents));
     for i:= 0 to numEvents - 1 do
     if (events[i].EventType = key_event) and
       (events[i].Event.KeyEvent.bKeyDown) then
     begin
       Result := True;
       Break;
     end;
   end;
 end;


begin
  try
    WriteLn('Winpass v1.0 (c) 2012 Remko Weijnen');
    WriteLn('Reads the DefaultPassword value from the LSA Secrets');
    WriteLn('');

    stdin := GetStdHandle(STD_INPUT_HANDLE);
    SetConsoleMode(stdin, OldConsoleMode(stdin) and
      not (ENABLE_LINE_INPUT or ENABLE_ECHO_INPUT));

    if ParamCount = 1 then
      KeyNameStr := ParamStr(1);

    ZeroMemory(@ObjAttributes, SizeOf(ObjAttributes));
    nts := LsaOpenPolicy(nil, ObjAttributes, POLICY_ALL_ACCESS, hLsaPolicy);
    if nts <> STATUS_SUCCESS then
    begin
      WriteLn(Format('OpenPolicy failed with 0x%.8x (%s)',
        [nts, SysErrorMessage(RtlNtStatusToDosError(nts))]));
      Exit;
    end;

    try
      PrivateData := nil;
      RtlInitUnicodeString(@KeyName, PChar(KeyNameStr));

      nts := LsaRetrievePrivateData(hLsaPolicy, KeyName, PrivateData);

      if nts <> STATUS_SUCCESS then
      begin
        WriteLn(Format('LsaRetrievePrivateData failed with 0x%.8x (%s)',
          [nts, SysErrorMessage(RtlNtStatusToDosError(nts))]));
        Exit;
      end;

      SetLength(Secret, PrivateData^.Length div SizeOf(Char));
      CopyMemory(@Secret[1], PrivateData^.Buffer, PrivateData^.Length);
      WriteLn(Format('%s: %s', [KeyNameStr, Secret]));
    finally
      LsaClose(hLsaPolicy);
    end;

    WriteLn('Press any key to continue');
    while not KeyPressed do
      Sleep(10);
    GetCh; // or Write(GetCh);

    WriteLn('');
    SetConsoleMode(stdin,
    OldConsoleMode(stdin) or (ENABLE_LINE_INPUT or ENABLE_ECHO_INPUT));
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
