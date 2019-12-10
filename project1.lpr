program project1;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes, SysUtils,process,fphttpclient,StrUtils,httpsend,ssockets,sslsockets,fpopenssl,CustApp;

type

  { TMyApplication }

  TMyApplication = class(TCustomApplication)
  protected
    procedure DoRun; override;

    private

  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
    procedure checkip;virtual;
    procedure banner;virtual;
    procedure location;virtual;
   procedure malicious;virtual;
  end;

{ TMyApplication }

procedure TMyApplication.DoRun;
var
  ErrorMsg: String;
begin
  // quick check parameters
  ErrorMsg:=CheckOptions('h l b i m', 'help list blacklist iplocation malicious');
  if ErrorMsg<>'' then begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h', 'help') then begin
    WriteHelp;
    Terminate;
    Exit;
  end;

  if HasOption('i','iplocation') then begin
    banner;
    location;
    terminate;
    Exit;

  end;
  if hasoption('m','malicious') then begin
    banner;
    malicious;
    terminate;
    exit;
  end;
  if HasOption('b','blacklist') then begin
    banner;
    checkip;
    Terminate;
    Exit;
  { add your program here }
  end;
   banner;
  // stop program loop
  Terminate;
end;

constructor TMyApplication.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
end;

destructor TMyApplication.Destroy;
begin
  inherited Destroy;
end;


procedure checkmalware;
var
  cmd,res:string;
  begin
  writeln('[+] Updating database...');
  cmd := 'curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v "#" | grep -v -E "\s[1-2]$" | cut -f 1 > database';
  RunCommand('/bin/bash',['-c',cmd],res);
  writeln('                       ');

end;

function getscript(url:string):string;
var
  FPHTTPClient: TFPHTTPClient;
  Resultget : string;
begin
FPHTTPClient := TFPHTTPClient.Create(nil);
FPHTTPClient.AllowRedirect := True;
   try
   Resultget := FPHTTPClient.Get('http://api.hackertarget.com/geoip/?q='+url); // test URL, real one is HTTPS
   getscript := Resultget;
   writeln(getscript);
   except
      on E: exception do
         writeln(E.Message);
   end;
FPHTTPClient.Free;

end;
Procedure TMyApplication.location;
var
  i:integer;
  url:string;
  begin

  for i:=0 to paramCount -1 do begin

  if (paramstr(i)='-i') then begin

    url :=paramstr(i+1);
    end;
  end;
  getscript(url);

  end;

procedure TMyApplication.malicious;
var
list:Tstringlist;
blist:Tstringlist;
outres:Tstringlist;
i,p,c:integer;
oty,ffile:string;
begin

 for p := 0 to paramcount do begin

 if (paramstr(p)='-l') then begin
   ffile:=paramstr(p+1);
 end;
 end;
 list := Tstringlist.Create;
 blist:= Tstringlist.Create;
 //outres:=Tstringlist.Create;

 //load database into stringlist
  blist.LoadFromFile(ffile);
  list.LoadFromFile('database');
  for i:=0 to list.Count -1 do begin
   oty := list.Strings[i];
 // end;
   for c:=0 to blist.Count -1 do begin
   blist.Strings[c];
 //  end;
     if AnsiContainsStr(blist.Strings[c],oty) then begin
       writeln('[+] the following IP '+blist[c]+' is Malicious ');
     end;

end;

  end;
   list.free;
   blist.Free;
 end;



procedure TMyApplication.banner;
var
  banners:string;
begin
  banners := '[*] threat intelligence IPs Check Tool '#10+
             '[+] Coded by : @zux0x3a '#10+
             '[!] https://0xsp.com'#10+
             '=========================';
  writeln(banners);
  checkmalware;

end;

procedure TMyApplication.checkip;
var
 list:Tstringlist;
 blist:TstringList;
 res: string;
 i,li,bi,fi:integer;
 flist:string;
 process : Tprocess;
 outputstream :TmemoryStream;
 bblist:string;
 listout:Tstringlist;
 outy:string;
 c,ps:integer;
begin

  process := Tprocess.Create(nil);
  process.options := [poUsePipes,poStderrToOutPut];
for i := 1 to paramcount do begin
 if(paramstr(i)='-l') then begin
  flist := paramstr(i+1);

end;

 end;
  //String List Creation
  list := Tstringlist.Create;
  blist := Tstringlist.Create;
  listout := Tstringlist.Create;
  list.LoadFromFile(flist);
  blist.LoadFromFile('sources');
  for bi := 0 to blist.Count -1 do begin


  for li:=0 to list.Count -1 do begin


     try
   process.commandLine := 'dig +short'+' '+list[li]+'.'+blist[bi];

   process.Execute;
   listout.LoadFromStream(process.Output);
   except on
    E:exception do
   writeln(E.message);
      end;

  for  ps:=0 to listout.Count -1 do begin

   outy := listout.Strings[ps];
   if AnsiContainsStr(outy,'.') then begin

   writeln('[*] IP '+list[li],' is listed on '+blist[bi]);
   end;

 end;
  end;
   end;
 list.Free;
    blist.Free;
    listout.Free;
  end;
procedure TMyApplication.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ', ExeName, ' -h');
  writeln('-l ','--Load List of IPs from a file ');
  writeln('-c ','--Check range of IPs for blacklist/spam');
  writeln('-m ','--Lookup for List of Ips through Daily Malicious Activity Database ');
  writeln('-i ','--Retrieve IP Location ');
end;

var
  Application: TMyApplication;
begin
  Application:=TMyApplication.Create(nil);
  Application.Title:='IPs Checker';
  Application.Run;
  Application.Free;
end.

