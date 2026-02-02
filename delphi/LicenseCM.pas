{*******************************************************}
{                                                       }
{       LicenseCM Delphi SDK                            }
{       Enhanced Security Features                      }
{                                                       }
{       Supports: Delphi 10.3+, FMX and VCL             }
{                                                       }
{*******************************************************}

unit LicenseCM;

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.DateUtils,
  System.Net.HttpClient, System.Net.URLClient, System.NetEncoding,
  System.Hash, System.Generics.Collections, System.Threading;

type
  TSessionInfo = record
    Token: string;
    Expires: TDateTime;
    IsValid: Boolean;
  end;

  TSecurityViolationEvent = procedure(Sender: TObject; Details: TDictionary<string, string>) of object;
  THeartbeatFailedEvent = procedure(Sender: TObject; ErrorMessage: string) of object;
  TSessionExpiredEvent = procedure(Sender: TObject) of object;

  TLicenseCMClient = class(TComponent)
  private
    FBaseUrl: string;
    FProductId: string;
    FSecretKey: string;
    FUseEncryption: Boolean;
    FAutoHeartbeat: Boolean;
    FHeartbeatInterval: Integer;

    // Session state
    FSessionToken: string;
    FSessionExpires: TDateTime;
    FLicenseKey: string;
    FHWID: string;
    FPublicKey: string;

    // Heartbeat
    FHeartbeatTask: ITask;
    FHeartbeatStop: Boolean;

    // Events
    FOnSessionExpired: TSessionExpiredEvent;
    FOnSecurityViolation: TSecurityViolationEvent;
    FOnHeartbeatFailed: THeartbeatFailedEvent;

    FHttpClient: THTTPClient;

    function CollectClientData: TJSONObject;
    function DetectVMIndicators: TJSONArray;
    function DetectDebugIndicators: TJSONArray;
    function Sign(const Data: string): string;
    function DoRequest(const Endpoint: string; Data: TJSONObject): TJSONObject;
    procedure HandleSessionInfo(const ResponseData: TJSONObject);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    class function GenerateHWID: string; static;

    procedure Initialize;
    function FetchPublicKey: string;

    function Validate(const LicenseKey: string; const HWID: string = ''): TJSONObject;
    function Activate(const LicenseKey: string; const HWID: string = ''): TJSONObject;
    function Deactivate(const LicenseKey: string = ''; const HWID: string = ''): TJSONObject;
    function Heartbeat(const LicenseKey: string = ''; const HWID: string = ''): TJSONObject;

    procedure StartHeartbeat;
    procedure StopHeartbeat;

    function IsSessionValid: Boolean;
    function GetSessionInfo: TSessionInfo;

    procedure Cleanup;

    property BaseUrl: string read FBaseUrl write FBaseUrl;
    property ProductId: string read FProductId write FProductId;
    property SecretKey: string read FSecretKey write FSecretKey;
    property UseEncryption: Boolean read FUseEncryption write FUseEncryption;
    property AutoHeartbeat: Boolean read FAutoHeartbeat write FAutoHeartbeat;
    property HeartbeatInterval: Integer read FHeartbeatInterval write FHeartbeatInterval;

    property OnSessionExpired: TSessionExpiredEvent read FOnSessionExpired write FOnSessionExpired;
    property OnSecurityViolation: TSecurityViolationEvent read FOnSecurityViolation write FOnSecurityViolation;
    property OnHeartbeatFailed: THeartbeatFailedEvent read FOnHeartbeatFailed write FOnHeartbeatFailed;
  end;

implementation

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows, Winapi.IpHlpApi, Winapi.IpTypes,
  {$ENDIF}
  System.Diagnostics;

{ TLicenseCMClient }

constructor TLicenseCMClient.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FBaseUrl := 'http://localhost:3000';
  FProductId := '';
  FSecretKey := '';
  FUseEncryption := False;
  FAutoHeartbeat := True;
  FHeartbeatInterval := 300000; // 5 minutes
  FHeartbeatStop := True;

  FHttpClient := THTTPClient.Create;
  FHttpClient.ContentType := 'application/json';
  FHttpClient.ConnectionTimeout := 30000;
  FHttpClient.ResponseTimeout := 30000;
end;

destructor TLicenseCMClient.Destroy;
begin
  Cleanup;
  FHttpClient.Free;
  inherited;
end;

class function TLicenseCMClient.GenerateHWID: string;
var
  Components: TStringList;
  Data: string;
  {$IFDEF MSWINDOWS}
  AdapterInfo: PIP_ADAPTER_INFO;
  BufLen: ULONG;
  ComputerName: array[0..MAX_COMPUTERNAME_LENGTH] of Char;
  Size: DWORD;
  {$ENDIF}
begin
  Components := TStringList.Create;
  try
    // Platform
    {$IFDEF MSWINDOWS}
    Components.Add('Windows');
    {$ELSE}
    Components.Add('Unknown');
    {$ENDIF}

    // Architecture
    {$IFDEF WIN64}
    Components.Add('x64');
    {$ELSE}
    Components.Add('x86');
    {$ENDIF}

    // Computer name
    {$IFDEF MSWINDOWS}
    Size := MAX_COMPUTERNAME_LENGTH + 1;
    if GetComputerName(ComputerName, Size) then
      Components.Add(ComputerName);
    {$ENDIF}

    // MAC Address
    {$IFDEF MSWINDOWS}
    BufLen := SizeOf(TIP_ADAPTER_INFO);
    GetMem(AdapterInfo, BufLen);
    try
      if GetAdaptersInfo(AdapterInfo, BufLen) = ERROR_BUFFER_OVERFLOW then
      begin
        ReallocMem(AdapterInfo, BufLen);
        if GetAdaptersInfo(AdapterInfo, BufLen) = NO_ERROR then
        begin
          Components.Add(Format('%.2x:%.2x:%.2x:%.2x:%.2x:%.2x', [
            AdapterInfo^.Address[0], AdapterInfo^.Address[1],
            AdapterInfo^.Address[2], AdapterInfo^.Address[3],
            AdapterInfo^.Address[4], AdapterInfo^.Address[5]
          ]));
        end;
      end;
    finally
      FreeMem(AdapterInfo);
    end;
    {$ENDIF}

    // CPU count
    Components.Add(IntToStr(TThread.ProcessorCount));

    Data := Components.DelimitedText;
    Components.Delimiter := '|';
    Data := Components.DelimitedText;

    Result := THashSHA2.GetHashString(Data, SHA256);

  finally
    Components.Free;
  end;
end;

function TLicenseCMClient.CollectClientData: TJSONObject;
var
  EnvIndicators: TJSONObject;
  {$IFDEF MSWINDOWS}
  ComputerName: array[0..MAX_COMPUTERNAME_LENGTH] of Char;
  Size: DWORD;
  Hostname: string;
  {$ENDIF}
begin
  Result := TJSONObject.Create;

  if FHWID <> '' then
    Result.AddPair('hwid', FHWID)
  else
    Result.AddPair('hwid', GenerateHWID);

  Result.AddPair('timestamp', TJSONNumber.Create(DateTimeToUnix(Now, False) * 1000));

  {$IFDEF MSWINDOWS}
  Result.AddPair('platform', 'Windows');
  {$ELSE}
  Result.AddPair('platform', 'Unknown');
  {$ENDIF}

  Result.AddPair('os_version', TOSVersion.ToString);

  {$IFDEF WIN64}
  Result.AddPair('architecture', 'x64');
  {$ELSE}
  Result.AddPair('architecture', 'x86');
  {$ENDIF}

  {$IFDEF MSWINDOWS}
  Size := MAX_COMPUTERNAME_LENGTH + 1;
  if GetComputerName(ComputerName, Size) then
    Hostname := ComputerName
  else
    Hostname := 'unknown';
  Result.AddPair('hostname', Hostname);
  {$ENDIF}

  Result.AddPair('delphi_version', IntToStr(CompilerVersion));
  Result.AddPair('cpu_count', TJSONNumber.Create(TThread.ProcessorCount));

  EnvIndicators := TJSONObject.Create;
  EnvIndicators.AddPair('debug_mode', TJSONBool.Create(GetEnvironmentVariable('DEBUG') <> ''));
  Result.AddPair('env_indicators', EnvIndicators);

  Result.AddPair('vm_indicators', DetectVMIndicators);
  Result.AddPair('debug_indicators', DetectDebugIndicators);
end;

function TLicenseCMClient.DetectVMIndicators: TJSONArray;
var
  {$IFDEF MSWINDOWS}
  ComputerName: array[0..MAX_COMPUTERNAME_LENGTH] of Char;
  Size: DWORD;
  Hostname: string;
  {$ENDIF}
  VMHostnames: array of string;
  VM: string;
begin
  Result := TJSONArray.Create;

  VMHostnames := ['vmware', 'virtualbox', 'sandbox', 'virtual', 'qemu'];

  {$IFDEF MSWINDOWS}
  Size := MAX_COMPUTERNAME_LENGTH + 1;
  if GetComputerName(ComputerName, Size) then
  begin
    Hostname := LowerCase(ComputerName);
    for VM in VMHostnames do
    begin
      if Pos(VM, Hostname) > 0 then
      begin
        Result.Add('suspicious_hostname');
        Break;
      end;
    end;
  end;
  {$ENDIF}

  if TThread.ProcessorCount < 2 then
    Result.Add('single_cpu');
end;

function TLicenseCMClient.DetectDebugIndicators: TJSONArray;
var
  Stopwatch: TStopwatch;
  I: Integer;
  Duration: Int64;
begin
  Result := TJSONArray.Create;

  if GetEnvironmentVariable('DEBUG') <> '' then
    Result.Add('env_debug');

  // Timing analysis
  Stopwatch := TStopwatch.StartNew;
  for I := 1 to 1000 do
    Random;
  Stopwatch.Stop;
  Duration := Stopwatch.ElapsedMilliseconds;

  if Duration > 100 then
    Result.Add('timing_anomaly');
end;

function TLicenseCMClient.Sign(const Data: string): string;
begin
  Result := THashSHA2.GetHMAC(Data, FSecretKey, SHA256);
end;

function TLicenseCMClient.FetchPublicKey: string;
var
  Response: IHTTPResponse;
  JSON: TJSONObject;
begin
  Result := '';
  try
    Response := FHttpClient.Get(FBaseUrl + '/api/client/public-key');
    if Response.StatusCode = 200 then
    begin
      JSON := TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
      try
        if JSON.GetValue<Boolean>('success') then
        begin
          FPublicKey := JSON.GetValue<string>('data.public_key');
          Result := FPublicKey;
        end;
      finally
        JSON.Free;
      end;
    end;
  except
    // Ignore errors
  end;
end;

procedure TLicenseCMClient.Initialize;
begin
  FetchPublicKey;
end;

function TLicenseCMClient.DoRequest(const Endpoint: string; Data: TJSONObject): TJSONObject;
var
  ClientData: TJSONObject;
  Body: TJSONObject;
  RequestBody: TStringStream;
  Response: IHTTPResponse;
  ResponseJSON: TJSONObject;
  ResponseData: TJSONObject;
  Details: TDictionary<string, string>;
begin
  Result := nil;

  ClientData := CollectClientData;

  Body := TJSONObject.Create;
  try
    // Copy data
    if Assigned(Data) then
    begin
      Body.AddPair('license_key', Data.GetValue<string>('license_key'));
      Body.AddPair('hwid', Data.GetValue<string>('hwid'));
    end;

    Body.AddPair('product_id', FProductId);
    Body.AddPair('client_data', ClientData);

    if FSessionToken <> '' then
      Body.AddPair('session_token', FSessionToken);

    RequestBody := TStringStream.Create(Body.ToString, TEncoding.UTF8);
    try
      Response := FHttpClient.Post(FBaseUrl + '/api/client' + Endpoint, RequestBody);

      ResponseJSON := TJSONObject.ParseJSONValue(Response.ContentAsString) as TJSONObject;
      try
        if ResponseJSON.GetValue<Boolean>('success') then
        begin
          ResponseData := ResponseJSON.GetValue<TJSONObject>('data');
          HandleSessionInfo(ResponseData);
          Result := ResponseData.Clone as TJSONObject;
        end
        else
        begin
          // Handle security violations
          if ResponseJSON.GetValue<Boolean>('security_blocked', False) then
          begin
            Details := TDictionary<string, string>.Create;
            try
              Details.Add('type', 'blocked');
              Details.Add('reason', ResponseJSON.GetValue<string>('message', 'Unknown'));
              if Assigned(FOnSecurityViolation) then
                FOnSecurityViolation(Self, Details);
            finally
              Details.Free;
            end;
          end;

          raise Exception.Create(ResponseJSON.GetValue<string>('message', 'Unknown error'));
        end;
      finally
        ResponseJSON.Free;
      end;
    finally
      RequestBody.Free;
    end;
  finally
    Body.Free;
  end;
end;

procedure TLicenseCMClient.HandleSessionInfo(const ResponseData: TJSONObject);
var
  Session: TJSONObject;
  ExpiresStr: string;
begin
  // Handle session token rotation
  if ResponseData.TryGetValue<string>('new_token', FSessionToken) then
    Exit;

  // Handle session info
  if ResponseData.TryGetValue<TJSONObject>('session', Session) then
  begin
    Session.TryGetValue<string>('token', FSessionToken);
    if Session.TryGetValue<string>('expires_at', ExpiresStr) then
      FSessionExpires := ISO8601ToDate(ExpiresStr, False);
  end;
end;

function TLicenseCMClient.Validate(const LicenseKey: string; const HWID: string): TJSONObject;
var
  Data: TJSONObject;
begin
  FLicenseKey := LicenseKey;
  if HWID <> '' then
    FHWID := HWID
  else
    FHWID := GenerateHWID;

  Data := TJSONObject.Create;
  try
    Data.AddPair('license_key', LicenseKey);
    Data.AddPair('hwid', FHWID);
    Result := DoRequest('/validate', Data);
  finally
    Data.Free;
  end;
end;

function TLicenseCMClient.Activate(const LicenseKey: string; const HWID: string): TJSONObject;
var
  Data: TJSONObject;
begin
  FLicenseKey := LicenseKey;
  if HWID <> '' then
    FHWID := HWID
  else
    FHWID := GenerateHWID;

  Data := TJSONObject.Create;
  try
    Data.AddPair('license_key', LicenseKey);
    Data.AddPair('hwid', FHWID);
    Result := DoRequest('/activate', Data);

    // Start heartbeat if enabled
    if FAutoHeartbeat and Assigned(Result) and (Result.GetValue('session') <> nil) then
      StartHeartbeat;
  finally
    Data.Free;
  end;
end;

function TLicenseCMClient.Deactivate(const LicenseKey: string; const HWID: string): TJSONObject;
var
  Data: TJSONObject;
  LK, HW: string;
begin
  StopHeartbeat;

  if LicenseKey <> '' then
    LK := LicenseKey
  else
    LK := FLicenseKey;

  if HWID <> '' then
    HW := HWID
  else if FHWID <> '' then
    HW := FHWID
  else
    HW := GenerateHWID;

  Data := TJSONObject.Create;
  try
    Data.AddPair('license_key', LK);
    Data.AddPair('hwid', HW);
    Result := DoRequest('/deactivate', Data);

    FSessionToken := '';
    FSessionExpires := 0;
  finally
    Data.Free;
  end;
end;

function TLicenseCMClient.Heartbeat(const LicenseKey: string; const HWID: string): TJSONObject;
var
  Data: TJSONObject;
  LK, HW: string;
begin
  if LicenseKey <> '' then
    LK := LicenseKey
  else
    LK := FLicenseKey;

  if HWID <> '' then
    HW := HWID
  else if FHWID <> '' then
    HW := FHWID
  else
    HW := GenerateHWID;

  Data := TJSONObject.Create;
  try
    Data.AddPair('license_key', LK);
    Data.AddPair('hwid', HW);
    Result := DoRequest('/heartbeat', Data);
  finally
    Data.Free;
  end;
end;

procedure TLicenseCMClient.StartHeartbeat;
begin
  StopHeartbeat;

  FHeartbeatStop := False;

  FHeartbeatTask := TTask.Run(
    procedure
    begin
      while not FHeartbeatStop do
      begin
        Sleep(FHeartbeatInterval);
        if FHeartbeatStop then
          Exit;

        try
          Heartbeat;
        except
          on E: Exception do
          begin
            if Assigned(FOnHeartbeatFailed) then
              TThread.Synchronize(nil,
                procedure
                begin
                  FOnHeartbeatFailed(Self, E.Message);
                end);

            if (Pos('expired', LowerCase(E.Message)) > 0) or
               (Pos('invalid', LowerCase(E.Message)) > 0) then
            begin
              FHeartbeatStop := True;
              if Assigned(FOnSessionExpired) then
                TThread.Synchronize(nil,
                  procedure
                  begin
                    FOnSessionExpired(Self);
                  end);
              Exit;
            end;
          end;
        end;
      end;
    end);
end;

procedure TLicenseCMClient.StopHeartbeat;
begin
  FHeartbeatStop := True;
  if Assigned(FHeartbeatTask) then
  begin
    FHeartbeatTask.Cancel;
    FHeartbeatTask := nil;
  end;
end;

function TLicenseCMClient.IsSessionValid: Boolean;
begin
  Result := (FSessionToken <> '') and (FSessionExpires > 0) and (Now < FSessionExpires);
end;

function TLicenseCMClient.GetSessionInfo: TSessionInfo;
begin
  Result.Token := FSessionToken;
  Result.Expires := FSessionExpires;
  Result.IsValid := IsSessionValid;
end;

procedure TLicenseCMClient.Cleanup;
begin
  StopHeartbeat;
  FSessionToken := '';
  FSessionExpires := 0;
  FLicenseKey := '';
  FHWID := '';
end;

end.
