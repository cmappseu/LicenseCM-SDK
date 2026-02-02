program LicenseCMExample;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.Generics.Collections,
  LicenseCM in '..\LicenseCM.pas';

var
  Client: TLicenseCMClient;
  LicenseKey: string;
  Result: TJSONObject;

begin
  try
    WriteLn('LicenseCM Delphi SDK Example');
    WriteLn('============================');
    WriteLn;

    Client := TLicenseCMClient.Create(nil);
    try
      Client.BaseUrl := 'http://localhost:3000';
      Client.ProductId := 'your-product-id';
      Client.SecretKey := 'your-secret-key';
      Client.UseEncryption := False;
      Client.AutoHeartbeat := True;

      // Set callbacks
      Client.OnSessionExpired := procedure(Sender: TObject)
        begin
          WriteLn('Session expired! Please re-activate.');
          Halt(1);
        end;

      Client.OnSecurityViolation := procedure(Sender: TObject; Details: TDictionary<string, string>)
        begin
          WriteLn('Security violation: ', Details['reason']);
          Halt(1);
        end;

      Client.OnHeartbeatFailed := procedure(Sender: TObject; ErrorMessage: string)
        begin
          WriteLn('Heartbeat failed: ', ErrorMessage);
        end;

      LicenseKey := 'XXXX-XXXX-XXXX-XXXX';

      // Initialize
      WriteLn('Initializing...');
      Client.Initialize;
      WriteLn('Initialized.');
      WriteLn;

      // Activate
      WriteLn('Activating license...');
      Result := Client.Activate(LicenseKey);
      try
        WriteLn('License activated!');
        WriteLn('Response: ', Result.ToString);
      finally
        Result.Free;
      end;
      WriteLn;

      // Session info
      WriteLn('Session valid: ', BoolToStr(Client.IsSessionValid, True));
      WriteLn;

      // Keep running
      WriteLn('Press Enter to exit...');
      ReadLn;

      // Deactivate
      WriteLn('Deactivating...');
      Result := Client.Deactivate;
      try
        WriteLn('Deactivated.');
      finally
        Result.Free;
      end;

    finally
      Client.Free;
    end;

  except
    on E: Exception do
      WriteLn('Error: ', E.Message);
  end;
end.
