package body TLS_Handshake.Contains is

   function Client_Hello_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_CLIENT_HELLO then
         pragma Assume (TLS_Handshake.Client_Hello.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Client_Hello_Handshake;

   function Server_Hello_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_SERVER_HELLO then
         pragma Assume (TLS_Handshake.Server_Hello.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Server_Hello_Handshake;

   function Encrypted_Extensions_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_ENCRYPTED_EXTENSIONS then
         pragma Assume (TLS_Handshake.Encrypted_Extensions.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Encrypted_Extensions_Handshake;

   function Certificate_Request_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_CERTIFICATE_REQUEST then
         pragma Assume (TLS_Handshake.Certificate_Request.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Certificate_Request_Handshake;

   function Certificate_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_CERTIFICATE then
         pragma Assume (TLS_Handshake.Certificate.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Certificate_Handshake;

   function Certificate_Verify_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_CERTIFICATE_VERIFY then
         pragma Assume (TLS_Handshake.Certificate_Verify.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Certificate_Verify_Handshake;

   function Finished_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_FINISHED then
         pragma Assume (TLS_Handshake.Finished.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Finished_Handshake;

   function End_Of_Early_Data_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_END_OF_EARLY_DATA then
         return True;
      end if;
      return False;
   end End_Of_Early_Data_Handshake;

   function New_Session_Ticket_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_NEW_SESSION_TICKET then
         pragma Assume (TLS_Handshake.New_Session_Ticket.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end New_Session_Ticket_Handshake;

   function Key_Update_Handshake (Buffer : Types.Bytes) return Boolean is
   begin
      if TLS_Handshake.Handshake.Get_Tag (Buffer) = HANDSHAKE_KEY_UPDATE then
         pragma Assume (TLS_Handshake.Key_Update.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));
         return True;
      end if;
      return False;
   end Key_Update_Handshake;

end TLS_Handshake.Contains;
