with TLS_Handshake.Handshake;
with TLS_Handshake.Client_Hello;
with TLS_Handshake.Server_Hello;
with TLS_Handshake.Encrypted_Extensions;
with TLS_Handshake.Certificate_Request;
with TLS_Handshake.Certificate;
with TLS_Handshake.Certificate_Verify;
with TLS_Handshake.Finished;
with TLS_Handshake.New_Session_Ticket;
with TLS_Handshake.Key_Update;

package TLS_Handshake.Contains
  with SPARK_Mode
is

   function Client_Hello_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Client_Hello_Handshake'Result then TLS_Handshake.Client_Hello.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Server_Hello_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Server_Hello_Handshake'Result then TLS_Handshake.Server_Hello.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Encrypted_Extensions_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Encrypted_Extensions_Handshake'Result then TLS_Handshake.Encrypted_Extensions.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Certificate_Request_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Certificate_Request_Handshake'Result then TLS_Handshake.Certificate_Request.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Certificate_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Certificate_Handshake'Result then TLS_Handshake.Certificate.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Certificate_Verify_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Certificate_Verify_Handshake'Result then TLS_Handshake.Certificate_Verify.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Finished_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Finished_Handshake'Result then TLS_Handshake.Finished.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function End_Of_Early_Data_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer));

   function New_Session_Ticket_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if New_Session_Ticket_Handshake'Result then TLS_Handshake.New_Session_Ticket.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

   function Key_Update_Handshake (Buffer : Types.Bytes) return Boolean
     with
       Pre => (TLS_Handshake.Handshake.Is_Contained (Buffer) and then TLS_Handshake.Handshake.Is_Valid (Buffer)),
       Post => (if Key_Update_Handshake'Result then TLS_Handshake.Key_Update.Is_Contained (Buffer (TLS_Handshake.Handshake.Get_Payload_First (Buffer) .. TLS_Handshake.Handshake.Get_Payload_Last (Buffer))));

end TLS_Handshake.Contains;
