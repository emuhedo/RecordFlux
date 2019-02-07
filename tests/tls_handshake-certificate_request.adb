package body TLS_Handshake.Certificate_Request is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Certificate_Request_Context (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Certificate_Request_Context_First (Buffer);
      Last := Get_Certificate_Request_Context_Last (Buffer);
   end Get_Certificate_Request_Context;

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Extensions_First (Buffer);
      Last := Get_Extensions_Last (Buffer);
      pragma Assume (TLS_Handshake.Extensions.Is_Contained (Buffer (First .. Last)));
   end Get_Extensions;

end TLS_Handshake.Certificate_Request;
