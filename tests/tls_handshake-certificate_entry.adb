package body TLS_Handshake.Certificate_Entry is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Cert_Data (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Cert_Data_First (Buffer);
      Last := Get_Cert_Data_Last (Buffer);
   end Get_Cert_Data;

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Extensions_First (Buffer);
      Last := Get_Extensions_Last (Buffer);
      pragma Assume (TLS_Handshake.Extensions.Is_Contained (Buffer (First .. Last)));
   end Get_Extensions;

end TLS_Handshake.Certificate_Entry;
