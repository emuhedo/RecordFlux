package body TLS_Handshake.Extension is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Extension_Data (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Extension_Data_First (Buffer);
      Last := Get_Extension_Data_Last (Buffer);
   end Get_Extension_Data;

end TLS_Handshake.Extension;
