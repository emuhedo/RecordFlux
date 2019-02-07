package body TLS_Record.TLS_Plaintext is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Fragment (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Fragment_First (Buffer);
      Last := Get_Fragment_Last (Buffer);
   end Get_Fragment;

end TLS_Record.TLS_Plaintext;
