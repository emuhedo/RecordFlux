package body TLS_Handshake.Finished is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Verify_Data (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Verify_Data_First (Buffer);
      Last := Get_Verify_Data_Last (Buffer);
   end Get_Verify_Data;

end TLS_Handshake.Finished;
