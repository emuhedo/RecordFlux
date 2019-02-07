package body TLS_Record.TLS_Ciphertext is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Encrypted_Record (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Encrypted_Record_First (Buffer);
      Last := Get_Encrypted_Record_Last (Buffer);
   end Get_Encrypted_Record;

end TLS_Record.TLS_Ciphertext;
