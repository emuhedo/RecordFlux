package body TLS_Record.TLS_Inner_Plaintext is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

end TLS_Record.TLS_Inner_Plaintext;
