package body TLS_Handshake.Key_Update is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

end TLS_Handshake.Key_Update;
