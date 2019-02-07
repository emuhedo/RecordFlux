package body TLS_Alert.Alert is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

end TLS_Alert.Alert;
