package body TLS_Handshake.Certificate_Verify is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Signature (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Signature_First (Buffer);
      Last := Get_Signature_Last (Buffer);
   end Get_Signature;

end TLS_Handshake.Certificate_Verify;
