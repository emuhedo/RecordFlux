package body TLS_Handshake.Certificate is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Certificate_Request_Context (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Certificate_Request_Context_First (Buffer);
      Last := Get_Certificate_Request_Context_Last (Buffer);
   end Get_Certificate_Request_Context;

   procedure Get_Certificate_List (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Certificate_List_First (Buffer);
      Last := Get_Certificate_List_Last (Buffer);
      pragma Assume (TLS_Handshake.Certificate_Entries.Is_Contained (Buffer (First .. Last)));
   end Get_Certificate_List;

end TLS_Handshake.Certificate;
