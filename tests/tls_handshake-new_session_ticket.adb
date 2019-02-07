package body TLS_Handshake.New_Session_Ticket is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Ticket_Nonce (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Ticket_Nonce_First (Buffer);
      Last := Get_Ticket_Nonce_Last (Buffer);
   end Get_Ticket_Nonce;

   procedure Get_Ticket (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Ticket_First (Buffer);
      Last := Get_Ticket_Last (Buffer);
   end Get_Ticket;

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Extensions_First (Buffer);
      Last := Get_Extensions_Last (Buffer);
   end Get_Extensions;

end TLS_Handshake.New_Session_Ticket;
