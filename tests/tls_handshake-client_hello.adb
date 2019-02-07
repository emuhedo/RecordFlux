package body TLS_Handshake.Client_Hello is

   procedure Label (Buffer : Types.Bytes) is
   begin
      pragma Assume (Is_Contained (Buffer));
   end Label;

   procedure Get_Random (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Random_First (Buffer);
      Last := Get_Random_Last (Buffer);
   end Get_Random;

   procedure Get_Legacy_Session_ID (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Legacy_Session_ID_First (Buffer);
      Last := Get_Legacy_Session_ID_Last (Buffer);
   end Get_Legacy_Session_ID;

   procedure Get_Cipher_Suites (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Cipher_Suites_First (Buffer);
      Last := Get_Cipher_Suites_Last (Buffer);
   end Get_Cipher_Suites;

   procedure Get_Legacy_Compression_Methods (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Legacy_Compression_Methods_First (Buffer);
      Last := Get_Legacy_Compression_Methods_Last (Buffer);
   end Get_Legacy_Compression_Methods;

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type) is
   begin
      First := Get_Extensions_First (Buffer);
      Last := Get_Extensions_Last (Buffer);
      pragma Assume (TLS_Handshake.Extensions.Is_Contained (Buffer (First .. Last)));
   end Get_Extensions;

end TLS_Handshake.Client_Hello;
