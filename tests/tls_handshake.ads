with Types;
use type Types.Index_Type, Types.Length_Type;

package TLS_Handshake
  with SPARK_Mode
is

   type Handshake_Type_Base is mod (2**8);
   function Convert_To_Handshake_Type_Base is new Types.Convert_To_Mod (Handshake_Type_Base);

   type Handshake_Type is (HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, HANDSHAKE_NEW_SESSION_TICKET, HANDSHAKE_END_OF_EARLY_DATA, HANDSHAKE_ENCRYPTED_EXTENSIONS, HANDSHAKE_CERTIFICATE, HANDSHAKE_CERTIFICATE_REQUEST, HANDSHAKE_CERTIFICATE_VERIFY, HANDSHAKE_FINISHED, HANDSHAKE_KEY_UPDATE, HANDSHAKE_MESSAGE_HASH) with Size => 8;
   for Handshake_Type use (HANDSHAKE_CLIENT_HELLO => 1, HANDSHAKE_SERVER_HELLO => 2, HANDSHAKE_NEW_SESSION_TICKET => 4, HANDSHAKE_END_OF_EARLY_DATA => 5, HANDSHAKE_ENCRYPTED_EXTENSIONS => 8, HANDSHAKE_CERTIFICATE => 11, HANDSHAKE_CERTIFICATE_REQUEST => 13, HANDSHAKE_CERTIFICATE_VERIFY => 15, HANDSHAKE_FINISHED => 20, HANDSHAKE_KEY_UPDATE => 24, HANDSHAKE_MESSAGE_HASH => 254);

   type Length_Type is mod (2**24);
   function Convert_To_Length_Type is new Types.Convert_To_Mod (Length_Type);

   type Extension_Type_Base is mod (2**16);
   function Convert_To_Extension_Type_Base is new Types.Convert_To_Mod (Extension_Type_Base);

   type Extension_Type_Enum is (EXTENSION_SERVER_NAME, EXTENSION_MAX_FRAGMENT_LENGTH, EXTENSION_STATUS_REQUEST, EXTENSION_SUPPORTED_GROUPS, EXTENSION_SIGNATURE_ALGORITHMS, EXTENSION_USE_SRTP, EXTENSION_HEARTBEAT, EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP, EXTENSION_CLIENT_CERTIFICATE_TYPE, EXTENSION_SERVER_CERTIFICATE_TYPE, EXTENSION_PADDING, EXTENSION_PRE_SHARED_KEY, EXTENSION_EARLY_DATA, EXTENSION_SUPPORTED_VERSIONS, EXTENSION_COOKIE, EXTENSION_PSK_KEY_EXCHANGE_MODES, EXTENSION_CERTIFICATE_AUTHORITIES, EXTENSION_OID_FILTERS, EXTENSION_POST_HANDSHAKE_AUTH, EXTENSION_SIGNATURE_ALGORITHMS_CERT, EXTENSION_KEY_SHARE) with Size => 16;
   for Extension_Type_Enum use (EXTENSION_SERVER_NAME => 0, EXTENSION_MAX_FRAGMENT_LENGTH => 1, EXTENSION_STATUS_REQUEST => 5, EXTENSION_SUPPORTED_GROUPS => 10, EXTENSION_SIGNATURE_ALGORITHMS => 13, EXTENSION_USE_SRTP => 14, EXTENSION_HEARTBEAT => 15, EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION => 16, EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP => 18, EXTENSION_CLIENT_CERTIFICATE_TYPE => 19, EXTENSION_SERVER_CERTIFICATE_TYPE => 20, EXTENSION_PADDING => 21, EXTENSION_PRE_SHARED_KEY => 41, EXTENSION_EARLY_DATA => 42, EXTENSION_SUPPORTED_VERSIONS => 43, EXTENSION_COOKIE => 44, EXTENSION_PSK_KEY_EXCHANGE_MODES => 45, EXTENSION_CERTIFICATE_AUTHORITIES => 47, EXTENSION_OID_FILTERS => 48, EXTENSION_POST_HANDSHAKE_AUTH => 49, EXTENSION_SIGNATURE_ALGORITHMS_CERT => 50, EXTENSION_KEY_SHARE => 51);

   type Extension_Type (Known : Boolean := False) is
      record
         case Known is
            when True =>
               Enum : Extension_Type_Enum;
            when False =>
               Raw : Extension_Type_Base;
         end case;
      end record;

   type Extension_Data_Length_Type is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Extension_Data_Length_Type is new Types.Convert_To_Int (Extension_Data_Length_Type);

   type Protocol_Version_Type_Base is mod (2**16);
   function Convert_To_Protocol_Version_Type_Base is new Types.Convert_To_Mod (Protocol_Version_Type_Base);

   type Protocol_Version_Type is (TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3) with Size => 16;
   for Protocol_Version_Type use (TLS_1_0 => 769, TLS_1_1 => 770, TLS_1_2 => 771, TLS_1_3 => 772);

   type Legacy_Session_ID_Length_Type_Base is range 0 .. ((2**8) - 1) with Size => 8;
   function Convert_To_Legacy_Session_ID_Length_Type_Base is new Types.Convert_To_Int (Legacy_Session_ID_Length_Type_Base);

   subtype Legacy_Session_ID_Length_Type is Legacy_Session_ID_Length_Type_Base range 0 .. 32;

   type Cipher_Suites_Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Cipher_Suites_Length_Type_Base is new Types.Convert_To_Int (Cipher_Suites_Length_Type_Base);

   subtype Cipher_Suites_Length_Type is Cipher_Suites_Length_Type_Base range 2 .. ((2**16) - 2);

   type Legacy_Compression_Methods_Length_Type_Base is range 0 .. ((2**8) - 1) with Size => 8;
   function Convert_To_Legacy_Compression_Methods_Length_Type_Base is new Types.Convert_To_Int (Legacy_Compression_Methods_Length_Type_Base);

   subtype Legacy_Compression_Methods_Length_Type is Legacy_Compression_Methods_Length_Type_Base range 1 .. ((2**8) - 1);

   type Client_Hello_Extensions_Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Client_Hello_Extensions_Length_Type_Base is new Types.Convert_To_Int (Client_Hello_Extensions_Length_Type_Base);

   subtype Client_Hello_Extensions_Length_Type is Client_Hello_Extensions_Length_Type_Base range 8 .. ((2**16) - 1);

   type Cipher_Suite_Type is mod (2**16);
   function Convert_To_Cipher_Suite_Type is new Types.Convert_To_Mod (Cipher_Suite_Type);

   type Legacy_Compression_Method_Type_Base is range 0 .. ((2**8) - 1) with Size => 8;
   function Convert_To_Legacy_Compression_Method_Type_Base is new Types.Convert_To_Int (Legacy_Compression_Method_Type_Base);

   subtype Legacy_Compression_Method_Type is Legacy_Compression_Method_Type_Base range 0 .. 0;

   type Server_Hello_Extensions_Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Server_Hello_Extensions_Length_Type_Base is new Types.Convert_To_Int (Server_Hello_Extensions_Length_Type_Base);

   subtype Server_Hello_Extensions_Length_Type is Server_Hello_Extensions_Length_Type_Base range 6 .. ((2**16) - 1);

   type Encrypted_Extensions_Length_Type is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Encrypted_Extensions_Length_Type is new Types.Convert_To_Int (Encrypted_Extensions_Length_Type);

   type Certificate_Request_Context_Length_Type is range 0 .. ((2**8) - 1) with Size => 8;
   function Convert_To_Certificate_Request_Context_Length_Type is new Types.Convert_To_Int (Certificate_Request_Context_Length_Type);

   type Certificate_Request_Extensions_Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Certificate_Request_Extensions_Length_Type_Base is new Types.Convert_To_Int (Certificate_Request_Extensions_Length_Type_Base);

   subtype Certificate_Request_Extensions_Length_Type is Certificate_Request_Extensions_Length_Type_Base range 2 .. ((2**16) - 1);

   type Cert_Data_Length_Type_Base is range 0 .. ((2**24) - 1) with Size => 24;
   function Convert_To_Cert_Data_Length_Type_Base is new Types.Convert_To_Int (Cert_Data_Length_Type_Base);

   subtype Cert_Data_Length_Type is Cert_Data_Length_Type_Base range 1 .. ((2**24) - 1);

   type Certificate_Extensions_Length_Type is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Certificate_Extensions_Length_Type is new Types.Convert_To_Int (Certificate_Extensions_Length_Type);

   type Certificate_List_Length_Type is range 0 .. ((2**24) - 1) with Size => 24;
   function Convert_To_Certificate_List_Length_Type is new Types.Convert_To_Int (Certificate_List_Length_Type);

   type Signature_Scheme_Base is mod (2**16);
   function Convert_To_Signature_Scheme_Base is new Types.Convert_To_Mod (Signature_Scheme_Base);

   type Signature_Scheme is (RSA_PKCS1_SHA1, ECDSA_SHA1, RSA_PKCS1_SHA256, ECDSA_SECP256R1_SHA256, RSA_PKCS1_SHA384, ECDSA_SECP384R1_SHA384, RSA_PKCS1_SHA512, ECDSA_SECP521R1_SHA512, RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512, ED25519, ED448, RSA_PSS_PSS_SHA256, RSA_PSS_PSS_SHA384, RSA_PSS_PSS_SHA512) with Size => 16;
   for Signature_Scheme use (RSA_PKCS1_SHA1 => 513, ECDSA_SHA1 => 515, RSA_PKCS1_SHA256 => 1025, ECDSA_SECP256R1_SHA256 => 1027, RSA_PKCS1_SHA384 => 1281, ECDSA_SECP384R1_SHA384 => 1283, RSA_PKCS1_SHA512 => 1537, ECDSA_SECP521R1_SHA512 => 1539, RSA_PSS_RSAE_SHA256 => 2052, RSA_PSS_RSAE_SHA384 => 2053, RSA_PSS_RSAE_SHA512 => 2054, ED25519 => 2055, ED448 => 2056, RSA_PSS_PSS_SHA256 => 2057, RSA_PSS_PSS_SHA384 => 2058, RSA_PSS_PSS_SHA512 => 2059);

   type Signature_Length_Type is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Signature_Length_Type is new Types.Convert_To_Int (Signature_Length_Type);

   type Ticket_Lifetime_Type is mod (2**32);
   function Convert_To_Ticket_Lifetime_Type is new Types.Convert_To_Mod (Ticket_Lifetime_Type);

   type Ticket_Age_Add_Type is mod (2**32);
   function Convert_To_Ticket_Age_Add_Type is new Types.Convert_To_Mod (Ticket_Age_Add_Type);

   type Ticket_Nonce_Length_Type is range 0 .. 255 with Size => 8;
   function Convert_To_Ticket_Nonce_Length_Type is new Types.Convert_To_Int (Ticket_Nonce_Length_Type);

   type Ticket_Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Ticket_Length_Type_Base is new Types.Convert_To_Int (Ticket_Length_Type_Base);

   subtype Ticket_Length_Type is Ticket_Length_Type_Base range 1 .. ((2**16) - 1);

   type New_Session_Ticket_Extensions_Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_New_Session_Ticket_Extensions_Length_Type_Base is new Types.Convert_To_Int (New_Session_Ticket_Extensions_Length_Type_Base);

   subtype New_Session_Ticket_Extensions_Length_Type is New_Session_Ticket_Extensions_Length_Type_Base range 0 .. ((2**16) - 2);

   type Key_Update_Request_Base is mod (2**8);
   function Convert_To_Key_Update_Request_Base is new Types.Convert_To_Mod (Key_Update_Request_Base);

   type Key_Update_Request is (UPDATE_NOT_REQUESTED, UPDATE_REQUESTED) with Size => 8;
   for Key_Update_Request use (UPDATE_NOT_REQUESTED => 0, UPDATE_REQUESTED => 1);

   pragma Warnings (Off, "precondition is statically false");

   function Unreachable_Handshake_Type return Handshake_Type is
      (Handshake_Type'First)
     with
       Pre => False;

   function Unreachable_Length_Type return Length_Type is
      (Length_Type'First)
     with
       Pre => False;

   function Unreachable_Types_Index_Type return Types.Index_Type is
      (Types.Index_Type'First)
     with
       Pre => False;

   function Unreachable_Types_Length_Type return Types.Length_Type is
      (Types.Length_Type'First)
     with
       Pre => False;

   function Unreachable_Extension_Type return Extension_Type is
      ((False, Extension_Type_Base'First))
     with
       Pre => False;

   function Unreachable_Extension_Data_Length_Type return Extension_Data_Length_Type is
      (Extension_Data_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Protocol_Version_Type return Protocol_Version_Type is
      (Protocol_Version_Type'First)
     with
       Pre => False;

   function Unreachable_Legacy_Session_ID_Length_Type return Legacy_Session_ID_Length_Type is
      (Legacy_Session_ID_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Cipher_Suites_Length_Type return Cipher_Suites_Length_Type is
      (Cipher_Suites_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Legacy_Compression_Methods_Length_Type return Legacy_Compression_Methods_Length_Type is
      (Legacy_Compression_Methods_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Client_Hello_Extensions_Length_Type return Client_Hello_Extensions_Length_Type is
      (Client_Hello_Extensions_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Cipher_Suite_Type return Cipher_Suite_Type is
      (Cipher_Suite_Type'First)
     with
       Pre => False;

   function Unreachable_Legacy_Compression_Method_Type return Legacy_Compression_Method_Type is
      (Legacy_Compression_Method_Type'First)
     with
       Pre => False;

   function Unreachable_Server_Hello_Extensions_Length_Type return Server_Hello_Extensions_Length_Type is
      (Server_Hello_Extensions_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Encrypted_Extensions_Length_Type return Encrypted_Extensions_Length_Type is
      (Encrypted_Extensions_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Certificate_Request_Context_Length_Type return Certificate_Request_Context_Length_Type is
      (Certificate_Request_Context_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Certificate_Request_Extensions_Length_Type return Certificate_Request_Extensions_Length_Type is
      (Certificate_Request_Extensions_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Cert_Data_Length_Type return Cert_Data_Length_Type is
      (Cert_Data_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Certificate_Extensions_Length_Type return Certificate_Extensions_Length_Type is
      (Certificate_Extensions_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Certificate_List_Length_Type return Certificate_List_Length_Type is
      (Certificate_List_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Signature_Scheme return Signature_Scheme is
      (Signature_Scheme'First)
     with
       Pre => False;

   function Unreachable_Signature_Length_Type return Signature_Length_Type is
      (Signature_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Ticket_Lifetime_Type return Ticket_Lifetime_Type is
      (Ticket_Lifetime_Type'First)
     with
       Pre => False;

   function Unreachable_Ticket_Age_Add_Type return Ticket_Age_Add_Type is
      (Ticket_Age_Add_Type'First)
     with
       Pre => False;

   function Unreachable_Ticket_Nonce_Length_Type return Ticket_Nonce_Length_Type is
      (Ticket_Nonce_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Ticket_Length_Type return Ticket_Length_Type is
      (Ticket_Length_Type'First)
     with
       Pre => False;

   function Unreachable_New_Session_Ticket_Extensions_Length_Type return New_Session_Ticket_Extensions_Length_Type is
      (New_Session_Ticket_Extensions_Length_Type'First)
     with
       Pre => False;

   function Unreachable_Key_Update_Request return Key_Update_Request is
      (Key_Update_Request'First)
     with
       Pre => False;

   pragma Warnings (On, "precondition is statically false");

   function Valid_Handshake_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Handshake_Type_Base (Buffer, Offset) is when 1 | 2 | 4 | 5 | 8 | 11 | 13 | 15 | 20 | 24 | 254 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Handshake_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Handshake_Type (Buffer : Types.Bytes; Offset : Natural) return Handshake_Type is
      (case Convert_To_Handshake_Type_Base (Buffer, Offset) is when 1 => HANDSHAKE_CLIENT_HELLO, when 2 => HANDSHAKE_SERVER_HELLO, when 4 => HANDSHAKE_NEW_SESSION_TICKET, when 5 => HANDSHAKE_END_OF_EARLY_DATA, when 8 => HANDSHAKE_ENCRYPTED_EXTENSIONS, when 11 => HANDSHAKE_CERTIFICATE, when 13 => HANDSHAKE_CERTIFICATE_REQUEST, when 15 => HANDSHAKE_CERTIFICATE_VERIFY, when 20 => HANDSHAKE_FINISHED, when 24 => HANDSHAKE_KEY_UPDATE, when 254 => HANDSHAKE_MESSAGE_HASH, when others => Unreachable_Handshake_Type)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Handshake_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Handshake_Type (Buffer, Offset));

   function Valid_Extension_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (True)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Extension_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Extension_Type (Buffer : Types.Bytes; Offset : Natural) return Extension_Type
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Extension_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Extension_Type (Buffer, Offset));

   function Valid_Protocol_Version_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Protocol_Version_Type_Base (Buffer, Offset) is when 769 | 770 | 771 | 772 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Protocol_Version_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Protocol_Version_Type (Buffer : Types.Bytes; Offset : Natural) return Protocol_Version_Type is
      (case Convert_To_Protocol_Version_Type_Base (Buffer, Offset) is when 769 => TLS_1_0, when 770 => TLS_1_1, when 771 => TLS_1_2, when 772 => TLS_1_3, when others => Unreachable_Protocol_Version_Type)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Protocol_Version_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Protocol_Version_Type (Buffer, Offset));

   function Valid_Signature_Scheme (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Signature_Scheme_Base (Buffer, Offset) is when 1025 | 1281 | 1537 | 1027 | 1283 | 1539 | 2052 | 2053 | 2054 | 2055 | 2056 | 2057 | 2058 | 2059 | 513 | 515 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Signature_Scheme_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Signature_Scheme (Buffer : Types.Bytes; Offset : Natural) return Signature_Scheme is
      (case Convert_To_Signature_Scheme_Base (Buffer, Offset) is when 1025 => RSA_PKCS1_SHA256, when 1281 => RSA_PKCS1_SHA384, when 1537 => RSA_PKCS1_SHA512, when 1027 => ECDSA_SECP256R1_SHA256, when 1283 => ECDSA_SECP384R1_SHA384, when 1539 => ECDSA_SECP521R1_SHA512, when 2052 => RSA_PSS_RSAE_SHA256, when 2053 => RSA_PSS_RSAE_SHA384, when 2054 => RSA_PSS_RSAE_SHA512, when 2055 => ED25519, when 2056 => ED448, when 2057 => RSA_PSS_PSS_SHA256, when 2058 => RSA_PSS_PSS_SHA384, when 2059 => RSA_PSS_PSS_SHA512, when 513 => RSA_PKCS1_SHA1, when 515 => ECDSA_SHA1, when others => Unreachable_Signature_Scheme)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Signature_Scheme_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Signature_Scheme (Buffer, Offset));

   function Valid_Key_Update_Request (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Key_Update_Request_Base (Buffer, Offset) is when 0 | 1 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Key_Update_Request_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Key_Update_Request (Buffer : Types.Bytes; Offset : Natural) return Key_Update_Request is
      (case Convert_To_Key_Update_Request_Base (Buffer, Offset) is when 0 => UPDATE_NOT_REQUESTED, when 1 => UPDATE_REQUESTED, when others => Unreachable_Key_Update_Request)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Key_Update_Request_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Key_Update_Request (Buffer, Offset));

end TLS_Handshake;
