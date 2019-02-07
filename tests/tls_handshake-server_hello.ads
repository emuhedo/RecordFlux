with TLS_Handshake.Extensions;

package TLS_Handshake.Server_Hello
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Legacy_Version_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 2 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Protocol_Version_Type (Buffer (Buffer'First .. (Buffer'First + 1)), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Version_0 (Buffer : Types.Bytes) return Protocol_Version_Type is
      (Convert_To_Protocol_Version_Type (Buffer (Buffer'First .. (Buffer'First + 1)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Version_0 (Buffer));

   function Valid_Legacy_Version (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Version_0 (Buffer) and then Get_Legacy_Version_0 (Buffer) = TLS_1_2))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Version (Buffer : Types.Bytes) return Protocol_Version_Type is
      ((if Valid_Legacy_Version_0 (Buffer) then Get_Legacy_Version_0 (Buffer) else Unreachable_Protocol_Version_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Version (Buffer));

   function Valid_Random_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Version_0 (Buffer) and then ((Buffer'Length >= 34 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Get_Legacy_Version_0 (Buffer) = TLS_1_2)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Random_00_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 2))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Random_00 (Buffer));

   function Get_Random_00_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 33))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Random_00 (Buffer));

   function Valid_Random (Buffer : Types.Bytes) return Boolean is
      (Valid_Random_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Random_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Random_00 (Buffer) then Get_Random_00_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Random (Buffer));

   function Get_Random_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Random_00 (Buffer) then Get_Random_00_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Random (Buffer));

   procedure Get_Random (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Random (Buffer)),
       Post => (First = Get_Random_First (Buffer) and then Last = Get_Random_Last (Buffer));

   function Valid_Legacy_Session_ID_Length_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Random_00 (Buffer) and then ((Buffer'Length >= 35 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_Legacy_Session_ID_Length_Type_Base (Buffer ((Buffer'First + 34) .. (Buffer'First + 34)), 0) <= 32)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Session_ID_Length_000 (Buffer : Types.Bytes) return Legacy_Session_ID_Length_Type is
      (Convert_To_Legacy_Session_ID_Length_Type_Base (Buffer ((Buffer'First + 34) .. (Buffer'First + 34)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID_Length_000 (Buffer));

   function Valid_Legacy_Session_ID_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Legacy_Session_ID_Length_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Session_ID_Length (Buffer : Types.Bytes) return Legacy_Session_ID_Length_Type is
      ((if Valid_Legacy_Session_ID_Length_000 (Buffer) then Get_Legacy_Session_ID_Length_000 (Buffer) else Unreachable_Legacy_Session_ID_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID_Length (Buffer));

   function Valid_Legacy_Session_ID_0000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Session_ID_Length_000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + 35) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Session_ID_0000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 35))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID_0000 (Buffer));

   function Get_Legacy_Session_ID_0000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 34))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID_0000 (Buffer));

   function Valid_Legacy_Session_ID (Buffer : Types.Bytes) return Boolean is
      (Valid_Legacy_Session_ID_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Session_ID_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Legacy_Session_ID_0000 (Buffer) then Get_Legacy_Session_ID_0000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID (Buffer));

   function Get_Legacy_Session_ID_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Legacy_Session_ID_0000 (Buffer) then Get_Legacy_Session_ID_0000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID (Buffer));

   procedure Get_Legacy_Session_ID (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Session_ID (Buffer)),
       Post => (First = Get_Legacy_Session_ID_First (Buffer) and then Last = Get_Legacy_Session_ID_Last (Buffer));

   function Valid_Cipher_Suite_00000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Session_ID_0000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + 37) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Cipher_Suite_00000 (Buffer : Types.Bytes) return Cipher_Suite_Type is
      (Convert_To_Cipher_Suite_Type (Buffer ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 35) .. (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 36)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Cipher_Suite_00000 (Buffer));

   function Valid_Cipher_Suite (Buffer : Types.Bytes) return Boolean is
      (Valid_Cipher_Suite_00000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Cipher_Suite (Buffer : Types.Bytes) return Cipher_Suite_Type is
      ((if Valid_Cipher_Suite_00000 (Buffer) then Get_Cipher_Suite_00000 (Buffer) else Unreachable_Cipher_Suite_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Cipher_Suite (Buffer));

   function Valid_Legacy_Compression_Method_000000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Cipher_Suite_00000 (Buffer) and then ((Buffer'Length >= (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + 38) and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_Legacy_Compression_Method_Type_Base (Buffer ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 37) .. (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 37)), 0) <= 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Compression_Method_000000 (Buffer : Types.Bytes) return Legacy_Compression_Method_Type is
      (Convert_To_Legacy_Compression_Method_Type_Base (Buffer ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 37) .. (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 37)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Compression_Method_000000 (Buffer));

   function Valid_Legacy_Compression_Method (Buffer : Types.Bytes) return Boolean is
      (Valid_Legacy_Compression_Method_000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Compression_Method (Buffer : Types.Bytes) return Legacy_Compression_Method_Type is
      ((if Valid_Legacy_Compression_Method_000000 (Buffer) then Get_Legacy_Compression_Method_000000 (Buffer) else Unreachable_Legacy_Compression_Method_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Compression_Method (Buffer));

   function Valid_Extensions_Length_0000000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Compression_Method_000000 (Buffer) and then ((Buffer'Length >= (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + 40) and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_Server_Hello_Extensions_Length_Type_Base (Buffer ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 38) .. (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 39)), 0) >= 6)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_Length_0000000 (Buffer : Types.Bytes) return Server_Hello_Extensions_Length_Type is
      (Convert_To_Server_Hello_Extensions_Length_Type_Base (Buffer ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 38) .. (Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 39)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_Length_0000000 (Buffer));

   function Valid_Extensions_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_Length_0000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_Length (Buffer : Types.Bytes) return Server_Hello_Extensions_Length_Type is
      ((if Valid_Extensions_Length_0000000 (Buffer) then Get_Extensions_Length_0000000 (Buffer) else Unreachable_Server_Hello_Extensions_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_Length (Buffer));

   function Valid_Extensions_00000000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Extensions_Length_0000000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Extensions_Length_0000000 (Buffer)) + Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + 40) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_00000000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 40))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_00000000 (Buffer));

   function Get_Extensions_00000000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Extensions_Length_0000000 (Buffer)) + Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + Buffer'First + 39))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_00000000 (Buffer));

   function Valid_Extensions (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_00000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extensions_00000000 (Buffer) then Get_Extensions_00000000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer));

   function Get_Extensions_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extensions_00000000 (Buffer) then Get_Extensions_00000000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer));

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer)),
       Post => ((First = Get_Extensions_First (Buffer) and then Last = Get_Extensions_Last (Buffer)) and then TLS_Handshake.Extensions.Is_Contained (Buffer (First .. Last)));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_00000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Extensions_00000000 (Buffer) then (Types.Length_Type (Get_Extensions_Length_0000000 (Buffer)) + Types.Length_Type (Get_Legacy_Session_ID_Length_000 (Buffer)) + 40) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.Server_Hello;
