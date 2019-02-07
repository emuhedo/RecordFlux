with TLS_Handshake.Extensions;

package TLS_Handshake.Certificate_Request
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Certificate_Request_Context_Length_0 (Buffer : Types.Bytes) return Boolean is
      ((Buffer'Length >= 1 and then Buffer'First <= (Types.Index_Type'Last / 2)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Certificate_Request_Context_Length_0 (Buffer : Types.Bytes) return Certificate_Request_Context_Length_Type is
      (Convert_To_Certificate_Request_Context_Length_Type (Buffer (Buffer'First .. Buffer'First), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context_Length_0 (Buffer));

   function Valid_Certificate_Request_Context_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Certificate_Request_Context_Length_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Certificate_Request_Context_Length (Buffer : Types.Bytes) return Certificate_Request_Context_Length_Type is
      ((if Valid_Certificate_Request_Context_Length_0 (Buffer) then Get_Certificate_Request_Context_Length_0 (Buffer) else Unreachable_Certificate_Request_Context_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context_Length (Buffer));

   function Valid_Certificate_Request_Context_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Certificate_Request_Context_Length_0 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + 1) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Certificate_Request_Context_00_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 1))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context_00 (Buffer));

   function Get_Certificate_Request_Context_00_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context_00 (Buffer));

   function Valid_Certificate_Request_Context (Buffer : Types.Bytes) return Boolean is
      (Valid_Certificate_Request_Context_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Certificate_Request_Context_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Certificate_Request_Context_00 (Buffer) then Get_Certificate_Request_Context_00_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context (Buffer));

   function Get_Certificate_Request_Context_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Certificate_Request_Context_00 (Buffer) then Get_Certificate_Request_Context_00_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context (Buffer));

   procedure Get_Certificate_Request_Context (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Certificate_Request_Context (Buffer)),
       Post => (First = Get_Certificate_Request_Context_First (Buffer) and then Last = Get_Certificate_Request_Context_Last (Buffer));

   function Valid_Extensions_Length_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Certificate_Request_Context_00 (Buffer) and then ((Buffer'Length >= (Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + 3) and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_Certificate_Request_Extensions_Length_Type_Base (Buffer ((Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First + 1) .. (Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First + 2)), 0) >= 2)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_Length_000 (Buffer : Types.Bytes) return Certificate_Request_Extensions_Length_Type is
      (Convert_To_Certificate_Request_Extensions_Length_Type_Base (Buffer ((Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First + 1) .. (Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First + 2)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_Length_000 (Buffer));

   function Valid_Extensions_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_Length_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_Length (Buffer : Types.Bytes) return Certificate_Request_Extensions_Length_Type is
      ((if Valid_Extensions_Length_000 (Buffer) then Get_Extensions_Length_000 (Buffer) else Unreachable_Certificate_Request_Extensions_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_Length (Buffer));

   function Valid_Extensions_0000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Extensions_Length_000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Extensions_Length_000 (Buffer)) + Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + 3) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_0000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First + 3))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_0000 (Buffer));

   function Get_Extensions_0000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Extensions_Length_000 (Buffer)) + Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + Buffer'First + 2))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_0000 (Buffer));

   function Valid_Extensions (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extensions_0000 (Buffer) then Get_Extensions_0000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer));

   function Get_Extensions_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extensions_0000 (Buffer) then Get_Extensions_0000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer));

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer)),
       Post => ((First = Get_Extensions_First (Buffer) and then Last = Get_Extensions_Last (Buffer)) and then TLS_Handshake.Extensions.Is_Contained (Buffer (First .. Last)));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Extensions_0000 (Buffer) then (Types.Length_Type (Get_Extensions_Length_000 (Buffer)) + Types.Length_Type (Get_Certificate_Request_Context_Length_0 (Buffer)) + 3) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.Certificate_Request;
