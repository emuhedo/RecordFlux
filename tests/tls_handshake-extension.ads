package TLS_Handshake.Extension
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Tag_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 2 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Extension_Type (Buffer (Buffer'First .. (Buffer'First + 1)), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Tag_0 (Buffer : Types.Bytes) return Extension_Type is
      (Convert_To_Extension_Type (Buffer (Buffer'First .. (Buffer'First + 1)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Tag_0 (Buffer));

   function Valid_Tag (Buffer : Types.Bytes) return Boolean is
      (Valid_Tag_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Tag (Buffer : Types.Bytes) return Extension_Type is
      ((if Valid_Tag_0 (Buffer) then Get_Tag_0 (Buffer) else Unreachable_Extension_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Tag (Buffer));

   function Valid_Extension_Data_Length_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Tag_0 (Buffer) and then (Buffer'Length >= 4 and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extension_Data_Length_00 (Buffer : Types.Bytes) return Extension_Data_Length_Type is
      (Convert_To_Extension_Data_Length_Type (Buffer ((Buffer'First + 2) .. (Buffer'First + 3)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data_Length_00 (Buffer));

   function Valid_Extension_Data_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Extension_Data_Length_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extension_Data_Length (Buffer : Types.Bytes) return Extension_Data_Length_Type is
      ((if Valid_Extension_Data_Length_00 (Buffer) then Get_Extension_Data_Length_00 (Buffer) else Unreachable_Extension_Data_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data_Length (Buffer));

   function Valid_Extension_Data_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Extension_Data_Length_00 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Extension_Data_Length_00 (Buffer)) + 4) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extension_Data_000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 4))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data_000 (Buffer));

   function Get_Extension_Data_000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Extension_Data_Length_00 (Buffer)) + Buffer'First + 3))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data_000 (Buffer));

   function Valid_Extension_Data (Buffer : Types.Bytes) return Boolean is
      (Valid_Extension_Data_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extension_Data_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extension_Data_000 (Buffer) then Get_Extension_Data_000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data (Buffer));

   function Get_Extension_Data_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extension_Data_000 (Buffer) then Get_Extension_Data_000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data (Buffer));

   procedure Get_Extension_Data (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extension_Data (Buffer)),
       Post => (First = Get_Extension_Data_First (Buffer) and then Last = Get_Extension_Data_Last (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Extension_Data_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Extension_Data_000 (Buffer) then (Types.Length_Type (Get_Extension_Data_Length_00 (Buffer)) + 4) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.Extension;
