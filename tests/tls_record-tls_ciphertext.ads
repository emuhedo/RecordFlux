package TLS_Record.TLS_Ciphertext
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
      (((Buffer'Length >= 1 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Content_Type (Buffer (Buffer'First .. Buffer'First), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Tag_0 (Buffer : Types.Bytes) return Content_Type is
      (Convert_To_Content_Type (Buffer (Buffer'First .. Buffer'First), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Tag_0 (Buffer));

   function Valid_Tag (Buffer : Types.Bytes) return Boolean is
      ((Valid_Tag_0 (Buffer) and then Get_Tag_0 (Buffer) = APPLICATION_DATA))
     with
       Pre => Is_Contained (Buffer);

   function Get_Tag (Buffer : Types.Bytes) return Content_Type is
      ((if Valid_Tag_0 (Buffer) then Get_Tag_0 (Buffer) else Unreachable_Content_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Tag (Buffer));

   function Valid_Legacy_Record_Version_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Tag_0 (Buffer) and then (((Buffer'Length >= 3 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Get_Tag_0 (Buffer) = APPLICATION_DATA) and then Valid_Protocol_Version_Type (Buffer ((Buffer'First + 1) .. (Buffer'First + 2)), 0))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Record_Version_00 (Buffer : Types.Bytes) return Protocol_Version_Type is
      (Convert_To_Protocol_Version_Type (Buffer ((Buffer'First + 1) .. (Buffer'First + 2)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Record_Version_00 (Buffer));

   function Valid_Legacy_Record_Version (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Record_Version_00 (Buffer) and then Get_Legacy_Record_Version_00 (Buffer) = TLS_1_2))
     with
       Pre => Is_Contained (Buffer);

   function Get_Legacy_Record_Version (Buffer : Types.Bytes) return Protocol_Version_Type is
      ((if Valid_Legacy_Record_Version_00 (Buffer) then Get_Legacy_Record_Version_00 (Buffer) else Unreachable_Protocol_Version_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Legacy_Record_Version (Buffer));

   function Valid_Length_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Legacy_Record_Version_00 (Buffer) and then ((Buffer'Length >= 5 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Get_Legacy_Record_Version_00 (Buffer) = TLS_1_2)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Length_000 (Buffer : Types.Bytes) return Length_Type is
      (Convert_To_Length_Type (Buffer ((Buffer'First + 3) .. (Buffer'First + 4)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Length_000 (Buffer));

   function Valid_Length (Buffer : Types.Bytes) return Boolean is
      ((Valid_Length_000 (Buffer) and then Get_Length_000 (Buffer) <= 16640))
     with
       Pre => Is_Contained (Buffer);

   function Get_Length (Buffer : Types.Bytes) return Length_Type is
      ((if Valid_Length_000 (Buffer) then Get_Length_000 (Buffer) else Unreachable_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Length (Buffer));

   function Valid_Encrypted_Record_0000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Length_000 (Buffer) and then ((Buffer'Length >= (Types.Length_Type (Get_Length_000 (Buffer)) + 5) and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Get_Length_000 (Buffer) <= 16640)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Encrypted_Record_0000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 5))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Encrypted_Record_0000 (Buffer));

   function Get_Encrypted_Record_0000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Length_000 (Buffer)) + Buffer'First + 4))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Encrypted_Record_0000 (Buffer));

   function Valid_Encrypted_Record (Buffer : Types.Bytes) return Boolean is
      (Valid_Encrypted_Record_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Encrypted_Record_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Encrypted_Record_0000 (Buffer) then Get_Encrypted_Record_0000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Encrypted_Record (Buffer));

   function Get_Encrypted_Record_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Encrypted_Record_0000 (Buffer) then Get_Encrypted_Record_0000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Encrypted_Record (Buffer));

   procedure Get_Encrypted_Record (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Encrypted_Record (Buffer)),
       Post => (First = Get_Encrypted_Record_First (Buffer) and then Last = Get_Encrypted_Record_Last (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Encrypted_Record_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Encrypted_Record_0000 (Buffer) then (Types.Length_Type (Get_Length_000 (Buffer)) + 5) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Record.TLS_Ciphertext;
