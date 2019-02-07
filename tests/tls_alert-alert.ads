package TLS_Alert.Alert
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Alert_Level_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 1 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Alert_Level (Buffer (Buffer'First .. Buffer'First), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Alert_Level_0 (Buffer : Types.Bytes) return Alert_Level is
      (Convert_To_Alert_Level (Buffer (Buffer'First .. Buffer'First), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Alert_Level_0 (Buffer));

   function Valid_Alert_Level (Buffer : Types.Bytes) return Boolean is
      (Valid_Alert_Level_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Alert_Level (Buffer : Types.Bytes) return Alert_Level is
      ((if Valid_Alert_Level_0 (Buffer) then Get_Alert_Level_0 (Buffer) else Unreachable_Alert_Level))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Alert_Level (Buffer));

   function Valid_Alert_Description_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Alert_Level_0 (Buffer) and then ((Buffer'Length >= 2 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Alert_Description_Type (Buffer ((Buffer'First + 1) .. (Buffer'First + 1)), 0))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Alert_Description_00 (Buffer : Types.Bytes) return Alert_Description_Type is
      (Convert_To_Alert_Description_Type (Buffer ((Buffer'First + 1) .. (Buffer'First + 1)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Alert_Description_00 (Buffer));

   function Valid_Alert_Description (Buffer : Types.Bytes) return Boolean is
      (Valid_Alert_Description_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Alert_Description (Buffer : Types.Bytes) return Alert_Description_Type is
      ((if Valid_Alert_Description_00 (Buffer) then Get_Alert_Description_00 (Buffer) else Unreachable_Alert_Description_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Alert_Description (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Alert_Description_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Alert_Description_00 (Buffer) then 2 else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Alert.Alert;
