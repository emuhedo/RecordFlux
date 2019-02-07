package TLS_Handshake.Certificate_Verify
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Algorithm_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 2 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Signature_Scheme (Buffer (Buffer'First .. (Buffer'First + 1)), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Algorithm_0 (Buffer : Types.Bytes) return Signature_Scheme is
      (Convert_To_Signature_Scheme (Buffer (Buffer'First .. (Buffer'First + 1)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Algorithm_0 (Buffer));

   function Valid_Algorithm (Buffer : Types.Bytes) return Boolean is
      (Valid_Algorithm_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Algorithm (Buffer : Types.Bytes) return Signature_Scheme is
      ((if Valid_Algorithm_0 (Buffer) then Get_Algorithm_0 (Buffer) else Unreachable_Signature_Scheme))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Algorithm (Buffer));

   function Valid_Signature_Length_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Algorithm_0 (Buffer) and then (Buffer'Length >= 4 and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Signature_Length_00 (Buffer : Types.Bytes) return Signature_Length_Type is
      (Convert_To_Signature_Length_Type (Buffer ((Buffer'First + 2) .. (Buffer'First + 3)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature_Length_00 (Buffer));

   function Valid_Signature_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Signature_Length_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Signature_Length (Buffer : Types.Bytes) return Signature_Length_Type is
      ((if Valid_Signature_Length_00 (Buffer) then Get_Signature_Length_00 (Buffer) else Unreachable_Signature_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature_Length (Buffer));

   function Valid_Signature_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Signature_Length_00 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Signature_Length_00 (Buffer)) + 4) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Signature_000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 4))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature_000 (Buffer));

   function Get_Signature_000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Signature_Length_00 (Buffer)) + Buffer'First + 3))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature_000 (Buffer));

   function Valid_Signature (Buffer : Types.Bytes) return Boolean is
      (Valid_Signature_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Signature_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Signature_000 (Buffer) then Get_Signature_000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature (Buffer));

   function Get_Signature_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Signature_000 (Buffer) then Get_Signature_000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature (Buffer));

   procedure Get_Signature (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Signature (Buffer)),
       Post => (First = Get_Signature_First (Buffer) and then Last = Get_Signature_Last (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Signature_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Signature_000 (Buffer) then (Types.Length_Type (Get_Signature_Length_00 (Buffer)) + 4) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.Certificate_Verify;
