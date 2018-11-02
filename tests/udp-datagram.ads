package UDP.Datagram
  with SPARK_Mode
is

   pragma Warnings (Off, "precondition is statically false");

   function Unreachable_Port_Type return Port_Type is
      (Port_Type'First)
     with
       Pre => False;

   function Unreachable_Length_Type return Length_Type is
      (Length_Type'First)
     with
       Pre => False;

   function Unreachable_Checksum_Type return Checksum_Type is
      (Checksum_Type'First)
     with
       Pre => False;

   function Unreachable_Natural return Natural is
      (Natural'First)
     with
       Pre => False;

   pragma Warnings (On, "precondition is statically false");

   function Is_Contained (Buffer : Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Initialize (Buffer : Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Source_Port_0 (Buffer : Bytes) return Boolean is
      ((Buffer'Length >= 2 and then Buffer'First <= (Natural'Last / 2)))
     with
       Pre => Is_Contained (Buffer);

   function Source_Port_0 (Buffer : Bytes) return Port_Type is
      (Convert_To_Port_Type (Buffer (Buffer'First .. (Buffer'First + 1))))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Source_Port_0 (Buffer));

   function Valid_Source_Port (Buffer : Bytes) return Boolean is
      (Valid_Source_Port_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Source_Port (Buffer : Bytes) return Port_Type is
      ((if Valid_Source_Port_0 (Buffer) then Source_Port_0 (Buffer) else Unreachable_Port_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Source_Port (Buffer));

   function Valid_Destination_Port_00 (Buffer : Bytes) return Boolean is
      ((Valid_Source_Port_0 (Buffer) and then (Buffer'Length >= 4 and then Buffer'First <= (Natural'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Destination_Port_00 (Buffer : Bytes) return Port_Type is
      (Convert_To_Port_Type (Buffer ((Buffer'First + 2) .. (Buffer'First + 3))))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Destination_Port_00 (Buffer));

   function Valid_Destination_Port (Buffer : Bytes) return Boolean is
      (Valid_Destination_Port_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Destination_Port (Buffer : Bytes) return Port_Type is
      ((if Valid_Destination_Port_00 (Buffer) then Destination_Port_00 (Buffer) else Unreachable_Port_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Destination_Port (Buffer));

   function Valid_Length_000 (Buffer : Bytes) return Boolean is
      ((Valid_Destination_Port_00 (Buffer) and then ((Buffer'Length >= 6 and then Buffer'First <= (Natural'Last / 2)) and then Convert_To_Length_Type_Base (Buffer ((Buffer'First + 4) .. (Buffer'First + 5))) >= 8)))
     with
       Pre => Is_Contained (Buffer);

   function Length_000 (Buffer : Bytes) return Length_Type is
      (Convert_To_Length_Type_Base (Buffer ((Buffer'First + 4) .. (Buffer'First + 5))))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Length_000 (Buffer));

   function Valid_Length (Buffer : Bytes) return Boolean is
      (Valid_Length_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Length (Buffer : Bytes) return Length_Type is
      ((if Valid_Length_000 (Buffer) then Length_000 (Buffer) else Unreachable_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Length (Buffer));

   function Valid_Checksum_0000 (Buffer : Bytes) return Boolean is
      ((Valid_Length_000 (Buffer) and then (Buffer'Length >= 8 and then Buffer'First <= (Natural'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Checksum_0000 (Buffer : Bytes) return Checksum_Type is
      (Convert_To_Checksum_Type (Buffer ((Buffer'First + 6) .. (Buffer'First + 7))))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Checksum_0000 (Buffer));

   function Valid_Checksum (Buffer : Bytes) return Boolean is
      (Valid_Checksum_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Checksum (Buffer : Bytes) return Checksum_Type is
      ((if Valid_Checksum_0000 (Buffer) then Checksum_0000 (Buffer) else Unreachable_Checksum_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Checksum (Buffer));

   function Valid_Payload_00000 (Buffer : Bytes) return Boolean is
      ((Valid_Checksum_0000 (Buffer) and then (Buffer'Length >= Natural (Length_000 (Buffer)) and then Buffer'First <= (Natural'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Payload_00000_First (Buffer : Bytes) return Natural is
      ((Buffer'First + 8))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload_00000 (Buffer));

   function Payload_00000_Last (Buffer : Bytes) return Natural is
      ((Buffer'First + Natural (Length_000 (Buffer)) + (-1)))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload_00000 (Buffer));

   function Valid_Payload (Buffer : Bytes) return Boolean is
      (Valid_Payload_00000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Payload_First (Buffer : Bytes) return Natural is
      ((if Valid_Payload_00000 (Buffer) then Payload_00000_First (Buffer) else Unreachable_Natural))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload (Buffer));

   function Payload_Last (Buffer : Bytes) return Natural is
      ((if Valid_Payload_00000 (Buffer) then Payload_00000_Last (Buffer) else Unreachable_Natural))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload (Buffer));

   procedure Payload (Buffer : Bytes; First : out Natural; Last : out Natural)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload (Buffer)),
       Post => (First = Payload_First (Buffer) and then Last = Payload_Last (Buffer));

   function Is_Valid (Buffer : Bytes) return Boolean is
      (Valid_Payload (Buffer))
     with
       Pre => Is_Contained (Buffer);

end UDP.Datagram;