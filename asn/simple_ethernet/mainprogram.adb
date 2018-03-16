with Ada.Directories;
with Ada.Sequential_IO;
with Ada.Text_IO;

with adaasn1rtl; use adaasn1rtl;
with Ethernet; use Ethernet;

function MainProgram return Integer is

    subtype Byte is BitArray (1 .. 8);

    function Read_File (Name : String) return EthernetFrame_ACN_Stream is
        package Byte_IO is new Ada.Sequential_IO (Byte);
        Input_File : Byte_IO.File_Type;
        Value : Byte;
        I : Natural := 0;
        Stream : EthernetFrame_ACN_Stream := (
            K => 0,
            DataLen => (Integer(Ada.Directories.Size(Name)) * 8),
            Data => (others => 0));
    begin
        Byte_IO.Open (Input_File, Byte_IO.In_File, Name);
        while not Byte_IO.End_Of_File (Input_File) loop
            I := I + 1;
            Byte_IO.Read (Input_File, Value);
            for J in 1 .. 8 loop
                Stream.Data ((I-1)*8+J) := Value (9 - J);
            end loop;
        end loop;
        Byte_IO.Close (Input_File);
        return Stream;
    end Read_File;

    OutVal : EthernetFrame;
    Result : ASN1_RESULT;
    BytesLoaded : Integer := 0;
    loadXmlSucceeded : Boolean := False ;

begin

    declare
        Strm : EthernetFrame_ACN_Stream := Read_File ("../../tests/ethernet_802.3.raw");
    begin
        EthernetFrame_ACN_Decode (OutVal, Strm, Result);
    end;

    if not Result.Success then
        Ada.Text_IO.Put ("Decode Failed");
        Ada.Text_IO.New_Line;
        return 2;
    end if;

    Ada.Text_IO.Put ("Destination: ");
    for I in OutVal.destination.Data'First .. OutVal.destination.Data'last loop
        Ada.Text_IO.Put (OutVal.destination.Data (I)'Image);
    end loop;
    Ada.Text_IO.New_Line;
    Ada.Text_IO.Put ("Source: ");
    for I in OutVal.source.Data'First .. OutVal.source.Data'last loop
        Ada.Text_IO.Put (OutVal.source.Data (I)'Image);
    end loop;
    Ada.Text_IO.New_Line;
    Ada.Text_IO.Put ("Payload: ");
    for I in OutVal.payload.Data'First .. OutVal.payload.Data'last loop
        Ada.Text_IO.Put (OutVal.payload.Data (I)'Image);
    end loop;
    Ada.Text_IO.New_Line;
    return 0;

end MainProgram;
