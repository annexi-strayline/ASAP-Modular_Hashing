------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2018-2021, ANNEXI-STRAYLINE Trans-Human Ltd.              --
--  All rights reserved.                                                    --
--                                                                          --
--  Original Contributors:                                                  --
--  * Richard Wai, Ensi Martini, Aninda Poddar, Noshen Atashe               --
--    (ANNEXI-STRAYLINE)                                                    --
--                                                                          --
--  Redistribution and use in source and binary forms, with or without      --
--  modification, are permitted provided that the following conditions are  --
--  met:                                                                    --
--                                                                          --
--      * Redistributions of source code must retain the above copyright    --
--        notice, this list of conditions and the following disclaimer.     --
--                                                                          --
--      * Redistributions in binary form must reproduce the above copyright --
--        notice, this list of conditions and the following disclaimer in   --
--        the documentation and/or other materials provided with the        --
--        distribution.                                                     --
--                                                                          --
--      * Neither the name of the copyright holder nor the names of its     --
--        contributors may be used to endorse or promote products derived   --
--        from this software without specific prior written permission.     --
--                                                                          --
--  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     --
--  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       --
--  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A --
--  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      --
--  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   --
--  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        --
--  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   --
--  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   --
--  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     --
--  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   --
--  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    --
--                                                                          --
------------------------------------------------------------------------------

with Interfaces;
with Ada.Streams;

package Modular_Hashing is
   
   ----------
   -- Hash --
   ----------
   
   type Hash is abstract tagged null record;
   
   -- The Hash Type represents a prototypical Hash value, being some kind of
   -- fixed-sized representation derrived from an input, such that two equal
   -- inputs generate the same Hash value.
   
   function "<" (Left, Right: Hash) return Boolean is abstract;
   function ">" (Left, Right: Hash) return Boolean is abstract;
   function "=" (Left, Right: Hash) return Boolean is abstract;
   
   
   -- Representation --
   --------------------
   
   type Hash_Binary_Value is
     array (Positive range <>) of Interfaces.Unsigned_8;
   
   function  Binary_Bytes (Value: Hash) return Positive is abstract;
   
   -- Returns the number of bytes required to represent the Hash value with
   -- a Hash_Binary array.
   
   function  Binary (Value: Hash) return Hash_Binary_Value is abstract with
       Post'Class => Binary'Result'Length = Value.Binary_Bytes;
   
   -- Returns a binary represetnation of the Hash value as an array of bytes.
   -- This output is used by the default implementation of Hexadecimal, which
   -- assumes that the resulting value is in ** LITTLE ENDIAN ** order
   
   function  Hexadecimal_Digits (Value: Hash) return Positive is
     (Hash'Class(Value).Binary_Bytes * 2);
   
   -- Returns the number of hexidecimal digits required to represent the Hash
   -- value. 
   
   function  Hexadecimal (Value     : Hash; 
                          Lower_Case: Boolean := True) 
                         return String with
     Post => Hexadecimal'Result'Length = Value.Hexadecimal_Digits;
   
   -- Returns the Hexadecimal representation of the Binary representation of 
   -- Hash value. The size of the returned String is always constant for any
   -- value of the same Hash'Class type, and can be queried via
   -- Hexidecimal_Digits function.
   
   
   --------------------
   -- Hash_Algorithm --
   --------------------
   
   type Hash_Algorithm is abstract 
     new Ada.Streams.Root_Stream_Type with null record;
   
   -- Members of Hash_Algorithm'Class represent any given Hashing algorithm
   -- which can produce a value of Hash'Class from an arbitrary input delivered
   -- via the Ada Stream interface.
   --
   -- Hash_Algorithm'Class members are not required, and should not be expected
   -- to be, task-safe.
   
   
   -- Streams Interface --
   -----------------------
   
   overriding procedure Read 
     (Stream: in out Hash_Algorithm;
      Item  :    out Ada.Streams.Stream_Element_Array;
      Last  :    out Ada.Streams.Stream_Element_Offset);
   -- Hash algorithms are always "one way". Reading from a Hash_Algorithm'Class
   -- constitutes an incorrect application of a Hash_Algorithm and causes an
   -- explicit raise of Program_Error
   
   
   overriding procedure Write 
     (Stream: in out Hash_Algorithm;
      Item  : in     Ada.Streams.Stream_Element_Array) 
     is abstract;
   -- Accepts a stream or message of an arbitrary size.
   --
   -- For message digest algorithms, content streamed to Write consitutes the
   -- message, and is held in a buffer until Digest is executed, which triggers
   -- digestion of the message (buffer contents at that point), into a single
   -- Hash value.
   
   
   -- Executive Operations --
   --------------------------
   procedure Reset (Engine: in out Hash_Algorithm) is abstract;
   -- Resets any internal state to the initial state, and clears any buffers.
   --
   -- Hash_Algorithms shall be self-initializing. Reset should only be 
   -- required to flush an aborted message
   
   function  Digest (Engine: in out Hash_Algorithm) 
                    return Hash'Class is abstract;
   -- Returns the Hash value from the Hash_Algoritm. For digest algorithms,
   -- this also causes the Hash to be computed.
   --
   -- The state of the Hash_Algorithm is reset. Any buffers are cleared.
   
   
   -- Message digest
   function  Digest (Engine : in out Hash_Algorithm'Class;
                     Message: in     String) 
                    return Hash'Class;
   
   function  Digest (Engine : in out Hash_Algorithm'Class;
                     Message: in     Wide_String) 
                    return Hash'Class;
   
   function  Digest (Engine : in out Hash_Algorithm'Class;
                     Message: in     Wide_Wide_String) 
                    return Hash'Class;
   -- Directly writes Message to Engine's stream, and then invokes Digest,
   -- returning the result

   
end Modular_Hashing;
