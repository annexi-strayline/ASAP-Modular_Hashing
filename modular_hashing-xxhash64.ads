------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                                 xxHash64                                 --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2021, ANNEXI-STRAYLINE Trans-Human Ltd.                   --
--  All rights reserved.                                                    --
--                                                                          --
--  Original Contributors:                                                  --
--  * Richard Wai (ANNEXI-STRAYLINE)                                        --
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

-- This engine implements Yann Collet's xxHash32 hash algorithm that is freely
-- available at https://github.com/Cyan4973/xxHash (v 0.8.0)

-- Specific implementations (package bodies) contain further specific licenses
-- as needed.

with Ada.Streams;
with Interfaces;

package Modular_Hashing.xxHash64 is
   
   type XXH64_Hash is new Hash with private;
   
   -- xxHash is a non-cryptographic fixed-sized hash for arbitrary message
   -- lengths. The digest is 64 bits (8 bytes).
   
   overriding function "<"   (Left, Right: XXH64_Hash) return Boolean;
   overriding function ">"   (Left, Right: XXH64_Hash) return Boolean;
   overriding function "="   (Left, Right: XXH64_Hash) return Boolean;
   
   XXH64_Hash_Bytes: constant := 8;
   
   overriding function Binary_Bytes (Value: XXH64_Hash) return Positive is 
     (XXH64_Hash_Bytes);
   
   overriding function Binary (Value: XXH64_Hash)
                              return Hash_Binary_Value 
   with Post => Binary'Result'Length = XXH64_Hash_Bytes;
   
   
   type XXH64_Engine is new Hash_Algorithm with private;
   
   overriding 
   procedure Write (Engine: in out XXH64_Engine;
                    Item  : in     Ada.Streams.Stream_Element_Array);
   
   overriding procedure Reset  (Engine: in out XXH64_Engine);
   
   overriding function  Digest (Engine: in out XXH64_Engine)
                               return Hash'Class;
   
private
   use Ada.Streams, Interfaces;
   
   subtype Accumulator_Type is Unsigned_64;
   
   type XXH64_Hash is new Hash with
      record
         Digest: Accumulator_Type;
      end record;
   
   ------------------
   -- XXH64_Engine --
   ------------------
   
   -- Prime constants
   PRIME64_1: constant := 16#9E3779B185EBCA87#;
   PRIME64_2: constant := 16#C2B2AE3D27D4EB4F#;
   PRIME64_3: constant := 16#165667B19E3779F9#;
   PRIME64_4: constant := 16#85EBCA77C2B2AE63#;
   PRIME64_5: constant := 16#27D4EB2F165667C5#;
   
   pragma Assert (Stream_Element'Size = 8);
   
   
   type Accumulator_Array is array (1 .. 4) of Accumulator_Type;
   
   Accumulators_Initial: constant Accumulator_Array
     := (1 => PRIME64_1 + PRIME64_2,
         2 => PRIME64_2,
         3 => 0,
         4 => 0 - PRIME64_1);
   
   type XXH64_Engine is new Hash_Algorithm with
      record
         Buffer      : Stream_Element_Array(1 .. 32);
         Last_Element: Stream_Element_Offset := 0;
         -- XXH64 works on "stripes" of 16 bytes
         
         Input_Total : Accumulator_Type := 0;
         -- Total input length. Note that the xxHash specification says:
         -- "If input length is so large that it requires more than 32-bits,
         --  only the lower 32-bits are added to the accumulator". This applies
         -- to xxHash64 as well.
         --
         -- In other words: wrap-around is OK
         
         Accumulators: Accumulator_Array := Accumulators_Initial;
      end record;
   
end Modular_Hashing.xxHash64;
