------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                                 xxHash32                                 --
--                                                                          --
--                          Pedantic Implementation                         --
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

-- This implementation follows the official xxHash algorithm specification as
-- described at https://github.com/Cyan4973/xxHash (v 0.8.0).
--
-- The specification contains the following copyright notice:
-- 
-- Copyright (c) Yann Collet
--
-- Permission is granted to copy and distribute this document for any purpose
-- and without charge, including translations into other languages and
-- incorporation into compilations, provided that the copyright notice and this
-- notice are preserved, and that any substantive changes or deletions from the
-- original are clearly marked. Distribution of this document is unlimited.

package body Modular_Hashing.xxHash32 is
   
   --
   -- XXH32_Hash
   --
   
   function "<" (Left, Right : XXH32_Hash) return Boolean is 
     (Left.Digest < Right.Digest);
   
   function ">" (Left, Right : XXH32_Hash) return Boolean is 
     (Left.Digest > Right.Digest);
   
   function "=" (Left, Right : XXH32_Hash) return Boolean is
     (Left.Digest = Right.Digest);
   
   ------------
   -- Binary --
   ------------
   
   function Binary (Value: XXH32_Hash) return Hash_Binary_Value is
      V: Accumulator_Type := Value.Digest;
   begin
      return Bin: Hash_Binary_Value (1 .. XXH32_Hash_Bytes) do
         for Byte of Bin loop
            Byte := Unsigned_8 (V and 16#FF#);
            V := Shift_Right (V, 8);
         end loop;
      end return;
   end Binary;
   
   
   --
   -- XXH32_Engine
   --
   
   ------------------
   -- Stripe_Round --  "Step 2"
   ------------------
   
   -- Stripe_Round executes one full strip round (16-bytes) on the engine.
   -- This consumes the entire 16-byte Buffer (which must be full)
   
   procedure Stripe_Round (Engine: in out XXH32_Engine) with
     Inline, 
     Pre  => Engine.Last_Element = Engine.Buffer'Last
   is
      Lanes       : Accumulator_Array;
      Accumulators: Accumulator_Array renames Engine.Accumulators;
   begin
      -- For each lane, load the value and then run the round on the
      -- accumulator. This is designed for simd, and we'll try to structure
      -- this to give the compiler as much of a chance as possible to see the
      -- obvious simd conditions
      
      -- Load lanes
      declare
         I: Stream_Element_Offset := Engine.Buffer'First;
      begin
         for Lane of Lanes loop
            for Byte of reverse Engine.Buffer(I .. I + 3) loop
               Lane := Shift_Left (Lane, 8);
               Lane := Lane + Accumulator_Type (Byte);
            end loop;
            
            I := I + 4;
         end loop;
      end;
      
      for I in Lanes'Range loop
         -- The actual rounds
         Accumulators(I) := Accumulators(I) + (Lanes(I) * PRIME32_2);
         Accumulators(I) := Rotate_Left (Accumulators(I), 13);
         Accumulators(I) := Accumulators(I) * PRIME32_1;
      end loop;
      
      Engine.Last_Element := Engine.Buffer'First - 1;
   end Stripe_Round;

   -----------
   -- Write --
   -----------
   
   procedure Write  (Engine : in out XXH32_Engine;
                     Item   : in     Stream_Element_Array)
   is 
      Last_Load: Stream_Element_Offset := Item'First - 1;
      
      procedure Load_Round with Inline, Pre => Last_Load < Item'Last is 
         Buffer_Space: Stream_Element_Offset 
           := Engine.Buffer'Last - Engine.Last_Element;
         
         Load_First: constant Stream_Element_Offset := Last_Load + 1;
         Load_Last : Stream_Element_Offset;
         Load_Size : Stream_Element_Offset := Buffer_Space;
         New_Last_Element: Stream_Element_Offset;
      begin
         pragma Assert (Buffer_Space > 0);
         
         -- Load in as many bytes as we can into the buffer. If we hit 16
         -- bytes, we call a Stripe_Round.
         
         Load_Last  := Load_First + Buffer_Space - 1;
         
         if Load_Last > Item'Last then
            Load_Last := Item'Last;
            Load_Size := Load_Last - Load_First + 1;
         end if;
         
         New_Last_Element := Engine.Last_Element + Load_Size;
         
         Engine.Buffer (Engine.Last_Element + 1 .. New_Last_Element)
           := Item (Load_First .. Load_Last);
         
         Last_Load := Load_Last;
         Engine.Last_Element := New_Last_Element;
         
         if New_Last_Element = Engine.Buffer'Last then
            Stripe_Round (Engine);
         end if;
         
      end;
      
   begin
      if Item'Length = 0 then return; end if;
      
      while Last_Load < Item'Last loop
         Load_Round;
      end loop;
      
      Engine.Input_Total := Engine.Input_Total + Item'Length;
   end Write;
   
   -----------
   -- Reset --
   -----------
   
   procedure Reset (Engine : in out XXH32_Engine) is
   begin
      Engine.Last_Element := Engine.Buffer'First - 1;
      Engine.Input_Total  := 0;
      Engine.Accumulators := Accumulators_Initial;
   end Reset;
   
   ------------
   -- Digest --
   ------------
   
   function Digest (Engine : in out XXH32_Engine) return Hash'Class is
      Lane_Accumulators: Accumulator_Array renames Engine.Accumulators;
      Hash_Accumulator : Accumulator_Type; 
      
      -- Steps as per the xxHash spec
      procedure Step_1_Short with Inline; -- Step 1 with < 16 byte total input
      -- Step 2. Process Stripes is done in Write
      procedure Step_3       with Inline; -- Accumulator Convergence
      procedure Step_4       with Inline; -- Add input length
      procedure Step_5       with Inline; -- Consume remaining input
      procedure Step_6       with Inline; -- Final mix (avalanche)
      
      -- Step 1 Short
      procedure Step_1_Short is
         -- This is invoked when Digest is called before 16 or more bytes have
         -- been written to the engine
      begin
         Hash_Accumulator := PRIME32_5;
      end;
      
      -- Step 3: Accumulator Convergence
      procedure Step_3 is begin
         Hash_Accumulator 
           :=  Rotate_Left (Lane_Accumulators(1), 1)
             + Rotate_Left (Lane_Accumulators(2), 7)
             + Rotate_Left (Lane_Accumulators(3), 12)
             + Rotate_Left (Lane_Accumulators(4), 18);
      end;
      
      -- Step 4: Add input length
      procedure Step_4 is begin
         Hash_Accumulator := Hash_Accumulator + Engine.Input_Total;
      end;
      
      -- Step 5: Consume remaining input
      procedure Step_5 is 
         Lane: Accumulator_Type := 0;
         Mark: Stream_Element_Offset := Engine.Buffer'First;
      begin

         pragma Assert (Engine.Last_Element < Engine.Buffer'Last);
         
         while (Engine.Last_Element - Mark) >= 3 loop
            -- Note that since we are shifting the lane 4 x 8bits,
            -- the initial value of Lane does not matter at all,
            -- so we don't need to clear it every time
            
            for Byte of reverse Engine.Buffer (Mark .. Mark + 3) loop
               Lane := Shift_Left (Lane, 8);
               Lane := Lane + Accumulator_Type (Byte);
            end loop;
            
            Mark := Mark + 4;
            
            Hash_Accumulator := Hash_Accumulator + Lane * PRIME32_3;
            Hash_Accumulator := Rotate_Left (Hash_Accumulator, 17);
            Hash_Accumulator := Hash_Accumulator * PRIME32_4;
         end loop;
         
         while Mark <= Engine.Last_Element loop
            Lane := Accumulator_Type (Engine.Buffer(Mark));
            Hash_Accumulator := Hash_Accumulator + Lane * PRIME32_5;
            Hash_Accumulator := Rotate_Left (Hash_Accumulator, 11);
            Hash_Accumulator := Hash_Accumulator * PRIME32_1;
            Mark := Mark + 1;
         end loop;
         
      end;
      
      -- Step 6: Final mix (avalanche)
      procedure Step_6 is 
         Acc: Accumulator_Type renames Hash_Accumulator;
      begin
         Acc := Acc xor Shift_Right (Acc, 15);
         Acc := Acc  *  PRIME32_2;
         Acc := Acc xor Shift_Right (Acc, 13);
         Acc := Acc  *  PRIME32_3;
         Acc := Acc xor Shift_Right (Acc, 16);
      end Step_6;
      
   begin
      
      if Engine.Input_Total < 16 then
         -- If the total input is less than 16, we need to "manually"
         -- initialize the accumulator. If we have done any rounds ("Step 2")
         -- to process 16-byte "stripes", then we would use "Step 3" to
         -- initialize Hash_Accumulator from the Engine's accumulators.
         
         Hash_Accumulator := PRIME32_5;
      else
         -- Normal completion (Converge the engine accumulators into the hash
         -- accumulator)
         Step_3;
      end if;
      
      Step_4;
      Step_5;
      Step_6;
      
      return XXH32_Hash'(Digest => Hash_Accumulator);
      
   end Digest;
   
end Modular_Hashing.xxHash32;
