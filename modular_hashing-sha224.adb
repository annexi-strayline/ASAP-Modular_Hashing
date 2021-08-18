------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                                SHA2 (224)                                --
--                                                                          --
--                       - "Reference" Implementation -                     --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2019-2021, ANNEXI-STRAYLINE Trans-Human Ltd.              --
--  All rights reserved.                                                    --
--                                                                          --
--  Original Contributors:                                                  --
--  * Ensi Martini (ANNEXI-STRAYLINE)                                       --
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

package body Modular_Hashing.SHA224 is
   
   ------------------
   -- Digest_Chunk --
   ------------------
   
   -- This procedure is the internal digest that allows for a 512-bit block to 
   -- be processed without finishing the hash (padding)
   --
   -- This is the bulk of the SHA224 algorithm, missing only the addition of
   -- message size with padding, which is handed by the Digest subprogram
   
   procedure Digest_Chunk (Engine : in out SHA224_Engine) with Inline is
      
      A, B, C, D, E, F, G, H, S0, S1, Ch, Maj, Temp_1, Temp_2: Unsigned_32;
      Word_Sequence : array (1 .. 64) of Unsigned_32;
      
   begin
      
      -- Break the chunk into 16 32-bit words, assign to Word_Sequence
      for I in 1 .. 16 loop
         
          Word_Sequence(I) := 
           
           Shift_Left(Value  => Unsigned_32
                        (Engine.Buffer(Stream_Element_Offset((I * 4) - 3))), 
                      Amount => 24)
              
           + Shift_Left(Value  => Unsigned_32
                          (Engine.Buffer(Stream_Element_Offset((I * 4) - 2))),
                        Amount => 16)
           
           + Shift_Left(Value  => Unsigned_32
                          (Engine.Buffer(Stream_Element_Offset((I * 4) - 1))),
                        Amount => 8)
           
           + Unsigned_32(Engine.Buffer(Stream_Element_Offset(I * 4)));
           
      end loop;
      
      -- Create the values for the rest of Word_Sequence
      for I in 17 .. 64 loop
         
         S0 := Rotate_Right (Value => Word_Sequence(I - 15), Amount =>  7) xor
               Rotate_Right (Value => Word_Sequence(I - 15), Amount => 18) xor
               Shift_Right (Value => Word_Sequence(I - 15), Amount =>  3);
           
         S1 := Rotate_Right (Value => Word_Sequence(I -  2), Amount => 17) xor
               Rotate_Right (Value => Word_Sequence(I -  2), Amount => 19) xor
               Shift_Right (Value => Word_Sequence(I -  2), Amount => 10);
         
         Word_Sequence(I) := Word_Sequence(I - 16) + S0 + 
                             Word_Sequence(I -  7) + S1;
           
      end loop;
      
      A := Engine.H0;
      B := Engine.H1;
      C := Engine.H2;
      D := Engine.H3;
      E := Engine.H4;
      F := Engine.H5;
      G := Engine.H6;
      H := Engine.H7;
      
         
      for I in 1 .. 64 loop
         
         S1 := Rotate_Right(Value => E, Amount =>  6) xor 
               Rotate_Right(Value => E, Amount => 11) xor
               Rotate_Right(Value => E, Amount => 25);
         
         Ch := (E and F) xor ( (not E) and G );
         
         Temp_1 := H + S1 + Ch + K(I) + Word_Sequence(I);
         
         S0 := Rotate_Right(Value => A, Amount =>  2) xor 
               Rotate_Right(Value => A, Amount => 13) xor
               Rotate_Right(Value => A, Amount => 22);
         
         Maj := (A and B) xor (A and C) xor (B and C);
         
         Temp_2 := S0 + Maj;
         
         H := G;
         G := F;
         F := E;
         E := D + Temp_1;
         D := C;
         C := B;
         B := A;
         A := Temp_1 + Temp_2;
         
      end loop;         
      
      Engine.H0 := Engine.H0 + A;
      Engine.H1 := Engine.H1 + B;
      Engine.H2 := Engine.H2 + C;
      Engine.H3 := Engine.H3 + D;
      Engine.H4 := Engine.H4 + E;
      Engine.H5 := Engine.H5 + F;
      Engine.H6 := Engine.H6 + G;
      Engine.H7 := Engine.H7 + H;

      Engine.Last_Element_Index := 0;
           
   end Digest_Chunk;
        
   ---------
   -- "<" --
   ---------
   
   function "<" (Left, Right: SHA224_Hash) return Boolean is
   begin
      
      -- Even though our numbers are split into arrays of Unsigned_32,
      -- comparison operators can work on each section individually,
      -- as the lower indices have more significance (big endian)
      
      for I in Message_Digest'Range loop
         
         if Left.Digest(I) < Right.Digest(I) then
            return True;
            
         elsif Left.Digest(I) > Right.Digest(I) then
            return False;
            
         end if;
      end loop;
      
      -- The only way we get here is when Left = Right
      return False;
   end "<";
   
   
   ---------
   -- ">" --
   ---------
   
   function ">" (Left, Right: SHA224_Hash) return Boolean is
   begin
      
      -- Even though our numbers are split into arrays of Unsigned_32,
      -- comparison operators can work on each section individually,
      -- as the lower indices have more significance (big endian)
      
      for I in Message_Digest'Range loop
         
         if Left.Digest(I) > Right.Digest(I) then
            return True;
            
         elsif Left.Digest(I) < Right.Digest(I) then
            return False;
            
         end if;
                           
      end loop;
      
      -- The only way we get here is when Left = Right
      return False;
   end ">";
   
   
   ---------
   -- "=" --
   ---------
   
   function "=" (Left, Right: SHA224_Hash) return Boolean is
   begin
      
      for I in Message_Digest'Range loop
         
         if Left.Digest(I) /= Right.Digest(I) then
            return False;
         end if;
         
      end loop;
      
      return True;
      
   end "=";
   
   ------------
   -- Binary --
   ------------
   
   function Binary (Value: SHA224_Hash) return Hash_Binary_Value is
      I: Positive;
      Register: Unsigned_32;
   begin
      -- SHA 224 simply omits H7
      
      return Output: Hash_Binary_Value (1 .. SHA224_Hash_Bytes) do
         I := Output'First;
         
         for CI in reverse Value.Digest'First .. Value.Digest'Last - 1 loop
            Register := Value.Digest(CI);
            
            for J in 1 .. 4 loop -- Four bytes per digest chunk
               Output(I) := Unsigned_8 (Register and 16#FF#);
               Register := Shift_Right (Register, 8);
               I := I + 1;
            end loop;
         end loop;
      end return;
         
   end Binary;
   
   -----------
   -- Write --
   -----------
   
   procedure Write  (Stream : in out SHA224_Engine;
                     Item   : in     Stream_Element_Array)
   is
      Last_In: Stream_Element_Offset;
      
   begin
      
      -- Check for a null range of Item and discard
      if Item'Length = 0 then
         return;
      end if;
      
      Last_In := Item'First - 1;
      
      -- Finally, we can go ahead and add the message length to the Engine now,
      -- since there are early-ending code-paths below, and so we can avoid
      -- duplicating code. The only way this can really go wrong is if the
      -- entire message is larger than the Message_Size, which SHA224 limits to a
      -- 64-bit signed integer. Therefore a message of 16 exabytes will cause
      -- an invalid hash, due to a wrap-around of the Message_Size.
      -- That's a risk we are willing to take.
      Stream.Message_Length 
           := Stream.Message_Length + (Stream_Element'Size * Item'Length);
      
      -- Our buffer has a size of 512 (the size of a "chunk" of processing for
      -- the SHA-2 algorithm).
      -- Our write should be automated so that as soon as that buffer is full
      -- (no matter how much of the Item array is written already), the chunk is
      -- processed 
      
      -- In order to take advantage of any processor vector copy features, we
      -- will explicitly copy Item in chunks that are either the full size of
      -- Item, 64 elements, or the remaining space in the hash Buffer, whichever
      -- is largest
      
      while Last_In < Item'Last loop
         declare
            subtype Buffer_Slice is Stream_Element_Offset range
              Stream.Last_Element_Index + 1 .. Stream.Buffer'Last;
            
            Buffer_Slice_Length: Stream_Element_Offset 
              := Buffer_Slice'Last - Buffer_Slice'First + 1;
            
            subtype Item_Slice is Stream_Element_Offset range
              Last_In + 1 .. Item'Last;
            
            Item_Slice_Length: Stream_Element_Offset
              := Item_Slice'Last - Item_Slice'First + 1;

         begin
            if Buffer_Slice_Length > Item_Slice_Length then
               -- We can fit the rest in the buffer, with space left-over
               declare
                  -- Set-up a specific slice in the Buffer which can accommodate
                  -- the remaining elements of Item
                  subtype Target_Slice is Stream_Element_Offset range
                    Buffer_Slice'First .. Buffer_Slice'First + 
                    (Item_Slice'Last - Item_Slice'First);
               begin
                  -- Here is the block copy
                  Stream.Buffer(Target_Slice'Range):= Item (Item_Slice'Range);
                  Stream.Last_Element_Index := Target_Slice'Last;
               end;
               
               -- That's it, we've absorbed the entire Item, no need to waste
               -- time updating Last_In.
               return;
               
            else
               -- This means the buffer space is either equal to or smaller than
               -- the remaining Item elements, this means we need process the 
               -- chunk (digest the buffer) no matter what
               
               -- First step is to copy in as much of the remaining Item
               -- elements as possible
               
               declare
                  subtype Source_Slice is Stream_Element_Offset range
                    Item_Slice'First 
                    .. Item_Slice'First + Buffer_Slice_Length - 1;
               begin
                  -- Block copy
                  Stream.Buffer(Buffer_Slice'Range) 
                    := Item (Source_Slice'Range);
                  Stream.Last_Element_Index := Buffer_Slice'Last;
                  Last_In := Source_Slice'Last;
               end;
               
               -- Now we digest the currently full buffer
               Digest_Chunk (Stream); 
               
            end if;
         end; 
      end loop;
      
   end Write;
   
   -----------
   -- Reset --
   -----------
   
   procedure Reset (Engine : in out SHA224_Engine) is
   begin
      
      Engine.Last_Element_Index  := 0;     
      Engine.Message_Length      := 0;
      
      Engine.H0                  := H0_Initial;
      Engine.H1                  := H1_Initial;
      Engine.H2                  := H2_Initial;
      Engine.H3                  := H3_Initial;
      Engine.H4                  := H4_Initial;
      Engine.H5                  := H5_Initial;
      Engine.H6                  := H6_Initial;
      Engine.H7                  := H7_Initial;
            
   end Reset;
   
   ------------
   -- Digest --
   ------------
   
   function Digest (Engine : in out SHA224_Engine)
                   return Hash'Class
   is
      
      -- The core of the message digest algorithm occurs in-line with stream
      -- writes through the Digest_Chunk procedure. The role of this function
      -- is to append the message size and padding, and then execute the final
      -- Digest_Chunk before returning the digest.
      
      -- We work with the data in the Buffer in chunks of 512 bits
      -- Once we get to the last section that is < 512 bits, we append
      -- the 64 bit length and padding 0's
      
      -- In most cases, this 64 bit + padding will all be in the last section
      -- of the buffer 
      -- We pad up until the 448th bit (56th byte) and then add the length
      
      -- However, we must also keep in mind the fringe case where the data ends
      -- at bit position 448 or later (byte 56 or later)
      -- In that case, the approach to take is to pad the final chunk, then add
      -- a new one that is ONLY padding and the 64 bit length
            
      Message_Length_Spliced : Stream_Element_Array(1 .. 8);
      
      Special_Case_Index     : Stream_Element_Offset := 0;
      
   begin
      
      -- Splitting the 64-bit message length into array of bytes
      for I in 1 .. 8 loop
         
         Message_Length_Spliced(Stream_Element_Offset(I)) := 
           Stream_Element
           (Unsigned_8(Shift_Right(Value  => Engine.Message_Length,
                                   Amount => 8 * (8 - I)) and 16#ff#));
      end loop;
      
            
      -- This is a while loop but we use an exit condition to make sure that it
      -- executes at least once (for the case of empty hash message)
      loop
         
         if Special_Case_Index /= 0 then
            
            if Special_Case_Index = 1 then
               Engine.Buffer(1) := 2#10000000#;
               
            else
               Engine.Buffer(1) := 2#00000000#;
               
            end if;
            
            Engine.Buffer(2 .. 56) := (others => 2#00000000#);
            
            Engine.Buffer(57 .. 64) := Message_Length_Spliced;
            
            Special_Case_Index := 0;
            
         -- If there is less than 512 bits left in the Buffer
         else
            

            -- The case where one chunk will hold Buffer + padding + 64 bits
            if Engine.Last_Element_Index < 56 then
               
               -- Add the correct amount of padding
               
               Engine.Buffer(Engine.Last_Element_Index + 1) := 2#10000000#;
               
               Engine.Buffer(Engine.Last_Element_Index + 2 .. 56) :=
                 (others => 2#00000000#);
                              
               -- Finish it off with Message_Length
               Engine.Buffer(57 .. 64) := Message_Length_Spliced;
               
               
            -- The case where one chunk will hold Buffer + padding, and
            -- another will hold padding + 64 bit message length   
            else
               
               -- Put what we can of the padding in the current chunk
               Engine.Buffer(Engine.Last_Element_Index + 1) := 2#10000000#;
               
               Engine.Buffer(Engine.Last_Element_Index + 2 .. 64) :=
                 (others => 2#00000000#);
                              
               -- Save where we left off in the padding for the next chunk
               Special_Case_Index := 65 - Engine.Last_Element_Index;
               
            end if;
            
         end if;
         
         
         Digest_Chunk (Engine);
         
         exit when Engine.Last_Element_Index = 0 and Special_Case_Index = 0;
      
      end loop;
      
      
      return Result: SHA224_Hash do
        Result.Digest := (1 => Engine.H0,
                          2 => Engine.H1,
                          3 => Engine.H2,
                          4 => Engine.H3,
                          5 => Engine.H4,
                          6 => Engine.H5,
                          7 => Engine.H6,
                          8 => Engine.H7);
      
        Engine.Reset;
      end return;
      
   end Digest;
   
end Modular_Hashing.SHA224;
