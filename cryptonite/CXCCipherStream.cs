using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace cryptonite
{
    public class CXCCipherStream : SymmetricCipherStream
    {
        private byte shortTermAccumulation = 0;
        private byte[] longTermAccumulation;
        private byte[] nextLongTermAccumulation;
        private int keyCycleLength = 0;
        private int cycleProgress = 0;
        private bool[] usedCycleBytes;

        public override int[] AvailableKeySizes
        {
            get
            {
                return new int[] { -1 };
            }
        }

        public void Initialize()
        {
            if (Key == null || IV == null || Key.Length == 0 || IV.Length == 0)
            {
                throw new ArgumentNullException("Key and IV must be set with a non-zero length");
            }
            keyCycleLength = Key.Length;
            if (IV.Length != Key.Length)
            {
                throw new ArgumentNullException("Key and IV must match in length");
            }
            if (UnderlyingStream == null)
            {
                throw new ArgumentNullException("UnderlyingStream must be set");
            }

            longTermAccumulation = new byte[keyCycleLength];
            nextLongTermAccumulation = new byte[keyCycleLength];
            usedCycleBytes = new bool[keyCycleLength];
            for (int i = 0; i < usedCycleBytes.Length; i++)
            {
                usedCycleBytes[i] = false;
            }

            for (int i = 0; i < keyCycleLength; i++)
            {
                encryptByte(IV[i]); // THE OUTPUT OF THIS FUNCTION ON THIS LINE SHOULD NEVER BE INCLUDED IN ANY CIPHER TEXT EVEN THOUGH IT SEEMS LIKE IT MAY BE "ENCRYPTED", THE SERIES OF BYTES PRODUCED HERE MIGHT AS WELL BE THE KEY BECAUSE THE KEY CAN BE EASILY DERIVED FROM IT
            }
        }
        public override bool CanRead
        {
            get
            {
                return UnderlyingStream.CanRead;
            }
        }
        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }
        public override bool CanWrite
        {
            get
            {
                return UnderlyingStream.CanWrite;
            }
        }
        public override long Length
        {
            get
            {
                return 0;
            }
        }
        public override long Position
        {
            get
            {
                throw new InvalidOperationException();
            }
            set
            {
                throw new InvalidOperationException();
            }
        }
        public override void Flush()
        {
            return;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new InvalidOperationException();
        }
        public override void SetLength(long value)
        {
            throw new InvalidOperationException();
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (Direction == Direction.Write)
            {
                throw new InvalidOperationException("Incorrect direction");
            }
            byte[] underlying = new byte[count];
            int read = UnderlyingStream.Read(underlying, 0, count);
            for (int i = 0; i < read; i++)
            {
                if (Mode == EncryptionMode.Encrypt)
                {
                    buffer[i + offset] = encryptByte(underlying[i]);
                }
                else
                {
                    buffer[i + offset] = decryptByte(underlying[i]);
                }
            }
            return read;
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Direction == Direction.Read)
            {
                throw new InvalidOperationException("Incorrect direction");
            }
            byte[] underlying = new byte[count];
            for (int i = 0; i < count; i++)
            {
                if (Mode == EncryptionMode.Encrypt)
                {
                    underlying[i] = encryptByte(buffer[i + offset]);
                }
                else
                {
                    underlying[i] = decryptByte(buffer[i + offset]);
                }
            }
            UnderlyingStream.Write(underlying, 0, count);
        }

        private byte encryptByte(byte clearByte)
        {
            if (cycleProgress >= keyCycleLength)
            {
                cycleProgress = 0;
                for (int i = 0; i < usedCycleBytes.Length; i++)
                {
                    usedCycleBytes[i] = false;
                }
                for (int i = 0; i < nextLongTermAccumulation.Length; i++)
                {
                    longTermAccumulation[i] = nextLongTermAccumulation[i];
                }
            }

            int usedCyclePosition = shortTermAccumulation % keyCycleLength;
            while (usedCycleBytes[usedCyclePosition])
            {
                usedCyclePosition++;
                if (usedCyclePosition >= keyCycleLength)
                {
                    usedCyclePosition = 0;
                }
            }
            //Console.WriteLine(usedCyclePosition);
            usedCycleBytes[usedCyclePosition] = true;
            byte cypherByte = (byte)(clearByte ^ shortTermAccumulation ^ longTermAccumulation[usedCyclePosition] ^ Key[usedCyclePosition]);
            nextLongTermAccumulation[cycleProgress] = (byte)(clearByte ^ Key[usedCyclePosition]);

            shortTermAccumulation ^= (byte)(clearByte ^ Key[usedCyclePosition]);
            cycleProgress++;

            return cypherByte;
        }
        private byte decryptByte(byte cipherByte)
        {
            if (cycleProgress >= keyCycleLength)
            {
                cycleProgress = 0;
                for (int i = 0; i < usedCycleBytes.Length; i++)
                {
                    usedCycleBytes[i] = false;
                }
                for (int i = 0; i < nextLongTermAccumulation.Length; i++)
                {
                    longTermAccumulation[i] = nextLongTermAccumulation[i];
                }
            }

            int usedCyclePosition = shortTermAccumulation % keyCycleLength;
            while (usedCycleBytes[usedCyclePosition])
            {
                usedCyclePosition++;
                if (usedCyclePosition >= keyCycleLength)
                {
                    usedCyclePosition = 0;
                }
            }
            usedCycleBytes[usedCyclePosition] = true;
            byte clearByte = (byte)(cipherByte ^ shortTermAccumulation ^ longTermAccumulation[usedCyclePosition] ^ Key[usedCyclePosition]);
            nextLongTermAccumulation[cycleProgress] = (byte)(clearByte ^ Key[usedCyclePosition]);

            shortTermAccumulation ^= (byte)(clearByte ^ Key[usedCyclePosition]);
            cycleProgress++;

            return clearByte;
        }

        public static byte[] TransformBuffer(byte[] Input, byte[] Key, byte[] IV, EncryptionMode Mode)
        {
            byte[] output = new byte[Input.Length];
            using (CXCCipherStream cxc = new CXCCipherStream())
            {
                cxc.Key = Key;
                cxc.IV = IV;
                cxc.Mode = Mode;
                using (MemoryStream ms = new MemoryStream(Input))
                {
                    cxc.UnderlyingStream = ms;
                    cxc.Initialize();
                    cxc.Read(output, 0, Input.Length);
                }
            }
            return output;
        }
    }
}
