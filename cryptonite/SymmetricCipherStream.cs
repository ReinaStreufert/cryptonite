using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace cryptonite
{
    public abstract class SymmetricCipherStream : Stream
    {
        public byte[] Key { get; set; } = null;
        public byte[] IV { get; set; } = null;
        public Stream UnderlyingStream { get; set; } = null;
        public EncryptionMode Mode { get; set; } = EncryptionMode.Encrypt;
        public Direction Direction { get; set; } = Direction.Read;
        public abstract int[] AvailableKeySizes { get; }
    }
    public enum EncryptionMode : byte
    {
        Encrypt = 0,
        Decrypt = 1
    }
    public enum Direction : byte
    {
        Read = 0,
        Write = 1
    }
}
