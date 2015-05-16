using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;

namespace SHA256_libraries
{
    public class Sha256
    {
        private static readonly UInt32[] KUints = {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };

        private static UInt32 Rotl(UInt32 x, byte n)
        {
            Debug.Assert(n < 32);
            return (x << n) | (x >> (32 - n));
        }

        private static UInt32 Rotr(UInt32 x, byte n)
        {
            Debug.Assert(n < 32);
            return (x >> n) | (x << (32 - n));
        }

        private static UInt32 Ch(UInt32 x, UInt32 y, UInt32 z)
        {
            return (x & y) ^ ((~x) & z);
        }

        private static UInt32 Major(UInt32 x, UInt32 y, UInt32 z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        private static UInt32 Sigma0(UInt32 x)
        {
            return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
        }

        private static UInt32 Sigma1(UInt32 x)
        {
            return Rotr(x, 17) ^ Rotr(x, 19) ^ (x >> 10);
        }

        private static UInt32 sigma0(UInt32 x)
        {
            return Rotr(x, 7) ^ Rotr(x, 18) ^ (x >> 3);
        }

        private static UInt32 sigma1(UInt32 x)
        {
            return Rotr(x, 17) ^ Rotr(x, 19) ^ (x >> 10);
        }

        private UInt32[] _h = new UInt32[8]
        {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };

        private readonly byte[] _pendingBlock = new byte[64];
        private uint _pendingBlockOff = 0;
        private readonly UInt32[] _uintBuffer = new UInt32[16];

        private UInt64 _bitsProcessed = 0;

        private bool _closed = false;

        private void ProcessBlock(UInt32[] mUints)
        {
            Debug.Assert(mUints.Length == 16);

            // BASIS: Prepare message for function W[t]:
            var w = new UInt32[64];
            for (var t = 0; t < 16; ++t)
            {
                w[t] = mUints[t];
                
            }

            for (var t = 16; t < 64; ++t)
            {
                w[t] = sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16];
            }

            // INITIALIZE: Prepare eight working variables with hash values of (i - 1):
            UInt32 a = _h[0],
                b = _h[1],
                c = _h[2],
                d = _h[3],
                e = _h[4],
                f = _h[5],
                g = _h[6],
                h = _h[7];

            // LOOP: For t = 0 to 63:
            for (int t = 0; t < 64; ++t)
            {
                UInt32 t1 = h + Sigma1(e) + Ch(e, f, g) + KUints[t] + w[t];
                UInt32 t2 = Sigma0(a) + Major(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            // SOLVE: Solve for hash value h:
            _h[0] = a + _h[0];
            _h[1] = b + _h[1];
            _h[2] = c + _h[2];
            _h[3] = d + _h[3];
            _h[4] = e + _h[4];
            _h[5] = f + _h[5];
            _h[6] = g + _h[6];
            _h[7] = h + _h[7];

        }

        private void AddData(byte[] data, uint offset, uint len)
        {
            if (_closed)
                throw new InvalidOperationException("Adding data to a 'closed' hasher.");

            if (len == 0)
                return;

            _bitsProcessed += len*8;

            while (len > 0)
            {
                uint amountToCopy;

                if (len < 64)
                {
                    if (_pendingBlockOff + len > 64)
                        amountToCopy = 64 - _pendingBlockOff;
                    else
                    {
                        amountToCopy = len;
                    }
                }
                else
                {
                    amountToCopy = 64 - _pendingBlockOff;
                }

                Array.Copy(data, offset, _pendingBlock, _pendingBlockOff, amountToCopy);
                len -= amountToCopy;
                offset += amountToCopy;
                _pendingBlockOff += amountToCopy;

                if (_pendingBlockOff == 64)
                {
                    ToUintArray(_pendingBlock, _uintBuffer);
                    ProcessBlock(_uintBuffer);
                    _pendingBlockOff = 0;
                }
            }
        }

        private ReadOnlyCollection<byte> GetHash()
        {
            return toByteArray(GetHashUInt32());
        }

        private ReadOnlyCollection<UInt32> GetHashUInt32()
        {
            if (!_closed)
            {
                UInt64 sizeTemp = _bitsProcessed;

                AddData(new byte[1] {0x80}, 0, 1);

                var availableSpace = 64 - _pendingBlockOff;

                if (availableSpace < 8)
                    availableSpace
                        += 64;

                // init
                var paddingBytes = new byte[availableSpace];
                // update uint64 length
                for (uint i = 1; i <= 8; ++i)
                {
                    paddingBytes[paddingBytes.Length - i] = (byte) sizeTemp;
                    sizeTemp >>= 8;
                }

                AddData(paddingBytes, 0u, (uint) paddingBytes.Length);

                Debug.Assert(_pendingBlockOff == 0);
                _closed = true;
            }

            return Array.AsReadOnly(_h);
        }

        private static void ToUintArray(byte[] src, UInt32[] destUints)
        {
            for (uint i = 0, j = 0; i < destUints.Length; ++i, j += 4)
            {
                destUints[i] = ((UInt32)src[j + 0] << 24) | ((UInt32)src[j + 1] << 16) | ((UInt32)src[j + 2] << 8) | ((UInt32)src[j + 3]);
            }
        }

        private static ReadOnlyCollection<byte> toByteArray(ReadOnlyCollection<UInt32> src)
        {
            var destBytes = new byte[src.Count*4];
            var position = 0;

            for (var i = 0; i < src.Count; ++i)
            {
                destBytes[position++] = (byte) (i >> 24);
                destBytes[position++] = (byte)(i >> 16);
                destBytes[position++] = (byte)(i >> 8);
                destBytes[position++] = (byte)(i);

            }

            return Array.AsReadOnly(destBytes);
        }

        public static ReadOnlyCollection<byte> HashFile(Stream fs)
        {
            var sha = new Sha256();
            var buf = new byte[8196];

            uint bytesRead;
            do
            {
                bytesRead = (uint)fs.Read(buf, 0, buf.Length);
                if (bytesRead == 0)
                    break;

                sha.AddData(buf, 0, bytesRead);
            }
            while (bytesRead == 8196);

            return sha.GetHash();
        }
    }
}
