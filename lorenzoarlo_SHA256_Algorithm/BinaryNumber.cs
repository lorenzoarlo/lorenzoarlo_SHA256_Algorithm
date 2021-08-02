using System;
using System.Text;

namespace lorenzoarlo_SHA256_Algorithm
{
    class BinaryNumber
    {
        //----- CONSTANTS -----

        //----- PROPERTIES -----

        public string Value { get; private set; }

        public int Length { get { return this.Value.Length; } }

        public uint UIntValue { get { return Convert.ToUInt32(this.Value, 2); } }

        public BinaryNumber ClonedObject { get { return new BinaryNumber(this.Value); } }

        public string HexRepresentation { get { return this.UIntValue.ToString("X").PadLeft(this.Length / 4, '0'); } }

        //----- CONSTRUCTOR -----

        public BinaryNumber(uint value, int length = 0)
        {
            this.Value = BinaryNumber.BinaryRepresentation(value, length);
        }

        public BinaryNumber(string s, bool alreadyBinary = true)
        {
            this.Value = (alreadyBinary) ? s : BinaryNumber.BinaryRepresentation(s);
        }

        //----- METHODS -----

        public void PadLeft(int totalWidth, char paddingChar)
        {
            this.Value = this.Value.PadLeft(totalWidth, paddingChar);
        }

        public void PadRight(int totalWidth, char paddingChar)
        {
            this.Value = this.Value.PadRight(totalWidth, paddingChar);
        }

        public void InsertBefore(string toInsert)
        {
            this.Value = toInsert + this.Value;
        }

        public void InsertAfter(string toInsert)
        {
            this.Value += toInsert;
        }

        public void Fix()
        {
            int nChunks = (int)Math.Ceiling((double)(this.Length + SHA256.BITS_FOR_STRING_LENGTH) / SHA256.CHUNKS_LENGTH);
            int finalLength = nChunks * SHA256.CHUNKS_LENGTH - SHA256.BITS_FOR_STRING_LENGTH;
            this.PadRight(finalLength, '0');
        }

        public BinaryNumber[] SubdiveInChunks()
        {
            int nChunks = this.Length / SHA256.CHUNKS_LENGTH;
            BinaryNumber[] chunks = new BinaryNumber[nChunks];

            for (int i = 0; i < nChunks; i++)
            {
                chunks[i] = new BinaryNumber(this.Value.Substring(i * SHA256.CHUNKS_LENGTH, SHA256.CHUNKS_LENGTH));
            }
            return chunks;
        }

        public void RightRotate(int times)
        {
            times = times % this.Length;
            string toRotate = this.Value.Substring(this.Length - times, times);
            string tmp = this.Value.Substring(0, this.Length - times);
            this.Value = toRotate + tmp;
        }

        public void LeftRotate(int times)
        {
            times = times % this.Length;
            string toRotate = this.Value.Substring(0, times);
            string tmp = this.Value.Substring(times, this.Length - times);
            this.Value = tmp + toRotate;
        }

        public void RightShift(int times)
        {
            this.Value = BinaryNumber.BinaryRepresentation(this.UIntValue >> times, this.Length);
        }

        public void LeftShift(int times)
        {
            this.Value = BinaryNumber.BinaryRepresentation(this.UIntValue << times, this.Length);
        }

        public override string ToString()
        {
            return this.Value;
        }

        //----- STATIC METHODS -----

        public static string BinaryRepresentation(string s)
        {
            string output = "";

            UTF8Encoding encode = (UTF8Encoding)UTF8Encoding.UTF8;
            byte[] stringBytes = encode.GetBytes(s);

            foreach (byte b in stringBytes)
            {
                output += BinaryNumber.BinaryRepresentation(b, 8);
            }
            return output;
        }

        public static string BinaryRepresentation(int value, int binaryLength = 0)
        {
            return Convert.ToString(value, 2).PadLeft(binaryLength, '0');
        }

        public static string BinaryRepresentation(uint value, int binaryLength = 0)
        {
            return Convert.ToString(value, 2).PadLeft(binaryLength, '0');
        }

        public static BinaryNumber RightRotate(BinaryNumber b, int times)
        {
            times = times % b.Length;
            string toRotate = b.Value.Substring(b.Length - times, times);
            string tmp = b.Value.Substring(0, b.Length - times);
            return new BinaryNumber(toRotate + tmp);
        }

        public static BinaryNumber LeftRotate(BinaryNumber b, int times)
        {
            times = times % b.Length;
            string toRotate = b.Value.Substring(0, times);
            string tmp = b.Value.Substring(times, b.Length - times);
            return new BinaryNumber(tmp + toRotate);
        }

        public static BinaryNumber RightShift(BinaryNumber b, int times)
        {
            return new BinaryNumber(b.UIntValue >> times, b.Length);
        }

        public static BinaryNumber LeftShift(BinaryNumber b, int times)
        {
            return new BinaryNumber(b.UIntValue << times, b.Length);
        }

        public static BinaryNumber operator +(BinaryNumber one, BinaryNumber two)
        {
            uint result = (one.UIntValue + two.UIntValue);
            BinaryNumber toReturn = new BinaryNumber(result, one.Length);
            return toReturn;
        }

        public static BinaryNumber operator +(BinaryNumber one, uint two)
        {
            uint result = (one.UIntValue + two);
            BinaryNumber toReturn = new BinaryNumber(result, one.Length);
            return toReturn;
        }

        public static BinaryNumber operator +(uint one, BinaryNumber two)
        {
            uint result = (one + two.UIntValue);
            BinaryNumber toReturn = new BinaryNumber(result, two.Length);
            return toReturn;
        }

        public static BinaryNumber operator &(BinaryNumber one, BinaryNumber two)
        {
            int l = (one.Length > two.Length) ? one.Length : two.Length;
            return new BinaryNumber(one.UIntValue & two.UIntValue, l);
        }

        public static BinaryNumber operator |(BinaryNumber one, BinaryNumber two)
        {
            int l = (one.Length > two.Length) ? one.Length : two.Length;
            return new BinaryNumber(one.UIntValue | two.UIntValue, l);
        }

        public static BinaryNumber operator ~(BinaryNumber one)
        {
            return new BinaryNumber(~one.UIntValue, one.Length);
        }

        public static BinaryNumber operator ^(BinaryNumber one, BinaryNumber two)
        {
            int l = (one.Length > two.Length) ? one.Length : two.Length;
            return new BinaryNumber(one.UIntValue ^ two.UIntValue, l);
        }
    }
}
