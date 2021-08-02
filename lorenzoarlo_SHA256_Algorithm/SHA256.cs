using System;
using System.IO;

namespace lorenzoarlo_SHA256_Algorithm
{
    class SHA256
    {
        //----- STATIC FIELDS -----

        static readonly uint[] HASH_CONSTANTS = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        };

        static readonly uint[] ROUND_CONSTANTS =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        //----- CONSTANTS -----

        public const int BITS_FOR_STRING_LENGTH = 64;

        public const int N_WORDS = 64;

        public const int CHUNKS_LENGTH = 512;

        public const int WORDS_LENGTH = 32;

        const string TEST_PATH = @"SHA256_Test.txt";

        //----- STATIC METHODS ----

        public static string String_To_SHA256(string message)
        {
            //-> Convert in binary

            BinaryNumber phrase = new BinaryNumber(message, false);

            uint initialLength = (uint)phrase.Length;

            //-> Append '1' at the end

            phrase.InsertAfter("1");

            //-> Fix the phrase

            phrase.Fix();

            //-> Append initial phrase length

            phrase.InsertAfter(BinaryNumber.BinaryRepresentation(initialLength, BITS_FOR_STRING_LENGTH));

            //-> Get chunks

            BinaryNumber[] chunks = phrase.SubdiveInChunks();

            //-> Message schedule

            BinaryNumber[] currentH = new BinaryNumber[HASH_CONSTANTS.Length];

            for (int i = 0; i < HASH_CONSTANTS.Length; i++)
            {
                currentH[i] = new BinaryNumber(HASH_CONSTANTS[i], WORDS_LENGTH);
            }

            foreach (BinaryNumber chunk in chunks)
            {
                BinaryNumber[] words = new BinaryNumber[N_WORDS];

                //-> Create words from 0 to 15

                for (int i = 0; i < 16; i++)
                {
                    words[i] = new BinaryNumber(chunk.Value.Substring(i * WORDS_LENGTH, WORDS_LENGTH));
                }

                //-> Create words from 16 to 63

                for (int i = 16; i < N_WORDS; i++)
                {
                    BinaryNumber S0 = BinaryNumber.RightRotate(words[i - 15], 7) ^ BinaryNumber.RightRotate(words[i - 15], 18) ^ BinaryNumber.RightShift(words[i - 15], 3);

                    BinaryNumber S1 = BinaryNumber.RightRotate(words[i - 2], 17) ^ BinaryNumber.RightRotate(words[i - 2], 19) ^ BinaryNumber.RightShift(words[i - 2], 10);

                    words[i] = words[i - 16] + S0 + words[i - 7] + S1;
                }

                //-> Initialize working variables
                BinaryNumber[] workingVariables = new BinaryNumber[HASH_CONSTANTS.Length];

                for (int i = 0; i < HASH_CONSTANTS.Length; i++)
                {
                    workingVariables[i] = new BinaryNumber(currentH[i].Value);
                }

                //-> Compression loop

                for (int i = 0; i < 64; i++)
                {
                    BinaryNumber S1 = BinaryNumber.RightRotate(workingVariables[4], 6) ^ BinaryNumber.RightRotate(workingVariables[4], 11) ^ BinaryNumber.RightRotate(workingVariables[4], 25);
                    BinaryNumber ch = (workingVariables[4] & workingVariables[5]) ^ (~workingVariables[4] & workingVariables[6]);
                    BinaryNumber tmp1 = workingVariables[7] + S1 + ch + ROUND_CONSTANTS[i] + words[i];
                    BinaryNumber S0 = BinaryNumber.RightRotate(workingVariables[0], 2) ^ BinaryNumber.RightRotate(workingVariables[0], 13) ^ BinaryNumber.RightRotate(workingVariables[0], 22);
                    BinaryNumber maj = (workingVariables[0] & workingVariables[1]) ^ (workingVariables[0] & workingVariables[2]) ^ (workingVariables[1] & workingVariables[2]);
                    BinaryNumber tmp2 = S0 + maj;

                    workingVariables[7] = workingVariables[6].ClonedObject;
                    workingVariables[6] = workingVariables[5].ClonedObject;
                    workingVariables[5] = workingVariables[4].ClonedObject;
                    workingVariables[4] = workingVariables[3] + tmp1;
                    workingVariables[3] = workingVariables[2].ClonedObject;
                    workingVariables[2] = workingVariables[1].ClonedObject;
                    workingVariables[1] = workingVariables[0].ClonedObject;
                    workingVariables[0] = tmp1 + tmp2;
                }

                for (int i = 0; i < HASH_CONSTANTS.Length; i++)
                {
                    currentH[i] = currentH[i] + workingVariables[i];
                }
            }

            //-> Return the coded output

            string output = "";
            for (int i = 0; i < HASH_CONSTANTS.Length; i++)
            {
                output += currentH[i].HexRepresentation;
            }
            return output;
        }

        public static void Test()
        {
            string[,] test = GetTest();

            for (int i = 0; i < test.GetLength(0); i++)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                string expectedInput = test[i, 0];
                Console.WriteLine($"Input -> {expectedInput }");


                Console.ForegroundColor = ConsoleColor.Magenta;
                string expectedOutput = test[i, 1];
                Console.WriteLine($"Expected output -> {expectedOutput}");

                Console.ForegroundColor = ConsoleColor.DarkYellow;
                string output = SHA256.String_To_SHA256(expectedInput);
                Console.WriteLine($"Real output -> {output}");

                bool result = output == expectedOutput;

                Console.ForegroundColor = (result) ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine($"Test result -> {result}");
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"Press any key to continue -> ");
            Console.ReadKey();
            Console.WriteLine();
        }

        static string[,] GetTest()
        {
            StreamReader r = new StreamReader(TEST_PATH);

            r.ReadLine();

            string[] lines = r.ReadToEnd().Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

            string[,] test = new string[lines.Length, 2];

            for (int i = 0; i < lines.Length; i++)
            {
                string[] tmp = lines[i].Split('|');
                test[i, 0] = tmp[0];
                test[i, 1] = tmp[1];
            }


            r.Close();

            return test;
        }

    }
}
