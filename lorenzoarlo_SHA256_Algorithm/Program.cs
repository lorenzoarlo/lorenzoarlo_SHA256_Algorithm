using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace lorenzoarlo_SHA256_Algorithm
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Insert a message: ");
            string message = Console.ReadLine();

            Console.WriteLine($"Inserted message -> {message}");

            string output = SHA256.String_To_SHA256(message);

            Console.WriteLine($"Hash -> {output}");

            Console.Write("Press any key to exit -> ");
            Console.ReadKey();
        }
    }
}
