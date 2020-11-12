using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EchoServer
{
    public class Program
    {
        private const int PORT = 7777;

        static void Main(string[] args)
        {
            

            Server server = new Server(PORT);
            server.Start();

            Console.ReadLine();
        }
    }
}
