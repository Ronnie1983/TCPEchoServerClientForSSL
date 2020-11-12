using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Schema;

namespace EchoClient
{
    internal class Client
    {
        private int PORT;

        public Client(int port)
        {
            this.PORT = port;
        }

        public void Start()
        {

            TcpClient connectionSocket = new TcpClient("192.168.104.136", PORT);
            Stream uns = connectionSocket.GetStream();
            bool leaveInnerStreamOpen = false;
            SslStream sslStream = new SslStream(uns, leaveInnerStreamOpen, new RemoteCertificateValidationCallback(ValidateServerCertificate),null);
            try
            {
                sslStream.AuthenticateAsClient("FakeServerName");
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                connectionSocket.Close();
                return;
            }

            using (StreamReader sr = new StreamReader(sslStream))
            using (StreamWriter sw = new StreamWriter(sslStream))
            {
                Console.WriteLine("Client have connected");
                sw.AutoFlush = true; // enable automatic flushing

                // three different clients - run only one of them

                Client1(sr, sw);        // read 1 line from console and send to server
                //Client2(sr, sw);      // read 5 lines and send to server
                //Client3(sr, sw);      // send 100 messages to server

                Console.WriteLine("Client finished");
            }
        }

        private void Client3(StreamReader sr, StreamWriter sw)
        {
            for (int i = 0; i < 100; i++)
            {
                string message = "Michael " + i;
                sw.WriteLine(message);
                string serverAnswer = sr.ReadLine();
                Console.WriteLine("Server: " + serverAnswer);
            }
            
        }

        private void Client2(StreamReader sr, StreamWriter sw)
        {
            
            for (int i = 0; i < 5; i++)
            {
                Console.WriteLine("Type a line");
                string message = Console.ReadLine();
                sw.WriteLine(message);
                string serverAnswer = sr.ReadLine();
                Console.WriteLine("Server: " + serverAnswer);
            }
            
        }

        private void Client1(StreamReader sr, StreamWriter sw)
        {
            // send
            Console.WriteLine("Type a line");
            string message = Console.ReadLine();
            sw.WriteLine(message);

            // receive
            string serverAnswer = sr.ReadLine();
            Console.WriteLine("Server: " + serverAnswer);
            
        }

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
    }
}