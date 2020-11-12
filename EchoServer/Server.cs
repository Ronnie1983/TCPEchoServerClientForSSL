using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace EchoServer
{
    internal class Server
    {
        private int PORT;

        public Server(int port)
        {
            this.PORT = port;
        }

        public void Start()
        {
            string serverCertificateFile = "C:/Users/DKROJEN/certificates/ServerSSL.pfx";
            bool clientCertificateRequired = false;
            bool checkCertificateRevocation = true;
            SslProtocols enabledSSLProtocols = SslProtocols.Tls;
            X509Certificate serverCertificate = new X509Certificate2(serverCertificateFile, "passW0rd");

            TcpListener serverSocket = new TcpListener(IPAddress.Any, PORT);
            serverSocket.Start();
            Console.WriteLine("Server started");

            TcpClient connectionSocket = serverSocket.AcceptTcpClient();
            Stream uns = connectionSocket.GetStream();
            bool leaveInnerStreamOpen = false;
            SslStream sslStream = new SslStream(uns, leaveInnerStreamOpen,new RemoteCertificateValidationCallback(ValidateServerCertificate),new LocalCertificateSelectionCallback(SelectLocalCertificate));
            sslStream.AuthenticateAsServer(serverCertificate, clientCertificateRequired, enabledSSLProtocols, checkCertificateRevocation);
            using (StreamReader sr = new StreamReader(sslStream))
            using (StreamWriter sw = new StreamWriter(sslStream))
            {
                Console.WriteLine("Server activated");
                sw.AutoFlush = true; // enable automatic flushing

                string message = sr.ReadLine(); // read string from client
                string answer = "";
                while (!string.IsNullOrEmpty(message))
                {

                    Console.WriteLine("Client: " + message);
                    answer = message.ToUpper(); // convert string to upper case
                    sw.WriteLine(answer); // send back upper case string
                    message = sr.ReadLine();

                }
            }
        }
        public static X509Certificate SelectLocalCertificate(
            object sender,
            string targetHost,
            X509CertificateCollection localCertificates,
            X509Certificate remoteCertificate,
            string[] acceptableIssuers)
        {
            Console.WriteLine("Client is selecting a local certificate.");
            if (acceptableIssuers != null &&
                acceptableIssuers.Length > 0 &&
                localCertificates != null &&
                localCertificates.Count > 0)
            {
                // Use the first certificate that is from an acceptable issuer.
                foreach (X509Certificate certificate in localCertificates)
                {
                    string issuer = certificate.Issuer;
                    if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                        return certificate;
                }
            }
            if (localCertificates != null &&
                localCertificates.Count > 0)
                return localCertificates[0];

            return null;
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