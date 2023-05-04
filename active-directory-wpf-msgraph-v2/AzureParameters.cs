using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO
{
    internal class AzureParameters
    {

        public string ClientId;
        public string TenantId;

        static AzureParameters BoehringerParameters()
        {
            var p = new AzureParameters();
            p.ClientId = "dce8f033-74b4-42c4-8c2a-cabfaeadfeb3";
            p.TenantId = "e1f8af86-ee95-4718-bd0d-375b37366c83";
            return p;
        }

        static AzureParameters FusionConsoleParameters()
        {
            var p = new AzureParameters();
            p.ClientId = "e2a5bd83-eb83-428b-8ad2-83f19b02f2de";
            p.TenantId = "4875e74b-9b8c-46a7-a612-7b975756f753";

            return p;
        }

        static AzureParameters FusionWebParameters()
        {
            var p = new AzureParameters();
            p.ClientId = "98087eb4-ba20-4dc0-a0ff-04883f4e4f8f";
            p.TenantId = "4875e74b-9b8c-46a7-a612-7b975756f753";

            return p;
        }
    }
}
