using System.Web;
//using System.Web.Http;
using System.Web.Mvc;

namespace OIDC_ClientApp_OWIN
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());


            // Configure Web API to use only bearer token authentication.
            // Must reference OWIN libraries for the following 2 lines to work
            //config.SuppressDefaultHostAuthentication();
            //filters.Add(new HostAuthenticationFilter(Microsoft.Owin.Security.OAuth.OAuthDefaults.AuthenticationType));
            ////filters.Add(new HostAuthenticationFilter(Microsoft.Owin.Security.OpenIdConnect.OpenIdConnectAuthenticationDefaults.AuthenticationType));

        }
    }
}
