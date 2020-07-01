using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using log4net;

namespace OIDC_ClientApp_OWIN
{
    public class MvcApplication : System.Web.HttpApplication
    {
        //public static string apiToken = ConfigurationManager.AppSettings["okta.ApiToken"];
        //public static Uri apiUrl = new System.Uri(ConfigurationManager.AppSettings["okta.ApiUrl"]);
        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        protected void Application_Start()
        {
            logger.Debug("Application_Start");
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            log4net.Config.XmlConfigurator.Configure(new FileInfo(Server.MapPath("~/Web.config")));

            System.Net.ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        }

        protected void Session_Start(object sender, EventArgs e)
        {
            logger.Debug("Session_Start");
        }

        protected void Application_BeginRequest()
        {
            logger.Debug("Application_BeginRequest");
        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            logger.Debug("Application_AuthenticateRequest");
        }

        protected void Application_Error(object sender, EventArgs e)
        {
            logger.Debug("Application_Error");
        }

        protected void Session_End(object sender, EventArgs e)
        {
            logger.Debug("Session_End");
        }

        protected void Application_End(object sender, EventArgs e)
        {
            logger.Debug("Application_End");
        }




    }


}
