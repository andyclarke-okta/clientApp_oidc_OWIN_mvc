using log4net;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace OIDC_ClientApp_OWIN.Controllers
{
    public class HomeController : Controller
    {
        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        NameValueCollection appSettings = ConfigurationManager.AppSettings;
        public ActionResult Index()
        {

            return View();
        }

        [Authorize]
        public ActionResult Login()
        {
            logger.Debug("protected endpoint intiate OIDC auth workflow");

            //if (!HttpContext.User.Identity.IsAuthenticated)
            //{
            //    logger.Debug("user is NOT authenticated");
      
            //    var properties = new AuthenticationProperties();
            //    //properties.RedirectUri = "/Home/MyProfile";
            //    HttpContext.GetOwinContext().Authentication.Challenge(properties,
            //        CookieAuthenticationDefaults.AuthenticationType,
            //        OpenIdConnectAuthenticationDefaults.AuthenticationType);

            //    return new HttpUnauthorizedResult();
            //}
 


            return RedirectToAction("PostLogin", "Home");
        }


        public ActionResult Logout()
        {
            logger.Debug("Logout");

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                logger.Debug("start log off authenticated user");
                HttpContext.GetOwinContext().Authentication.SignOut(
                            OpenIdConnectAuthenticationDefaults.AuthenticationType,
                            CookieAuthenticationDefaults.AuthenticationType
                            );
            }
            else
            {
                logger.Debug("user is not authenticated");
            }
            // this is configured in Startup.cs to hit /Home/PostLogin
            return View();
        }


        public ActionResult PostLogin()
        {
            logger.Debug("PostLogin");
            return View();
        }

        public ActionResult PostLogOut()
        {
            logger.Debug("PostLogOut");
            return View();
        }

        [Authorize]
        public ActionResult MyProfile()
        {

            var tempClaims = HttpContext.GetOwinContext().Authentication.User.Claims;


            return View(HttpContext.GetOwinContext().Authentication.User.Claims);
        }



        public ActionResult AuthError(string message)
        {
            logger.Debug("AuthError");
            TempData["message"] = message;
            return View();
        }

        


    }
}