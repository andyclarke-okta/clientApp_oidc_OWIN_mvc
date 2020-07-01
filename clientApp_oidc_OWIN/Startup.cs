using Microsoft.Owin;
using Owin;
using System.Web.Configuration;
using System.Linq;

using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using log4net;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Generic;
using System;
using System.Web;
using IdentityModel.Client;

[assembly: OwinStartup(typeof(OIDC_ClientApp_OWIN.Startup))]

namespace OIDC_ClientApp_OWIN
{
    public class Startup
    {
        string idp = WebConfigurationManager.AppSettings["oidc.idp"];
        ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        string clientId = WebConfigurationManager.AppSettings["oidc.spintweb.clientId"];
        string clientSecret = WebConfigurationManager.AppSettings["oidc.spintweb.clientSecret"];
        string authority = WebConfigurationManager.AppSettings["oidc.issuer"];
        string redirectUri = WebConfigurationManager.AppSettings["oidc.spintweb.redirectUri"];
        string responseType = WebConfigurationManager.AppSettings["oidc.tokenType"];
        string scope = WebConfigurationManager.AppSettings["oidc.scopes"];
        string postLogoutRedirectUri = WebConfigurationManager.AppSettings["oidc.spintweb.postLogoutRedirectUri"];


        public void Configuration(IAppBuilder app)
        {
            app.Use(async (Context, next) =>
            {
                // request processing - do something here                
                await next.Invoke();
                // response processing - do something here
            });
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            //app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseCookieAuthentication(new CookieAuthenticationOptions {

                CookieName = "Okta_OIDCSApp"            
            });

            //string storeRedirectUrl = null;

            //var protocolValidator = new OpenIdConnectProtocolValidator();
            //protocolValidator.RequireNonce = true;
            //protocolValidator.RequireStateValidation = false;
            //protocolValidator.RequireState = false;


            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Authority = authority,
                    //Note: this can be done dynamically below
                    RedirectUri = redirectUri,
                    ResponseType = responseType,
                    Scope = scope,
                    PostLogoutRedirectUri = postLogoutRedirectUri,
                    //ProtocolValidator = protocolValidator,


                    //Required to validate the signature
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidAudience = WebConfigurationManager.AppSettings["oidc.spintweb.clientId"],
                        ValidIssuer = WebConfigurationManager.AppSettings["oidc.issuer"],
                        ValidateIssuerSigningKey = true,
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true
                        //ValidateTokenReplay = false

                    },

                    //Must be placed after 'TokenValidationParameters'
                   // SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,



                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        MessageReceived = n =>
                        {
                            logger.Debug("MessageReceived");
                            string myCustomParameter;
                            var protectedState = n.ProtocolMessage.State.Split('=')[1];
                            var state = n.Options.StateDataFormat.Unprotect(protectedState);
                            state.Dictionary.TryGetValue("MyCustomParameter", out myCustomParameter);


                            return Task.FromResult(0);
                        },

                        AuthorizationCodeReceived = async n =>
                        {
                            //when response type of code is specific in responseType
                            logger.Debug("AuthorizationCodeReceived");
                            string code = n.Code;

                            var tokenClient = new TokenClient(authority + "/oauth2/v1/token", clientId, clientSecret);
                            var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, redirectUri);

                            if (tokenResponse.IsError)
                            {
                                throw new Exception(tokenResponse.Error);
                            }

                            //method 1 for storing token
                            HttpContext.Current.Session["access_token"] = tokenResponse.AccessToken;
                            HttpContext.Current.Session["refresh_token"] = tokenResponse.RefreshToken;
                            //HttpContext.Current.Session["id_token_ac"] = tokenResponse.IdentityToken;

                            //method 2 for storing token;
                            var claims = new List<Claim>();
                            claims.Add(new Claim("id_token_ac", tokenResponse.IdentityToken));
                            claims.Add(new Claim("access_token", tokenResponse.AccessToken));
                            claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
                            //should NOT add claims since the token has not been validated at this notification level
                            n.AuthenticationTicket.Identity.AddClaims(claims);


                            var userInfoClient = new UserInfoClient(authority + "/oauth2/v1/userinfo");
                            var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);

                            //add claims from userInfo endpoint
                            claims.AddRange(userInfoResponse.Claims);



                            //return Task.FromResult(0);
                        },
                        AuthenticationFailed = n =>
                        {
                            logger.Debug("AuthenticationFailed");
                            n.HandleResponse();
                            logger.Debug(n.Exception.Message);


                            if (n.Exception.Message == "access_denied")
                            {
                                //context.Response.Redirect(WebConfigurationManager.AppSettings["oidc.authError"]);
                                n.Response.Redirect("/Home/AuthError?message=" + n.Exception.Message);
                            }
                            if (n.Exception.Message == "login_required")
                            {
                                //context.Response.Redirect(WebConfigurationManager.AppSettings["oidc.authError"]);
                                n.Response.Redirect("/Home/AuthError?message=" + n.Exception.Message);
                            }
                            else
                            {
                                //context.Response.Redirect(WebConfigurationManager.AppSettings["oidc.authError"]);
                                n.Response.Redirect("/Home/AuthError?message=" + n.Exception.Message);
                            }

                            //if (context.Exception.Message.StartsWith("IDX21323"))
                            //{
                            //    context.SkipToNextMiddleware();
                            //    return Task.FromResult(0);

                            //    context.Response.Redirect(storeRedirectUrl);
                            //}

                            return Task.FromResult(0);
                        },
                        SecurityTokenReceived = n =>
                        {
                            logger.Debug("SecurityTokenReceived");


                            return Task.FromResult(0);
                        },
                        SecurityTokenValidated = n =>
                        {
                            logger.Debug("SecurityTokenValidated");
                            string nameIdent = n.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

                            string friendlyname = n.AuthenticationTicket.Identity.FindFirst("friendlyname").Value;
                            n.AuthenticationTicket.Identity.AddClaim(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", friendlyname));

                            //add id_token to calims to support OIDC logout
                            var id_token = n.ProtocolMessage.IdToken;
                            n.AuthenticationTicket.Identity.AddClaim(new Claim("id_token", id_token));
                            // Add roles based on Okta groups 
                            foreach (var group in n.AuthenticationTicket.Identity.Claims.Where(x => x.Type == "groups"))
                            {
                                n.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Role, group.Value));
                            }

                            string scheme = n.Request.Scheme;
                            string authority = n.Request.Uri.Authority;
                            n.AuthenticationTicket.Properties.RedirectUri = scheme + "://" + authority + "/Home/PostLogin";
 
                            return Task.FromResult(0);
                        },
                        //added to support idp parameter on authorize endpoint
                        RedirectToIdentityProvider = n =>
                        {
                            logger.Debug("RedirectToIdentityProvider");
                 
                            if (n.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Authentication)
                            {
                                //use this if only allowed access from entry application
                                //n.ProtocolMessage.SetParameter("prompt", "none"); //does not allow a login UI if no session
                                //use this to supercede an ACTIVE user
                                //n.ProtocolMessage.SetParameter("prompt", "login"); //forces login even if there is a ACTIVE Okta session
                                //use this to force consent,even if previously granted
                                //n.ProtocolMessage.SetParameter("prompt", "consent"); 

                                //Gobal Login Integration or Inbound IDP
                                //set value in web.config
                                //n.ProtocolMessage.SetParameter("idp", idp);



                                ////create redirect_url parameter dynamically
                                ////all variants MUST be included in Okta integration
                                //string absoluteUri = context.Request.Uri.AbsoluteUri;
                                //string myRedirectUrl = (absoluteUri.Substring(0, absoluteUri.IndexOf(context.Request.Uri.LocalPath))) + "/signin-oidc";
                                //string httpRule = context.Request.Headers["Front-End-Https"];
                                //if (!string.IsNullOrEmpty(httpRule) && httpRule == "On")
                                //{
                                //    int index = myRedirectUrl.IndexOf("http://");
                                //    if (myRedirectUrl.IndexOf("http://") != -1)
                                //    {
                                //        myRedirectUrl = myRedirectUrl.Replace("http://", "https://");
                                //    }
                                //}
                                //context.ProtocolMessage.RedirectUri = myRedirectUrl.ToLower();

                                //add state parameter to OIDC
                                var stateQueryString = n.ProtocolMessage.State.Split('=');
                                var protectedState = stateQueryString[1];
                                var state = n.Options.StateDataFormat.Unprotect(protectedState);
                                state.Dictionary.Add("MyCustomParameter", "myClientAppStateInfo");
                                n.ProtocolMessage.State = stateQueryString[0] + "=" + n.Options.StateDataFormat.Protect(state);
                            }
                 
                            if (n.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Logout)
                            {
                                var idToken = n.OwinContext.Authentication.User.Claims
                                    .FirstOrDefault(c => c.Type == "id_token")?.Value;
                                n.ProtocolMessage.IdTokenHint = idToken;
                            }
                            return Task.FromResult(0);
                        }
                    }
                });
        }


    }
}