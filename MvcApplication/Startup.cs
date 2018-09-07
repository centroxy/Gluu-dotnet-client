using System;
using System.Configuration;
using System.Net;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using IdentityModel.Client;
using System.Collections.Generic;
using System.Security.Claims;

[assembly: OwinStartup(typeof(MvcApplication.Startup))]

namespace MvcApplication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Configure Gluu  OP server parameters
            string oidcDomain = ConfigurationManager.AppSettings["OIDC:Domain"];
            string oidcClientId = ConfigurationManager.AppSettings["OIDC:ClientId"];
            string oidcClientSecret = ConfigurationManager.AppSettings["OIDC:ClientSecret"];
            string oidcRedirectUri = ConfigurationManager.AppSettings["OIDC:RedirectUri"];
            string oidcPostLogoutRedirectUri = ConfigurationManager.AppSettings["OIDC:PostLogoutRedirectUri"];
            string oidcCustompath= ConfigurationManager.AppSettings["OIDC:CustomPath"]; 
            string authority = $"https://{oidcDomain}";
            // Enable Kentor Cookie Saver middleware
            app.UseKentorOwinCookieSaver();

            // Ignore ivalid SSL ( Remove for Production )
            ServicePointManager.ServerCertificateValidationCallback =
            delegate (object s, X509Certificate certificate,
                     X509Chain chain, SslPolicyErrors sslPolicyErrors)
            { return true; };

            // Set Cookies as default authentication type
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                LoginPath = new PathString("/Account/Login")
            });

            // Configure Gluu authentication
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "iCrypto",

                Authority = $"https://{oidcDomain}",

                ClientId = oidcClientId,
                ClientSecret = oidcClientSecret,
                
                RedirectUri = oidcRedirectUri,
                PostLogoutRedirectUri = oidcPostLogoutRedirectUri,

                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = "openid profile",



                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"

                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {

                    AuthorizationCodeReceived = async n =>
                    {
                        // Exchange code for access and ID tokens
                        var tokenClient = new TokenClient(authority + $"/{oidcCustompath}/restv1/token", oidcClientId, oidcClientSecret);
                        var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(n.Code, oidcRedirectUri);

                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        var userInfoClient = new UserInfoClient(authority + $"/{oidcCustompath}/restv1/userinfo");
                        var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);
                        var claims = new List<Claim>();
                        claims.AddRange(userInfoResponse.Claims);
                        claims.Add(new Claim("id_token", tokenResponse.IdentityToken));
                        claims.Add(new Claim("access_token", tokenResponse.AccessToken));

                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
                        }

                        n.AuthenticationTicket.Identity.AddClaims(claims);

                        return;
                    },



                    RedirectToIdentityProvider = notification =>
                    {

                        //Uncommet - when Passing ACR values
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            notification.ProtocolMessage.AcrValues = "<ACR Value>";
                            notification.ProtocolMessage.Parameters.Add ("custom_response_headers", @"[{""language"":""us-en""}]");
                            //notification.OwinContext.Request.Headers.Append("Content-Language", "en-US");
                        }

                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {

                            var idTokenClaim = notification.OwinContext.Authentication.User.FindFirst("id_token");
                            if (idTokenClaim != null)
                            {
                                notification.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
                            }
                            //var logoutUri = $"https://{Domain}/v2/logout?client_id={ClientId}";
                            var logoutUri = $"https://{oidcDomain}/{oidcCustompath}/restv1/end_session?id_token_hint={notification.ProtocolMessage.IdTokenHint}";

                            var postLogoutUri = notification.ProtocolMessage.PostLogoutRedirectUri;
                            if (!string.IsNullOrEmpty(postLogoutUri))
                            {
                                if (postLogoutUri.StartsWith("/"))
                                {
                                    // transform to absolute
                                    var request = notification.Request;
                                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                                }
                                logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                            }

                            notification.Response.Redirect(logoutUri);
                            notification.HandleResponse();
                        }
                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}
