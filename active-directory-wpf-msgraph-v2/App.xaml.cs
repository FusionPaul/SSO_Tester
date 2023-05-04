using System.Windows;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Desktop;
using Microsoft.Identity.Client.Broker;
using System.Windows.Interop;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System;
using System.Text;
using System.Text.Json;

namespace SSO
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>

    // To change from Microsoft public cloud to a national cloud, use another value of AzureCloudInstance
    public partial class App : Application
    {
        static App()
        {
            
            //ConfigureFusionTestConsole();
            //ConfigureFusionTestWeb();

            ConfigureBoehringerProsper();
            CreatePublicApplication(true, false);
            //CreateConfidentialApplication();
        }

        public static void CreateApplication(bool useWam, bool useBrokerPreview)
        {
            CreatePublicApplication(useWam, useBrokerPreview);
            //CreateConfidentialApplication();
        }


        private static void ConfigureFusionTestConsole()
        {
            ClientId = "e2a5bd83-eb83-428b-8ad2-83f19b02f2de";
            Tenant = "4875e74b-9b8c-46a7-a612-7b975756f753";
        }
        private static void ConfigureFusionTestWeb()
        {
            ClientId = "98087eb4-ba20-4dc0-a0ff-04883f4e4f8f";
            Tenant = "4875e74b-9b8c-46a7-a612-7b975756f753";
        }

        private static void ConfigureBoehringerProsper()
        {
            ClientId = "dce8f033-74b4-42c4-8c2a-cabfaeadfeb3";
            Tenant = "e1f8af86-ee95-4718-bd0d-375b37366c83";
        }


        // Below are the clientId (Application Id) of your app registration and the tenant information. 
        // You have to replace:
        // - the content of ClientID with the Application Id for your app registration
        // - The content of Tenant by the information about the accounts allowed to sign-in in your application:
        //   - For Work or School account in your org, use your tenant ID, or domain
        //   - for any Work or School accounts, use organizations
        //   - for any Work or School accounts, or Microsoft personal account, use 4875e74b-9b8c-46a7-a612-7b975756f753
        //   - for Microsoft Personal account, use consumers
        private static string ClientId = "e2a5bd83-eb83-428b-8ad2-83f19b02f2de";

        // Note: Tenant is important for the quickstart.
        private static string Tenant = "4875e74b-9b8c-46a7-a612-7b975756f753";
        private static string Instance = "https://login.microsoftonline.com/";
       
        //private static IPublicClientApplication _clientApp;
        //public static IPublicClientApplication ClientApp { get { return _clientApp; } }

        private static IPublicClientApplication _clientApp;
        public static IPublicClientApplication ClientApp { get { return _clientApp; } }

        private System.Security.Cryptography.X509Certificates.X509Certificate2 GetCertificate()
        {
            string certText = "-----BEGIN CERTIFICATE-----\r\nMIIC8DCCAdigAwIBAgIQFqdO3m69/o9HUDkHnRmRQjANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQD\r\nEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMzA0MTkxMzI4\r\nMjRaFw0yNTA0MTkxMzI4MThaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQg\r\nU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0crJ/kylYtAl\r\nB04WB3ESN6nb4cjAqnALCtXB3fmnFKjoBRlgwFBwejjimbI/9godqZ1rZZg1DJWACG1aEIVAj8jz\r\nyYx19dOe1KSJI0x58wCbHuzI+ZDo9GsCKynC/VB9kt0epgHsmd52b6Ul6NczTLPNpe5CVVEgJ4pk\r\nDzKAVPy10E1cKkI3fAghbnWhysKQH2pm7MrEWx8EKLEyOzv2y1OjigD4R07pFImQusaq546ErB7K\r\n04cdmSyMRTiruukhUXebzK77580z1A8A3d57Z7qiu9tK2LzfV2Yrt6kbQMNjTUnUNADhynz0/IHP\r\nGoO50nixY53xbj0f6xCzcpDbvQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA5GIo5zJdT0B+kowIC\r\nZYDpiB6RN6ffdzVyFSzt8oME+0V7yhpC8qdJIypb1kWKZ+83nt7441nnX0nukGuTiBDdYtBO+rTF\r\nKKbEyia+/mmEOuIQWbLETZUWeHvsMDkLLVXVoTkBrUeI/cVDt0LljR7C1l6DDFvrCqI707OFfjzE\r\nXDx8PLTso8Z2fLlkBMMWSqTs8sHMsJof1m7SbDR1VDQ1JwtQFgmm/I0moqWdGPlttsZpCKqkZU40\r\n4AnpVVWU9mC4aFNQi0iIqQessn4Grc31uUx4hKDT+Qwq1MU+kmzC/2BB6X8AjaKZl1xRm2t5NdAz\r\nC1/pE7pCZhTNGRqwv2Ng\r\n-----END CERTIFICATE-----";
            var bytes = System.Text.Encoding.ASCII.GetBytes(certText);

            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(bytes);

            return cert;

        }

        public static void CreatePublicApplication(bool useWam, bool useBrokerPreview)
        {
            var builder = PublicClientApplicationBuilder.Create(ClientId)
            .WithAuthority($"{Instance}{Tenant}")
            .WithDefaultRedirectUri();


            //Use of Broker Requires redirect URI "ms-appx-web://microsoft.aad.brokerplugin/{client_id}" in app registration
            if (useWam && !useBrokerPreview)
            {
                builder.WithWindowsBroker(true);
            }
            else if (useWam && useBrokerPreview)
            {
                builder.WithBrokerPreview(true);
            }
            _clientApp = builder.Build();
            TokenCacheHelper.EnableSerialization(_clientApp.UserTokenCache);
        }

        //public static void CreateConfidentialApplication()
        //{
        //    var builder = ConfidentialClientApplicationBuilder.Create(ClientId)
        //    .WithAuthority($"{Instance}{Tenant}");

        //    _clientApp = builder.Build();
        //    TokenCacheHelper.EnableSerialization(_clientApp.UserTokenCache);
        //}

        private static IDictionary<string, object> GetClaims()
        {
            //aud = https://login.microsoftonline.com/ + Tenant ID + /v2.0
            string aud = $"https://login.microsoftonline.com/{Tenant}/v2.0";

            string ConfidentialClientID = ClientId; //client id 00000000-0000-0000-0000-000000000000
            const uint JwtToAadLifetimeInSeconds = 60 * 10; // Ten minutes
            DateTimeOffset validFrom = DateTimeOffset.UtcNow;
            DateTimeOffset validUntil = validFrom.AddSeconds(JwtToAadLifetimeInSeconds);

            return new Dictionary<string, object>()
    {
        { "aud", aud },
        { "exp", validUntil.ToUnixTimeSeconds() },
        { "iss", ConfidentialClientID },
        { "jti", Guid.NewGuid().ToString() },
        { "nbf", validFrom.ToUnixTimeSeconds() },
        { "sub", ConfidentialClientID }
    };
        }

        static string Base64UrlEncode(byte[] arg)
        {
            char Base64PadCharacter = '=';
            char Base64Character62 = '+';
            char Base64Character63 = '/';
            char Base64UrlCharacter62 = '-';
            char Base64UrlCharacter63 = '_';

            string s = Convert.ToBase64String(arg);
            s = s.Split(Base64PadCharacter)[0]; // RemoveAccount any trailing padding
            s = s.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }

        static string GetSignedClientAssertion(X509Certificate2 certificate)
        {
            // Get the RSA with the private key, used for signing.
            var rsa = certificate.GetRSAPrivateKey();

            //alg represents the desired signing algorithm, which is SHA-256 in this case
            //x5t represents the certificate thumbprint base64 url encoded
            var header = new Dictionary<string, string>()
    {
        { "alg", "RS256"},
        { "typ", "JWT" },
        { "x5t", Base64UrlEncode(certificate.GetCertHash()) }
    };

            //Please see the previous code snippet on how to craft claims for the GetClaims() method
            var claims = GetClaims();

            var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
            var claimsBytes = JsonSerializer.SerializeToUtf8Bytes(claims);
            string token = Base64UrlEncode(headerBytes) + "." + Base64UrlEncode(claimsBytes);

            string signature = Base64UrlEncode(rsa.SignData(Encoding.UTF8.GetBytes(token), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            string signedClientAssertion = string.Concat(token, ".", signature);
            return signedClientAssertion;
        }

    }
}
