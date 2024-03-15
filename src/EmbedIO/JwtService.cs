using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using MTUModelContainer.Database.Models;
using System.ComponentModel.DataAnnotations.Schema;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace EmbedIO
{
    public class JwtService
    {
        private readonly string _issuer;
        private readonly SecurityKey _key;
        private readonly string _encryptionKey;

        public JwtService(string issuer, SecurityKey key, string encryptionKey)
        {
            _issuer = issuer;
            _key = key;
            _encryptionKey = encryptionKey;
        }

        public ClaimsPrincipal GetPrincipal(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _issuer,
                IssuerSigningKey = _key,
            };

            SecurityToken validatedToken;
            return tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);
        }

        public string GenerateToken(User u, string type)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(BuildClaims(u)),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = _issuer,
                SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.RsaSha256),
                EncryptingCredentials = new EncryptingCredentials(
                    new SymmetricSecurityKey(sha2(_encryptionKey)), 
                    SecurityAlgorithms.Aes256KW,
                    SecurityAlgorithms.Aes256CbcHmacSha512),
            };

            tokenDescriptor.Subject.AddClaim(new Claim("type", type));

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private Claim[] BuildClaims(User u)
        {
            var claims = new List<Claim>();

            // get all public properties that are NON-foreign keys
            var allProperties = u.GetType().GetProperties();
            var nonForeignProps = allProperties.Where((z) => z.GetCustomAttribute(typeof(ForeignKeyAttribute)) is null)
                                               .ToList();

            foreach (var prop in nonForeignProps)
            {
                // get value
                var propValue = prop.GetValue(u);

                // attempt to get string value
                var strVal = propValue as string;
                if (strVal is null && propValue is not null) continue; // cannot be casted to string
                strVal = strVal is null ? "" : strVal;

                claims.Add(new Claim(prop.Name, strVal));
            }

            return claims.ToArray();
        }

        private byte[] sha2(string v)
        {
            using (var s = SHA256.Create())
            {
                return s.ComputeHash(Encoding.UTF8.GetBytes(v));
            }
        }
    }
}
