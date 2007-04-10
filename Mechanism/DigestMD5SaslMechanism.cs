using System;
using System.Text;
using System.Security.Cryptography;

namespace TripleSoftware.Sasl.Mechanism
{
	/// <summary>
	/// SASL Digest-MD5 authentication Mechanism
	/// </summary>
	public class DigestMD5SaslMechanism : ASaslMechanism
	{
		/// <summary>
		/// First stage of user authentication.
		/// </summary>
		/// <returns>user authenticate part</returns>
		private byte[] UserAuthenticationHash()
		{
			//If authzid is specified, then A1 is
			//
			//A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
			//        ":", nonce-value, ":", cnonce-value, ":", authzid-value }
			//
			//If authzid is not specified, then A1 is
			//
			//A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
			//         ":", nonce-value, ":", cnonce-value }

			StringBuilder result = new StringBuilder();
			MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();
			
			byte[] toHash = Encoding.Default.GetBytes(String.Concat(UserName, ":", Realm, ":", Password));
			byte[] hash = MD5.ComputeHash(toHash);

			result.Append(Encoding.Default.GetChars(hash));
			result.Append(":");
			result.Append(Nonce);
			result.Append(":");
			result.Append(Cnonce);

			if (Authzid.Length != 0)
			{
				result.Append(":");
				result.Append(Authzid);
			}

			toHash = Encoding.Default.GetBytes(result.ToString());
			hash = MD5.ComputeHash(toHash);
			return hash;
		}

		/// <summary>
		/// Second stage of user Authentication.
		/// </summary>
		/// <returns>Uri authenticate part</returns>
		private byte[] UriAuthentication()
		{
			//If the "qop" directive's value is "auth", then A2 is:
			//
			//A2 = { "AUTHENTICATE:", digest-uri-value }
			//
			//If the "qop" value is "auth-int" or "auth-conf" then A2 is:
			//
			//A2 = { "AUTHENTICATE:", digest-uri-value,
			//       ":00000000000000000000000000000000" }

			StringBuilder result = new StringBuilder();
			MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();

			result.Append("AUTHENTICATE:");
			result.Append(DigestUri);

			if (!Qop.Equals("auth"))
			{
				result.Append(":00000000000000000000000000000000");
			}

			byte[] toHash = Encoding.Default.GetBytes(result.ToString());
			byte[] hash = MD5.ComputeHash(toHash);
			return hash;
		}


		private string Response()
		{
			//HEX( KD ( HEX(H(A1)),
			//{ nonce-value, ":" nc-value, ":",
			//cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))

			StringBuilder response = new StringBuilder();
			MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();

			response.Append(HexToString(UserAuthenticationHash()).ToLower());
			response.Append(":");
			response.Append(Nonce);
			response.Append(":");
			response.Append(NC);
			response.Append(":");
			response.Append(Cnonce);
			response.Append(":");
			response.Append(Qop);
			response.Append(":");
			response.Append(HexToString(UriAuthentication()).ToLower());


			byte[] hash = MD5.ComputeHash(Encoding.Default.GetBytes(response.ToString()));

			return HexToString(hash).ToLower();
		}

		/// <summary>
		/// Respond to the servers sasl challenge with a MD5
		/// </summary>
		/// <returns>Response on the servers sasl challenge</returns>
		public override string GetResponse()
		{
			StringBuilder result = new StringBuilder();

#if ( DEBUG )
			this.Cnonce = "e43092337a6f999ce9f7179594b86c7006e2e1cb";
#else
			this.Cnonce = GenerateString(32);
#endif

			result.Append("username=");
			result.Append(AddQuotes(UserName));
			result.Append(",");
			result.Append("realm=");
			result.Append(AddQuotes(Realm));
			result.Append(",");
			result.Append("nonce=");
			result.Append(AddQuotes(Nonce));
			result.Append(",");
			result.Append("cnonce=");
			result.Append(AddQuotes(Cnonce));
			result.Append(",");
			result.Append("nc=");
			result.Append(NC);
			result.Append(",");
			result.Append("qop=");
			result.Append(Qop);
			result.Append(",");
			result.Append("digest-uri=");
			result.Append(AddQuotes(DigestUri));
			result.Append(",");
			result.Append("charset=");
			result.Append(Charset);
			result.Append(",");
			result.Append("response=");
			result.Append(this.Response());
			this.Response();

			byte[] encoder = Encoding.Default.GetBytes(result.ToString());

			return Convert.ToBase64String(encoder);
		}
		
		public override string GetResponse(string Challenge)
		{
			this.Challenge = Challenge;
			return this.Response();
		}


	}
}
