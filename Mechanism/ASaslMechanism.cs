using System;
using System.Text;
using TripleSoftware.Sasl;

namespace TripleSoftware.Sasl.Mechanism
{
	/// <summary>
	/// Abstract class for use by sasl mechanisms
	/// </summary>
	public abstract class ASaslMechanism : TripleSoftware.Sasl.ISaslMechanism
	{
		/// <summary>
		/// Accounts UserName 
		/// </summary>
		private string userName = "";
		/// <summary>
		/// Account password
		/// </summary>
		private string password = "";
		/// <summary>
		/// Server on which to authenticate
		/// </summary>
		private string server = "";
		/// <summary>
		/// Challenge send by the server
		/// </summary>
		private string challenge = "";
		
		private string digestUri = "";
		
		/// <summary>
		/// Number of treis to authenticate
		/// </summary>
		private int treis = 1;

		/// <summary>
		/// SASL realm
		/// </summary>
		private string realm;
		/// <summary>
		/// SASL nonce
		/// </summary>
		private string nonce;
		/// <summary>
		/// SASL qop
		/// </summary>
		private string qop;
		/// <summary>
		/// SASL Character se
		/// </summary>
		private string charset = "utf-8";
		/// <summary>
		/// SASL algorithm
		/// </summary>
		private string algorithm;
		/// <summary>
		/// SASL rspauth
		/// </summary>
		private string rspauth;
		/// <summary>
		/// SASL cnonce
		/// </summary>
		private string cnonce;
		/// <summary>
		/// SASL authzid
		/// </summary>
		private string authzid = "";
		
		/// <summary>
		/// accounts UserName property
		/// </summary>
		public string UserName {
			get { return this.userName; }
			set { this.userName = value; }
		}
		
		/// <summary>
		/// Accounts password property
		/// </summary>
		public string Password {
			get { return this.password; }
			set { this.password = value; }
		}
		
		/// <summary>
		/// Server on which to authenticate
		/// </summary>
		public string Server {
			get { return this.server; }
			set { this.server = value; }
		}
		
		/// <summary>
		/// Challeneg send by the server
		/// </summary>
		public string Challenge {
			get { return this.challenge; }
			set { this.challenge = value;
				Parse( value );
			}
		}
		
		/// <summary>
		/// get the next nc
		/// </summary>
		public string NC
		{
			get { return this.treis.ToString().PadLeft(8, '0'); }
		}

		/// <summary>
		/// Increase the number of tries
		/// </summary>
		public void AddTry()
		{
			treis++;
		}

		/// <summary>
		/// Get the digest-uri
		/// </summary>
		public string DigestUri
		{
			get { return this.digestUri; }
			set { this.digestUri = value; }
		}

		/// <summary>
		/// SASL Realm property
		/// </summary>
		protected string Realm
		{
			get { return this.realm; }
			set { this.realm = value; }
		}
		/// <summary>
		/// SASL Nonce property
		/// </summary>
		protected string Nonce
		{
			get { return this.nonce; }
			set { this.nonce = value; }
		}

		/// <summary>
		/// SASL Qop property
		/// </summary>
		protected string Qop
		{
			get { return this.qop; }
			set { this.qop = value; }
		}

		/// <summary>
		/// SASL Character set property
		/// </summary>
		protected string Charset
		{
			get { return this.charset; }
			set { this.charset = value; }
		}

		/// <summary>
		/// SASL encryption algorithm property
		/// </summary>
		protected string Algorithm
		{
			get { return this.algorithm; }
			set { this.algorithm = value; }
		}

		/// <summary>
		/// SASL RspAuth property
		/// </summary>
		protected string Rspauth
		{
			get { return this.rspauth; }
			set { this.rspauth = value; }
		}

		/// <summary>
		/// SASL Cnonce property
		/// </summary>
		protected string Cnonce
		{
			get { return this.cnonce; }
			set { this.cnonce = value; }
		}

		/// <summary>
		/// SASL Authzid property
		/// </summary>
		protected string Authzid
		{
			get { return this.authzid; }
			set { this.authzid = value; }
		}

		/// <summary>
		/// Generate a random string
		/// </summary>
		/// <param name="length">Length of the string</param>
		/// <returns>Radom string</returns>
		public static string GenerateString(int length)
		{
			char[] characters = "abcdefghiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
			StringBuilder builder = new StringBuilder();
			Random random = new Random();
			for (int i = 0; i < length; i++)
				builder.Append(characters[random.Next(0, characters.Length)]);
			return builder.ToString();
		}

		/// <summary>
		/// parse the fileds form the decripted challenge
		/// </summary>
		/// <param name="challenge"></param>
		private void Parse(string challenge)
		{
			byte[] decode = Convert.FromBase64String(challenge);
			challenge = Encoding.Default.GetString(decode);
			string[] split = challenge.Split(',');
			foreach (string pair in split)
			{
				string[] splitPair = pair.Split('=');
				string key = splitPair[0];
				string data = splitPair[1];
				if (data.StartsWith("\""))
				{
					data = data.Substring(1, data.Length - 2);
				}
				switch (key)
				{
					case "algorithm":
						Algorithm = data;
						break;
					case "charset":
						Charset = data;
						break;
					case "nonce":
						Nonce = data;
						break;
					case "qop":
						Qop = data;
						break;
					case "realm":
						Realm = data;
						break;
					case "rspauth":
						Rspauth = data;
						break;
					case "authzid":
						Authzid = data;
						break;
				}
			}
		}
		
		/// <summary>
		/// Responce of the sasl class to the challenge 
		/// </summary>
		/// <returns>Authentication hash</returns>
		public abstract string GetResponse();
		
		/// <summary>
		/// Responce of the sasl class to the challenge 
		/// </summary>
		/// <param name="Challenge">Server authentication Challenge</param>
		/// <returns>Authentication hash</returns>
		public abstract string GetResponse(string Challenge);
		
    	/// <summary>
		/// Converts all bytes in the Array to a string representation.
		/// </summary>
		/// <param name="buf"></param>
		/// <returns>string representation</returns>
		protected static string HexToString(byte[] buf)
		{
			StringBuilder sb = new StringBuilder();
			foreach (byte b in buf)
			{
				sb.Append(b.ToString("x2"));
			}
			return sb.ToString();
		}
		
		/// <summary>
		/// Adds " to the begining and end of the string
		/// </summary>
		/// <param name="s"></param>
		/// <returns>Quted string</returns>
		protected static string AddQuotes(string s)
		{
			return String.Concat("\"", s, "\"");
		}
	}
}
