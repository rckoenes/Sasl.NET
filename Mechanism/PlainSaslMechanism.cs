using System;
using System.Text;

namespace TripleSoftware.Sasl.Mechanism
{
	/// <summary>
	/// Plain unencrypted SASL authentication method 
	/// </summary>
	public class PlainSaslMechanism : ASaslMechanism
	{
				
		/// <summary>
		/// Plain method authentication
		/// </summary>
		/// <returns>unencrypted users authentication</returns>
		public override string GetResponse()
		{
			StringBuilder respnose = new StringBuilder();

			respnose.Append((char) 0);
			respnose.Append( UserName);
			respnose.Append((char) 0);
			respnose.Append( Password);

			byte[] encode = Encoding.Default.GetBytes(respnose.ToString());
			return Convert.ToBase64String(encode, 0, encode.Length);
		}
		
		/// <summary>
		/// Plain method authentication
		/// </summary>
		/// <param name="Challenge">Plain does not supprt challenge, this will be ignored</param>
		/// <returns>unencrypted users authentication</returns>
		public override string GetResponse(string Challenge)
		{
			return this.GetResponse();
		}
		

	}
}
