using System;

namespace TripleSoftware.Sasl
{
	/// <summary>
	/// ISaslMechanism interface.
	/// Interface which exposes default methods for Sasl Mechanisms.
	/// </summary>
	public interface ISaslMechanism
	{
		/// <summary>
		/// Username needed for authentication
		/// </summary>
		string UserName {get; set;}
		/// <summary>
		/// Password needed to authentication
		/// </summary>
		string Password {get; set;}
		
		/// <summary>
		/// Server on which to authenticate
		/// </summary>
		string Server {get;set;}
		
		/// <summary>
		/// Server authentication Challenge
		/// </summary>
		string Challenge{get; set;}
		
		/// <summary>
		/// Digest uri, example: XMPP/(server), SMTP/(server)
		/// </summary>
		string DigestUri{get; set;}
		
		/// <summary>
		/// Authentiction response
		/// </summary>
		/// <returns>Response hash</returns>
		string GetResponse();
		
		/// <summary>
		/// Authentiction response
		/// </summary>
		/// <param name="Challenge">Server authentication Challenge</param>
		/// <returns>Response hash</returns>
		string GetResponse( string Challenge );
	}
}
