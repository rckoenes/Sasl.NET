
#if TEST
using System;
using NUnit.Framework;
using TripleSoftware.Sasl;
using TripleSoftware.Sasl.Mechanism;

namespace TripleSoftware.Sasl.UnitTests
{
	/// <summary>
	/// Test class for Sasl methods
	/// </summary>
	[TestFixture]
	public class SaslTest
	{
		private static string username = "tux2k";
		private static string password = "test";
		private static string server = "jabber.xs4all.nl";

		private static string challenge = "bm9uY2U9IjEyMjAxOTMyODEiLHFvcD0iYXV0aCIsY2hhcnNldD11dGYtOCxhbGdvcml0aG09bWQ1LXNlc3M=";
		private static string response = "dXNlcm5hbWU9InR1eDJrIixyZWFsbT0iIixub25jZT0iMTIyMDE5MzI4MSIsY25vbmNlPSJlNDMwOTIzMzdhNmY5OTljZTlmNzE3OTU5NGI4NmM3MDA2ZTJlMWNiIixuYz0wMDAwMDAwMSxxb3A9YXV0aCxkaWdlc3QtdXJpPSJ4bXBwL2phYmJlci54czRhbGwubmwiLGNoYXJzZXQ9dXRmLTgscmVzcG9uc2U9ZjM2NTMwZmI1YzI0ZTRkZDYxY2U1MzZmMTFlZjk1ODU=";
		private static string plainResponse = "AHR1eDJrAHRlc3Q=";

		[Test]
		public void testMD5Mechanism()
		{
			try
			{
				ISaslMechanism mechanism = new DigestMD5SaslMechanism();
				mechanism.Password = password;
				mechanism.UserName = username;
				mechanism.Server = server;
				mechanism.Challenge = challenge;
				mechanism.DigestUri = "xmpp/"+server;
				Assert.AreEqual(response, mechanism.GetResponse());
			}
			catch (Exception e)
			{
				Assert.Fail("Error: " + e.ToString());
			}
		}

		[Test]
		public void testPlainMechanism()
		{
			try
			{
				
				ISaslMechanism mechanism = new PlainSaslMechanism();
				mechanism.Password = password;
				mechanism.UserName = username;
				mechanism.Server = server;
				mechanism.Challenge = challenge;
				Assert.AreEqual(plainResponse, mechanism.GetResponse());
			}
			catch (Exception e)
			{
				Assert.Fail("Error" + e.ToString());
			}
		}
		
		[Test]
		public void testSaslFactory(){
			SaslFactory saslFactory = new SaslFactory();
			ISaslMechanism mechanism = saslFactory.Make( "digest-md5" );
			mechanism.Password = password;
			mechanism.UserName = username;
			mechanism.Server = server;
			mechanism.DigestUri = "xmpp/"+server;
			mechanism.Challenge = challenge;
			Assert.AreEqual(response, mechanism.GetResponse());
		}
		
		[Test]
		public void testErrorSaslFactory(){
			bool fail = false;
			SaslFactory saslFactory = new SaslFactory();
			try{
				ISaslMechanism mechanism = saslFactory.Make( "md5" );
				mechanism.Password = password;
				mechanism.UserName = username;
				mechanism.Server = server;
				mechanism.Challenge = challenge;
				Assert.AreEqual(response, mechanism.GetResponse());
			} catch( SaslMechanismNotAvailableException){
				fail = true;
			}
			
			Assert.IsTrue( fail );
		}
		
	}
}
#endif
