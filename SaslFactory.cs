using System;
using System.Collections.Generic;

using TripleSoftware.Sasl;
using TripleSoftware.Sasl.Mechanism;

namespace TripleSoftware.Sasl
{
	/// <summary>
	/// Exception to throw when the factory tries to make a sasl mechanism which in not available
	/// </summary>
	public class SaslMechanismNotAvailableException : Exception{
		/// <summary>
		/// Exception to throw when the factory tries to make a sasl mechanism which in not available
		/// </summary>
		public SaslMechanismNotAvailableException( string message) : base(message) {}
	}
	
	/// <summary>
	/// Factory class that makes sasl Iathenticator classes.
	/// Also check wether sasl mechanism is supported
	/// </summary>
	public class SaslFactory
	{
		Dictionary<string, Type> SaslMechanismList = new Dictionary<string, Type>();
		
		/// <summary>
		/// 
		/// </summary>
		public SaslFactory()
		{
			SaslMechanismList.Add( "digest-md5", typeof(TripleSoftware.Sasl.Mechanism.DigestMD5SaslMechanism) );
			SaslMechanismList.Add( "plain", typeof(TripleSoftware.Sasl.Mechanism.PlainSaslMechanism)  );
		}
		
		/// <summary>
		/// Check wether we have support for this sasl type
		/// </summary>
		/// <returns></returns>
		public bool HasSupport(string mechanism){
			return SaslMechanismList.ContainsKey( mechanism );
		}
		
		/// <summary>
		/// Let the factory maken a new mecahnism by its name
		/// </summary>
		/// <param name="mechanism">Sasl mechanism name to make</param>
		/// <returns>Instants of the sasl mechanism</returns>
		public ASaslMechanism Make( string mechanism) {
			if( !this.HasSupport( mechanism ) )
				throw new SaslMechanismNotAvailableException( "The "+mechanism+" mechanism is not available" );
			
			Type mechanismType = SaslMechanismList[mechanism];
			return Activator.CreateInstance( mechanismType ) as ASaslMechanism;
			
		}
	}


}
