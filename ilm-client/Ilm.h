#ifndef	__LISTENHANDLER
#define __LISTENHANDLER

#include "LibraryModuleBase.h"
#include "Primitive.h"
#include "Connection.h"

#define	MAX_INPUT_LEN	100

struct params
{
	char	callbackAddress[ MAX_INPUT_LEN ];
	int		callbackPort;
	char	targetAddress[ MAX_INPUT_LEN ];
	char	protocolType[ MAX_INPUT_LEN ];
	int		rawPort;
};

namespace Ilm {

	//Listener
	class Listener {

		public:
			Connection* connection;

	   		//Default constructor
			Listener();      

			//Default destructor
			virtual ~Listener();
		
			//Interface to cutThroat
			void Listen( InterfaceLibrary::Primitive::Activation& actvn, 
						InterfaceLibrary::ProcessCmdAccumulator& acc, 
						InterfaceLibrary::ProcessCmdResponse& resp );
		
			void TriggerAndListen( InterfaceLibrary::Primitive::Activation& actvn, 
								InterfaceLibrary::ProcessCmdAccumulator& acc, 
								InterfaceLibrary::ProcessCmdResponse& resp );

			//returns Connection for external use right now...
			Connection* getConnection();

			//Sets connection, caller is responsible for destroyin previous connection is it existed...
			void setConnection( Connection *newConnection );
	};


	//Trigger
 	class Trigger {

		public:
		   //Interface to cutThroat
			void triggerImplant( InterfaceLibrary::Primitive::Activation& actvn, 
								InterfaceLibrary::ProcessCmdAccumulator& acc, 
								InterfaceLibrary::ProcessCmdResponse& resp );

		private:
			int parse_prompt_config_file( std::string filename, params *t_param );

	};

}

#endif
