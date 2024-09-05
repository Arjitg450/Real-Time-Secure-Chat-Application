Team Members- 
CS22MTECH12001    DEBIKA SAMANTA
CS23MTECH12001    ARJIT GUPTA
CS23MTECH14010    ROHIT SUTRAVE

TASK 1: How to create keys and certificates
	STEP 1: Commands given in the report to create the keys, csr's, ceritificates, verification for Root CA, Int CA, Alice, Bob
                                                                        _________________________________________________
                                                                       |                                                 |
                                                                       |  NOTE- Execute these Commands on LOCALMACHINE   |
                                                                       |_________________________________________________|


TASK 2: How to execute secure_chat_app_localhost.cpp

	STEP 1 Open two terminals in the source folder "secure chat

	STEP 2 Compile the code using the command 
		g++ -o secure_chat_app_localhost secure_chat_app_localhost.cpp -lssl -lcrypto

	STEP 3 Execute the server By using the command 
		./secure_chat_app -s

	STEP 4 Execute the client By using the command
		./secure_chat_app -c bob1



---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



                                                                        _______________________________________
                                                                       |                                       |
                                                                       |  NOTE- Execute these Commands on VM   |
                                                                       |_______________________________________|

TASK 2: How to execute secure_chat_app.cpp

	STEP 1 Open two terminals in the source folder "secure chat

	STEP 2 Compile the code using the command 
		g++ -o secure_chat_app secure_chat_app.cpp -lssl -lcrypto

	STEP 3 Execute the server By using the command 
		./secure_chat_app -s

	STEP 4 Execute the client By using the command
		./secure_chat_app -c bob1


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



TASK 3:	
	
	STEP 1: Poison the DNS :-  bash ~/poison-dns-alice1-bob1.sh

	STEP 2: on TRUDY container
			to compile the code
			by Using 	g++ secure_chat_interceptor.cpp -o secure_chat_interceptor -lssl -lcrypto

	STEP 3: on TRUDY container
			to compile the code
			by Using	./secure_chat_interceptor -d alice1 bob1

	STEP 4: execute the server on BOB container
 			by Using 	./secure_chat_app -s

	STEP 5: execute the server on BOB container
 			by Using 	./secure_chat_app -c bob1



---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

TASK 4:
	
	STEP 1: Poison the DNS :-  bash ~/poison-dns-alice1-bob1.sh

	STEP 2: on TRUDY container
			to compile the code
			by Using 	g++ secure_chat_active_interceptor.cpp -o secure_chat_active_interceptor -lssl -lcrypto

	STEP 3: on TRUDY container
			to compile the code
			by Using	./secure_chat_active_interceptor -m alice1 bob1

	STEP 4: execute the server on BOB container
 			by Using 	./secure_chat_app -s

	STEP 5: execute the server on BOB container
 			by Using 	./secure_chat_app -c bob1


