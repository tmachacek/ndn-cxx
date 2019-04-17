/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */

#include <ndn-cxx/face.hpp>
#include <unistd.h>
#include <iostream>
#include <string>
#include <fstream>
#include <cstdio>
//#include <iostream>
#include <memory>
#include <stdexcept>
//#include <string>
#include <array>
#include <stdio.h>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

using namespace ndn::security::v2;

// Globals
int thiscount = 1;
int timeoutCount = 0;
std::string AP_Namespace;
std::string consumerIdentity = "MEME4";
std::string caMAC;
std::string namespace_prefix = "/ndn/AP213/";
std::string prodName = "/ndn/AP/";
std::string prodIdentity = "producer";
ndn::security::v2::Certificate dataCert;

using namespace std;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces can be used to prevent/limit name conflicts
namespace examples {

class Consumer : noncopyable
{
public:
  void
  run()
  {
    certIdentity = AP_Namespace	+ "/" + consumerIdentity;
    Interest interest(Name("/example/testApp/randomData" + to_string(thiscount)));
    interest.setInterestLifetime(4_s); // 4 seconds
    interest.setMustBeFresh(true);

    
    m_keyChain.sign(interest, ndn::security::signingByIdentity(Name(certIdentity)));
    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));


    //m_keyChain.sign(interest,signingByCertificate(cert));
    std::cout << "\n>> Sending Interest: \n" << interest << std::endl;
    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();

    return;
  }

  void 
  run_autoconfig()
  {
	system("ndn-autoconfig -i wlan0 > temp_out.txt 2>&1");
	system("grep \"CA Namespace\" temp_out.txt > temp_out2.txt 2>&1");
        system("grep \"HUB\" temp_out.txt > temp_out4.txt 2>&1");
        std::ifstream file("temp_out2.txt");
	std::ifstream file2("temp_out4.txt");
	std::getline(file2, caMAC);
        std::getline(file, AP_Namespace);
	file.close();
	file2.close();
	std::string macName = caMAC.substr(caMAC.find("HUB") + 4);
	std::cout << "Found HUB MAC: " << macName << std::endl;
	caMAC = macName.substr(macName.find_first_not_of(" "));
	std::string namesp = AP_Namespace.substr(AP_Namespace.find(":") + 1); //remove description
	AP_Namespace = namesp.substr(namesp.find_first_not_of(" ")); //trim leading spaces
	std::cout << "AP namespace: " << AP_Namespace << std::endl;
	system("rm temp_out*");
	return;
  }

     void
  run_ndncert()
  {
          std::string cmdbuild = "ndncert-client " + AP_Namespace + " " + consumerIdentity + " NOCHALL";
	  std::cout << "sending " << cmdbuild << std::endl;
          system(cmdbuild.c_str());

          return;
  }
  


  void
  get_data_cert()
  {
    Interest interest(Name(prodName + "CA/_CERT/_DATACERT/" + prodIdentity));
    interest.setInterestLifetime(2_s); // 2 seconds
    interest.setMustBeFresh(true);

    m_face2.expressInterest(interest,
                           bind(&Consumer::onDataCert, this,  _1, _2),
                           bind(&Consumer::onNackCert, this, _1, _2),
                           bind(&Consumer::onTimeoutCert, this, _1));

    std::cout << "\n >> Sending Interest to retrieve CERTIFICATE: " << interest << std::endl;
    // processEvents will block until the requested data received or timeout occurs
    m_face2.processEvents();
  
    return;
  }

private:

  void
  getCertificate(std::string p_name)
  {

  }

  void
  onDataCert(const Interest& interest, const Data& data)
  {
	ndn::security::v2::Certificate cert(data.getContent().blockFromValue());
	dataCert = cert;
	//std::cout << "Cert: " << cert <<std::endl;

	return;
  }

  void
  onNackCert(const Interest& interest, const lp::Nack& nack)
  {
	std::cout << "\nNACK Retrieving Cert.... \n" << interest.getName() << std::endl;
	return;
  }

  void
  onTimeoutCert(const Interest& interest)
  {
	  std::cout << "\nTIMEOUT Retrieving Cert.... \n" << interest.getName() << std::endl;
	  return;
  }

  void
  onData(const Interest& interest, const Data& data)
  {

	  std::cout << "\n*** GOT DATA ***\n: " << data << std::endl;

    //Get certificate from CA for the name in received data packet
    get_data_cert();

    if(ndn::security::verifySignature(data, dataCert)) {
	std::cout << "\n<< Received Data: " << data << std::endl;
	std::cout << "\nData Verification SUCCESSFUL!!!\n";
    }
    else {
	    std::cout << "\n<< Received Data: " << data << std::endl;
    	std::cout << "\nData Received. Verification FAILED!!!\n";
    }
   sleep(5); 
  }


  // This is no longer used in this application, ignore
  void
  onNack(const Interest& interest, const lp::Nack& nack)
  {

	  if(nack.getReason() == lp::NackReason::INVALID_CERT){
		std::cout << "Got invalid cert. Starting ndncert...\n";
		system(caName.c_str());
		
		//sleep(1);

		//Set new signing identity that we got from CA
		auto ident = m_keyChain.getPib().getIdentity(Name(certIdentity));
		m_keyChain.setDefaultIdentity(ident);

		//reset count so app will start from beginning
		thiscount = 0;
	  }
	  if(nack.getReason() == lp::NackReason::NO_ROUTE){
		std::cout << "Got NoRoute. Starting discovery\n";
		std::string faceDestroy = "nfdc face destroy " + caMAC;

		// Assume pi reconnects to AP and ndn-autoconfig works the first time
                system(faceDestroy.c_str());
		sleep(12);
		run_autoconfig();
		run_ndncert();
		/*
		system("ndn-autoconfig -i wlan0 > run.txt 2>&1");
		//sleep(12);

		std::ifstream file("run.txt");
    		std::string str; 
    		while (std::getline(file, str))
    		{
        		if(str.find("CA Namespace:") != std::string::npos ){
				std::cout << "Line: " << str << "\n";
				std::string nameSpace = str.substr(str.find(":")+2);
				certIdentity = nameSpace + "/ME";

				//create ndncert-client command
				std::string cmdBuilder = "ndncert-client "+ nameSpace + " ME NOCHALL";
				caName = cmdBuilder;
				std::cout << "New Cert Identity: " << certIdentity << std::endl;
			}
    		}
 		*/
		//reset count to restart app
		thiscount = 0;
	}

    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;

    return;
  }

  // when 5 timeouts occur, assume change in AP and call ndn-autoconfig and ndncert-client
  void
  onTimeout(const Interest& interest)
  { 
      if(timeoutCount >= 5){
	std::cout << "\nToo many timeouts. Getting new HUB info\n";
  	std::cout << "Destroying old face: " << caMAC << std::endl;
	std::string destroyCom = "nfdc face destroy " + caMAC;
    
	system(destroyCom.c_str());	
	sleep(2);
	//std::cout << "Erasing content store...\n";
	//system("nfdc cs erase /");
	//sleep(2);
	//system("nfdc cs erase /");
	std::cout << "Running autoconfig...\n";
	run_autoconfig();
	sleep(2);
	std::cout << "Running ndncert-client...\n";
	//get new certificate under new AP
	run_ndncert();
	sleep(2);
	timeoutCount = 0;
	return;
     }
    timeoutCount++;
    std::cout << "\nTimeout " << timeoutCount << std::endl;

    return;
  }

private:
  KeyChain m_keyChain;
  Face m_face;
  Face m_face2;
  std::string caName;
  std::string certIdentity;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{

  if (argc == 2) {
          consumerIdentity = argv[1];
          //consumerIdentity = argv[2];
  }

  
  //std::cout << "First run autoconfig: " << caName << std::endl;
  //
  //
  //Assume that we do not have certificate at the beginning of test
  ndn::examples::Consumer consumer;
  try {
	  std::cout << "Running autoconfig for the first time" << std::endl;
	  consumer.run_autoconfig();
	  std::cout << "AP Namespace: " << AP_Namespace << "\nAP Face: " << caMAC <<  std::endl;
          consumer.run_ndncert();
	  //sleep(5);
    //consumer.run_autoconfig();
    //consumer.run_ndncert();

    // run test for 1000 unique interests
    while(thiscount < 1000){
    	consumer.run();
    	thiscount++;
    }
	//sleep(5);
    //system("");
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
